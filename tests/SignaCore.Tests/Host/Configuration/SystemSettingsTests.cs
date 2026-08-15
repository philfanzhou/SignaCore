using Microsoft.Extensions.Configuration;
using SignaCore.Database.Entity;
using SignaCore.Host.Configuration;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

public class SystemSettingsCatalogTests
{
    /// <summary>
    /// Only values that first-run setup collects may lack a default. Anything else without one would
    /// make a fresh installation fail validation immediately after setup wrote it.
    /// </summary>
    [Fact]
    public void OnlyTheSetupCollectedValues_LackADefault()
    {
        var withoutDefault = SystemSettingsCatalog.Definitions
            .Where(definition => !definition.HasDefault)
            .Select(definition => definition.Key)
            .OrderBy(key => key, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            new[] { SystemSettingKeys.PublicBaseUrl, SystemSettingKeys.JwtIssuer }
                .OrderBy(key => key, StringComparer.Ordinal),
            withoutDefault);
    }

    [Fact]
    public void EveryDefinition_UsesASupportedValueType()
    {
        Assert.All(
            SystemSettingsCatalog.Definitions,
            definition => Assert.True(SettingValueTypes.IsSupported(definition.ValueType)));
    }

    [Fact]
    public void JsonDefaults_AreValidJson()
    {
        foreach (var definition in SystemSettingsCatalog.Definitions
                     .Where(item => item.ValueType == SettingValueTypes.Json && item.HasDefault))
        {
            JsonSettingFlattener.Canonicalize(definition.DefaultValue!);
        }
    }

    /// <summary>
    /// Anything carrying a credential has to be marked secret, or it is stored in clear and returned
    /// by settings-list APIs.
    /// </summary>
    [Theory]
    [InlineData(SystemSettingKeys.SmsOtpHmacKey)]
    [InlineData(SystemSettingKeys.SmsBypassCode)]
    [InlineData(SystemSettingKeys.SmsProfiles)]
    [InlineData(SystemSettingKeys.WechatAppSecret)]
    [InlineData(SystemSettingKeys.LdapDirectories)]
    [InlineData(SystemSettingKeys.ConsulToken)]
    public void CredentialBearingSettings_AreMarkedSecret(string key)
    {
        Assert.True(SystemSettingsCatalog.Find(key)?.IsSecret);
    }

    [Fact]
    public void Defaults_ShipOptionalProvidersDisabled()
    {
        var defaults = SystemSettingsCatalog.BuildDefaults();

        Assert.Equal("false", defaults[SystemSettingKeys.LdapEnabled]);
        Assert.Equal("false", defaults[SystemSettingKeys.ConsulDiscoveryEnabled]);
        Assert.Equal("{}", defaults[SystemSettingKeys.SmsProfiles]);
        Assert.Equal(string.Empty, defaults[SystemSettingKeys.WechatAppId]);
        // Callback policy ships closed: HTTPS required, private addresses refused.
        Assert.Equal("true", defaults[SystemSettingKeys.CallbackRequireHttps]);
        Assert.Equal("false", defaults[SystemSettingKeys.CallbackAllowPrivateAddresses]);
        Assert.Equal("false", defaults[SystemSettingKeys.SecurityAllowNonHttpsIssuer]);
    }
}

public class SettingsSnapshotValidatorTests
{
    [Fact]
    public void Validate_WithACompleteSnapshot_ReportsNoErrors()
    {
        Assert.Empty(SettingsSnapshotValidator.Validate(CompleteSnapshot()));
    }

    [Fact]
    public void Validate_ListsEveryMissingKeyAtOnce()
    {
        var values = CompleteSnapshot();
        values.Remove(SystemSettingKeys.JwtAudience);
        values.Remove(SystemSettingKeys.SmsMaxAttempts);

        var errors = SettingsSnapshotValidator.Validate(values);

        Assert.Contains(errors, error => error.Contains(SystemSettingKeys.JwtAudience, StringComparison.Ordinal));
        Assert.Contains(errors, error => error.Contains(SystemSettingKeys.SmsMaxAttempts, StringComparison.Ordinal));
    }

    [Fact]
    public void Validate_OutsideDevelopment_RequiresHttpsPublicBaseUrl()
    {
        var values = CompleteSnapshot();
        values[SystemSettingKeys.PublicBaseUrl] = "http://identity.example.test";
        values[SystemSettingKeys.JwtIssuer] = "http://identity.example.test";

        var errors = SettingsSnapshotValidator.Validate(values);

        Assert.Contains(errors, error => error.Contains("HTTPS", StringComparison.Ordinal));
    }

    /// <summary>
    /// HTTP is accepted only when the operator explicitly opts in, independent of address shape.
    /// </summary>
    [Fact]
    public void Validate_WithAllowNonHttpsIssuer_AcceptsPlainHttp()
    {
        var values = CompleteSnapshot();
        values[SystemSettingKeys.PublicBaseUrl] = "http://identity.example.test";
        values[SystemSettingKeys.JwtIssuer] = "http://identity.example.test";
        values[SystemSettingKeys.SecurityAllowNonHttpsIssuer] = "true";

        Assert.Empty(SettingsSnapshotValidator.Validate(values));
    }

    /// <summary>
    /// A discovery document served from one URL with an `iss` claim naming another is rejected by
    /// every conforming client, so the two are not allowed to drift.
    /// </summary>
    [Fact]
    public void Validate_RejectsAnIssuerThatDoesNotMatchThePublicBaseUrl()
    {
        var values = CompleteSnapshot();
        values[SystemSettingKeys.JwtIssuer] = "https://somewhere.else.test";

        var errors = SettingsSnapshotValidator.Validate(values);

        Assert.Contains(errors, error => error.Contains(SystemSettingKeys.JwtIssuer, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(SystemSettingKeys.JwtAudience)]
    [InlineData(SystemSettingKeys.AdminUsername)]
    public void Validate_RejectsEmptyRequiredIdentitySettings(string key)
    {
        var values = CompleteSnapshot();
        values[key] = " ";

        var errors = SettingsSnapshotValidator.Validate(values);

        Assert.Contains(errors, error => error.Contains(key, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(SystemSettingKeys.JwtTokenExpirationHours, "0")]
    [InlineData(SystemSettingKeys.JwtTokenExpirationHours, "not-a-number")]
    [InlineData(SystemSettingKeys.RefreshTokenExpirationDays, "0")]
    [InlineData(SystemSettingKeys.PasswordHasherWorkFactor, "4")]
    [InlineData(SystemSettingKeys.LdapEnabled, "yes")]
    [InlineData(SystemSettingKeys.LdapDirectories, "{not json")]
    public void Validate_RejectsOutOfRangeOrMistypedValues(string key, string value)
    {
        var values = CompleteSnapshot();
        values[key] = value;

        var errors = SettingsSnapshotValidator.Validate(values);

        Assert.Contains(errors, error => error.Contains(key, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("https://identity.example.test/", "https://identity.example.test")]
    [InlineData("  https://identity.example.test  ", "https://identity.example.test")]
    [InlineData("https://identity.example.test:8443", "https://identity.example.test:8443")]
    public void TryNormalizeBaseUrl_TrimsAndDropsTheTrailingSlash(string input, string expected)
    {
        Assert.True(SettingsSnapshotValidator.TryNormalizeBaseUrl(input, out var normalized, out _));
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("")]
    [InlineData("identity.example.test")]
    [InlineData("ftp://identity.example.test")]
    [InlineData("https://user:pass@identity.example.test")]
    [InlineData("https://identity.example.test?x=1")]
    [InlineData("https://identity.example.test#fragment")]
    public void TryNormalizeBaseUrl_RejectsUnusableValues(string input)
    {
        Assert.False(SettingsSnapshotValidator.TryNormalizeBaseUrl(input, out _, out _));
    }

    private static Dictionary<string, string> CompleteSnapshot()
    {
        var values = SystemSettingsCatalog.BuildDefaults();
        values[SystemSettingKeys.PublicBaseUrl] = "https://identity.example.test";
        values[SystemSettingKeys.JwtIssuer] = "https://identity.example.test";
        values[SystemSettingKeys.AdminUsername] = "admin";
        return values;
    }
}

public class JsonSettingFlattenerTests
{
    /// <summary>
    /// Structured settings have to reach consumers through normal configuration semantics, so an
    /// array stored as JSON must bind exactly like the appsettings.json section it replaced.
    /// </summary>
    [Fact]
    public void Flatten_ExpandsArraysIntoIndexedConfigurationKeys()
    {
        var destination = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        JsonSettingFlattener.Flatten(
            "Callback:AllowedDomains",
            """["a.example","b.example"]""",
            destination);

        Assert.Equal("a.example", destination["Callback:AllowedDomains:0"]);
        Assert.Equal("b.example", destination["Callback:AllowedDomains:1"]);
    }

    [Fact]
    public void Flatten_ExpandsNestedObjects()
    {
        var destination = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        JsonSettingFlattener.Flatten(
            "Sms:Profiles",
            """{"production":{"Provider":"AlibabaCloud","SignName":"SignaCore"}}""",
            destination);

        Assert.Equal("AlibabaCloud", destination["Sms:Profiles:production:Provider"]);
        Assert.Equal("SignaCore", destination["Sms:Profiles:production:SignName"]);
    }

    [Fact]
    public void Flatten_KeepsNumbersAndBooleansInTheirJsonForm()
    {
        var destination = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        JsonSettingFlattener.Flatten("Ldap:Directories", """[{"Port":636,"UseTls":true}]""", destination);

        Assert.Equal("636", destination["Ldap:Directories:0:Port"]);
        Assert.Equal("true", destination["Ldap:Directories:0:UseTls"]);
    }
}

public class ConfigurationJsonExporterTests
{
    [Fact]
    public void Export_ReturnsNullWhenTheSectionIsAbsent()
    {
        Assert.Null(ConfigurationJsonExporter.Export(Section(new Dictionary<string, string?>(), "Missing")));
    }

    [Fact]
    public void Export_RebuildsAnArrayFromIndexedKeys()
    {
        var json = ConfigurationJsonExporter.Export(Section(
            new Dictionary<string, string?>
            {
                ["Callback:AllowedDomains:0"] = "a.example",
                ["Callback:AllowedDomains:1"] = "b.example"
            },
            "Callback:AllowedDomains"));

        Assert.Equal("""["a.example","b.example"]""", json);
    }

    [Fact]
    public void Export_RebuildsNestedObjects()
    {
        var json = ConfigurationJsonExporter.Export(Section(
            new Dictionary<string, string?>
            {
                ["Sms:Profiles:production:Provider"] = "AlibabaCloud"
            },
            "Sms:Profiles"));

        Assert.Equal("""{"production":{"Provider":"AlibabaCloud"}}""", json);
    }

    /// <summary>
    /// Environment variables commonly carry "a,b,c" where appsettings.json expressed an array; the
    /// legacy import has to understand both or it silently drops the deployment's allow lists.
    /// </summary>
    [Fact]
    public void Export_TreatsACommaSeparatedScalarAsAnArray()
    {
        var json = ConfigurationJsonExporter.Export(Section(
            new Dictionary<string, string?> { ["Sms:BypassPhones"] = "13800000000, 13900000000" },
            "Sms:BypassPhones"));

        Assert.Equal("""["13800000000","13900000000"]""", json);
    }

    [Fact]
    public void Export_PassesThroughAScalarThatIsAlreadyJson()
    {
        var json = ConfigurationJsonExporter.Export(Section(
            new Dictionary<string, string?> { ["AdminWeb:AllowedOrigins"] = """[ "https://a.test" ]""" },
            "AdminWeb:AllowedOrigins"));

        Assert.Equal("""["https://a.test"]""", json);
    }

    private static IConfigurationSection Section(Dictionary<string, string?> values, string key) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build().GetSection(key);
}
