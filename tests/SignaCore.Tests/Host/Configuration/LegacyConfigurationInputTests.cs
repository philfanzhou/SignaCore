using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Host.Configuration;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

/// <summary>
/// The fixed input matrix of the protected legacy configuration upgrade import: the product input
/// adapter must reproduce the old importer's reading rules exactly — catalog defaults, trimming,
/// the admin key alias with canonical-key precedence, every historical JSON shape, and the
/// plain-HTTP compatibility opt-in — because a pre-change deployment gets exactly one import.
/// </summary>
public class LegacyConfigurationInputTests
{
    private static (Dictionary<string, string> Values, int ImportedKeyCount) Read(
        Dictionary<string, string?> source) =>
        LegacyConfigurationInput.ReadCompleteInput(
            new ConfigurationBuilder().AddInMemoryCollection(source).Build(),
            NullLogger.Instance);

    private const string BaseUrl = "https://accounts.example.com";

    /// <summary>The minimum a pre-change deployment must supply: the required, defaultless keys.</summary>
    private static Dictionary<string, string?> RequiredOnly() => new()
    {
        [SystemSettingKeys.PublicBaseUrl] = BaseUrl,
        [SystemSettingKeys.JwtIssuer] = BaseUrl,
        [SystemSettingKeys.JwtAudience] = "Services",
        // The pre-change name of the administrator key; the canonical name wins when both exist.
        [SystemSettingKeys.LegacyAdminBootstrapUsername] = "legacy_admin"
    };

    [Fact]
    public void Read_CompletesAllFortyThreeKeysFromDefaultsAndTheDeployment()
    {
        var (values, importedCount) = Read(new Dictionary<string, string?>
        {
            [SystemSettingKeys.PublicBaseUrl] = $" {BaseUrl} ",
            [SystemSettingKeys.JwtIssuer] = BaseUrl,
            [SystemSettingKeys.JwtAudience] = " Services ",
            [SystemSettingKeys.LegacyAdminBootstrapUsername] = "legacy_admin"
        });

        // Exactly the four required keys came from the deployment; the other 39 keep the definition
        // table's legacy defaults, so the complete candidate always covers all 43 keys.
        Assert.Equal(4, importedCount);
        Assert.Equal(ServiceSettingDefinitions.Table.Count, values.Count);
        Assert.Equal(43, values.Count);

        // Deployment values are trimmed; defaults are untouched.
        Assert.Equal(BaseUrl, values[SystemSettingKeys.PublicBaseUrl]);
        Assert.Equal("Services", values[SystemSettingKeys.JwtAudience]);
        Assert.Equal("2", values[SystemSettingKeys.JwtTokenExpirationHours]);

        // The historical alias resolved onto the canonical key.
        Assert.Equal("legacy_admin", values[SystemSettingKeys.AdminUsername]);
    }

    [Fact]
    public void Read_PrefersTheCanonicalAdminKeyOverTheHistoricalAlias()
    {
        var (values, _) = Read(new Dictionary<string, string?>
        {
            [SystemSettingKeys.PublicBaseUrl] = BaseUrl,
            [SystemSettingKeys.JwtIssuer] = BaseUrl,
            [SystemSettingKeys.JwtAudience] = "Services",
            [SystemSettingKeys.AdminUsername] = "canonical_admin",
            [SystemSettingKeys.LegacyAdminBootstrapUsername] = "alias_admin"
        });

        Assert.Equal("canonical_admin", values[SystemSettingKeys.AdminUsername]);
    }

    [Fact]
    public void Read_RebuildsJsonFromIndexedArrayKeys()
    {
        var (values, _) = Read(RequiredOnly() .Concat(new Dictionary<string, string?>
        {
            ["Sms:BypassPhones:0"] = "13800000000",
            ["Sms:BypassPhones:1"] = "13900000000"
        }).ToDictionary());

        Assert.Equal("""["13800000000","13900000000"]""", values[SystemSettingKeys.SmsBypassPhones]);
    }

    [Fact]
    public void Read_RebuildsJsonFromNestedObjectKeys()
    {
        var (values, _) = Read(RequiredOnly().Concat(new Dictionary<string, string?>
        {
            ["Sms:Profiles:production:Provider"] = "AlibabaCloud",
            ["Sms:Profiles:production:SignName"] = "SignaCore"
        }).ToDictionary());

        Assert.Equal(
            """{"production":{"Provider":"AlibabaCloud","SignName":"SignaCore"}}""",
            values[SystemSettingKeys.SmsProfiles]);
    }

    [Fact]
    public void Read_PassesThroughAScalarThatIsAlreadyJson()
    {
        var (values, _) = Read(RequiredOnly().Concat(new Dictionary<string, string?>
        {
            ["AdminWeb:AllowedOrigins"] = """[ "https://a.test", "https://b.test" ]"""
        }).ToDictionary());

        Assert.Equal("""["https://a.test","https://b.test"]""", values[SystemSettingKeys.AdminWebAllowedOrigins]);
    }

    /// <summary>
    /// Environment variables commonly carried "a,b,c" where appsettings.json expressed an array;
    /// losing that shape would silently drop the deployment's allow lists.
    /// </summary>
    [Fact]
    public void Read_TreatsACommaSeparatedScalarAsAnArray()
    {
        var (values, _) = Read(RequiredOnly().Concat(new Dictionary<string, string?>
        {
            ["Callback:AllowedDomains"] = "a.example, b.example"
        }).ToDictionary());

        Assert.Equal("""["a.example","b.example"]""", values[SystemSettingKeys.CallbackAllowedDomains]);
    }

    [Fact]
    public void Read_EnablesThePlainHttpCompatibilityOptInForAPlainHttpDeployment()
    {
        var plainHttp = new Dictionary<string, string?>
        {
            [SystemSettingKeys.PublicBaseUrl] = "http://accounts.example.com",
            [SystemSettingKeys.JwtIssuer] = "http://accounts.example.com",
            [SystemSettingKeys.JwtAudience] = "Services",
            [SystemSettingKeys.LegacyAdminBootstrapUsername] = "legacy_admin"
        };

        var (values, _) = Read(plainHttp);

        // The deployment already served plain HTTP; the import records that loudly instead of
        // failing closed on an upgrade that changed nothing.
        Assert.Equal("true", values[SystemSettingKeys.SecurityAllowNonHttpsIssuer]);

        // An explicit deployment opt-in and an HTTPS deployment are both left untouched.
        var explicitOptIn = plainHttp.ToDictionary(
            entry => entry.Key,
            entry => (string?)entry.Value);
        explicitOptIn[SystemSettingKeys.SecurityAllowNonHttpsIssuer] = "true";
        Assert.Equal("true", Read(explicitOptIn).Values[SystemSettingKeys.SecurityAllowNonHttpsIssuer]);

        var https = RequiredOnly();
        Assert.NotEqual("true", Read(https).Values[SystemSettingKeys.SecurityAllowNonHttpsIssuer]);
    }

    /// <summary>
    /// The completeness check reports key names only, never any value. The keys without a usable
    /// default are exactly the two the first-run form used to collect.
    /// </summary>
    [Fact]
    public void Read_FailsClosedWithKeyNamesWhenARequiredSettingIsMissing()
    {
        var exception = Assert.Throws<SettingsSnapshotException>(
            () => Read(new Dictionary<string, string?> { ["unrelated"] = "value" }));

        Assert.Equal(
            [SystemSettingKeys.PublicBaseUrl, SystemSettingKeys.JwtIssuer],
            exception.Keys);
        Assert.DoesNotContain("unrelated", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("value", exception.Message, StringComparison.Ordinal);
    }
}
