using System.Text.Json;
using ServiceMantle.Configuration;
using SignaCore.Host.Configuration;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

/// <summary>
/// Behavioral equivalence between the legacy snapshot validator and the shared setting stack
/// (registry parsing + value constraints + composite validator) on equivalent inputs: the same
/// snapshot must be accepted or rejected by both. The new stack feeds each key through its
/// normalized name; a legacy snapshot's absent sensitive keys are compared as present-with-default
/// (the declared difference: missing means the old default).
/// </summary>
public sealed class SharedSettingEquivalenceTests
{
    private static readonly ServiceSettingDefinitionRegistry ProductionRegistry =
        new([new ServiceSettingDefinitions()], [new SignaCoreSettingCompositeValidator(false)]);

    private static readonly ServiceSettingDefinitionRegistry DevelopmentRegistry =
        new([new ServiceSettingDefinitions()], [new SignaCoreSettingCompositeValidator(true)]);

    /// <summary>A base64 string of 32 bytes, satisfying the SMS HMAC key rule.</summary>
    private static string HmacKey32 { get; } = Convert.ToBase64String(
        System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

    public static TheoryData<string, Dictionary<string, string>, bool> SnapshotCases
    {
        get
        {
            TheoryData<string, Dictionary<string, string>, bool> cases = [];

            void Add(string name, Dictionary<string, string> overrides, bool isDevelopment = false)
            {
                var snapshot = SystemSettingsCatalog.BuildDefaults();
                // The setup-collected pair has no default; give it the canonical valid value.
                snapshot[SystemSettingKeys.PublicBaseUrl] = "https://accounts.example.com";
                snapshot[SystemSettingKeys.JwtIssuer] = "https://accounts.example.com";
                foreach (var (key, value) in overrides)
                {
                    snapshot[key] = value;
                }

                cases.Add(name, snapshot, isDevelopment);
            }

            Add("defaults-with-setup-pair", []);
            Add("base-url-trailing-slash", new Dictionary<string, string>
            {
                [SystemSettingKeys.PublicBaseUrl] = "https://accounts.example.com/",
                [SystemSettingKeys.JwtIssuer] = "https://accounts.example.com"
            });
            Add("base-url-not-absolute", new Dictionary<string, string>
            {
                [SystemSettingKeys.PublicBaseUrl] = "accounts.example.com"
            });
            Add("base-url-with-query", new Dictionary<string, string>
            {
                [SystemSettingKeys.PublicBaseUrl] = "https://accounts.example.com/?x=1"
            });
            Add("base-url-http-without-opt-in", new Dictionary<string, string>
            {
                [SystemSettingKeys.PublicBaseUrl] = "http://accounts.example.com",
                [SystemSettingKeys.JwtIssuer] = "http://accounts.example.com"
            });
            Add("base-url-http-with-explicit-opt-in", new Dictionary<string, string>
            {
                [SystemSettingKeys.PublicBaseUrl] = "http://accounts.example.com",
                [SystemSettingKeys.JwtIssuer] = "http://accounts.example.com",
                [SystemSettingKeys.SecurityAllowNonHttpsIssuer] = "true"
            });
            Add("issuer-mismatch", new Dictionary<string, string>
            {
                [SystemSettingKeys.JwtIssuer] = "https://other.example.com"
            });
            Add("issuer-blank", new Dictionary<string, string>
            {
                [SystemSettingKeys.JwtIssuer] = " "
            });
            Add("audience-blank", new Dictionary<string, string>
            {
                [SystemSettingKeys.JwtAudience] = ""
            });
            Add("admin-username-blank", new Dictionary<string, string>
            {
                [SystemSettingKeys.AdminUsername] = ""
            });
            Add("token-hours-below-range", new Dictionary<string, string>
            {
                [SystemSettingKeys.JwtTokenExpirationHours] = "0"
            });
            Add("token-hours-above-range", new Dictionary<string, string>
            {
                [SystemSettingKeys.JwtTokenExpirationHours] = "25"
            });
            Add("refresh-days-below-range", new Dictionary<string, string>
            {
                [SystemSettingKeys.RefreshTokenExpirationDays] = "0"
            });
            Add("work-factor-above-range", new Dictionary<string, string>
            {
                [SystemSettingKeys.PasswordHasherWorkFactor] = "16"
            });
            Add("number-not-an-integer", new Dictionary<string, string>
            {
                [SystemSettingKeys.JwtTokenExpirationHours] = "2.5"
            });
            Add("number-not-numeric", new Dictionary<string, string>
            {
                [SystemSettingKeys.ConsulPort] = "eight-thousand"
            });
            Add("boolean-invalid", new Dictionary<string, string>
            {
                [SystemSettingKeys.LdapEnabled] = "yes"
            });
            Add("json-invalid", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsBypassPhones] = "[1, 2"
            });
            Add("json-array-root-violation", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsProfiles] = "[]"
            });
            Add("json-object-root-violation", new Dictionary<string, string>
            {
                [SystemSettingKeys.ReverseProxyKnownProxies] = "{}"
            });
            Add("sms-limits-invalid", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsOtpTtlSeconds] = "10"
            });
            Add("sms-hmac-key-too-short", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsOtpHmacKey] = Convert.ToBase64String(new byte[16])
            });
            Add("sms-hmac-key-not-base64", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsOtpHmacKey] = "not base64 !!"
            });
            Add("sms-logging-profile-in-production", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsProfiles] = """{"development":{"provider":"Logging"}}"""
            });
            Add("sms-logging-profile-in-development",
                new Dictionary<string, string>
                {
                    [SystemSettingKeys.SmsProfiles] = """{"development":{"provider":"Logging"}}"""
                },
                isDevelopment: true);
            Add("sms-alibaba-profile-complete", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsOtpHmacKey] = HmacKey32,
                [SystemSettingKeys.SmsProfiles] =
                    """{"main":{"provider":"AlibabaCloud","accessKeyId":"id","accessKeySecret":"secret","signName":"sign","templateId":"tpl"}}"""
            });
            Add("sms-tencent-profile-incomplete", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsOtpHmacKey] = HmacKey32,
                [SystemSettingKeys.SmsProfiles] =
                    """{"main":{"provider":"TencentCloud","accessKeyId":"id","accessKeySecret":"secret","signName":"sign","templateId":"tpl"}}"""
            });
            Add("sms-unsupported-provider", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsOtpHmacKey] = HmacKey32,
                [SystemSettingKeys.SmsProfiles] =
                    """{"main":{"provider":"OtherCloud","accessKeyId":"id","accessKeySecret":"secret","signName":"sign","templateId":"tpl"}}"""
            });
            Add("ldap-enabled-with-valid-directory", new Dictionary<string, string>
            {
                [SystemSettingKeys.LdapEnabled] = "true",
                [SystemSettingKeys.LdapDefaultDirectoryKey] = "main",
                [SystemSettingKeys.LdapDirectories] =
                    """[{"key":"main","hosts":["ldap.example.com"],"baseDn":"dc=example,dc=com","bindUsername":"uid=admin","bindPassword":"secret","port":636,"timeoutSeconds":10}]"""
            });
            Add("ldap-enabled-without-directories", new Dictionary<string, string>
            {
                [SystemSettingKeys.LdapEnabled] = "true",
                [SystemSettingKeys.LdapDefaultDirectoryKey] = "main"
            });
            Add("wechat-partial-credentials", new Dictionary<string, string>
            {
                [SystemSettingKeys.WechatAppId] = "wx123"
            });
            Add("wechat-complete-credentials", new Dictionary<string, string>
            {
                [SystemSettingKeys.WechatAppId] = "wx123",
                [SystemSettingKeys.WechatAppSecret] = "secret"
            });
            Add("wechat-api-url-not-https", new Dictionary<string, string>
            {
                [SystemSettingKeys.WechatAppId] = "wx123",
                [SystemSettingKeys.WechatAppSecret] = "secret",
                [SystemSettingKeys.WechatApiBaseUrl] = "http://api.weixin.qq.com"
            });
            Add("known-proxies-valid", new Dictionary<string, string>
            {
                [SystemSettingKeys.ReverseProxyKnownProxies] = """["10.0.0.1","192.168.0.0/24"]"""
            });
            Add("known-proxies-invalid-entry", new Dictionary<string, string>
            {
                [SystemSettingKeys.ReverseProxyKnownProxies] = """["not-an-ip"]"""
            });
            Add("empty-string-optionals-present", new Dictionary<string, string>
            {
                [SystemSettingKeys.LokiUri] = "",
                [SystemSettingKeys.OpenTelemetryOtlpEndpoint] = "",
                [SystemSettingKeys.WechatAppId] = "",
                [SystemSettingKeys.AdminUsername] = "root-admin"
            });

            return cases;
        }
    }

    [Theory]
    [MemberData(nameof(SnapshotCases))]
    public void EquivalentSnapshots_AcceptAndRejectIdentically(
        string name,
        Dictionary<string, string> legacySnapshot,
        bool isDevelopment)
    {
        Assert.NotEmpty(name);

        var legacyErrors = SettingsSnapshotValidator.Validate(legacySnapshot, isDevelopment);
        var shared = ValidateOnSharedStack(legacySnapshot, isDevelopment);

        Assert.Equal(
            legacyErrors.Count == 0,
            shared.IsValid);
    }

    [Fact]
    public void MissingSetupKeys_AreRejectedByBothStacks()
    {
        var legacy = SystemSettingsCatalog.BuildDefaults();
        legacy[SystemSettingKeys.PublicBaseUrl] = "https://accounts.example.com";
        legacy[SystemSettingKeys.JwtIssuer] = "https://accounts.example.com";

        var withoutIssuer = legacy.ToDictionary(
            pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        withoutIssuer.Remove(SystemSettingKeys.JwtIssuer);

        // Old: the key is missing → R1 error. New: required definition without a value.
        Assert.NotEmpty(SettingsSnapshotValidator.Validate(withoutIssuer, false));
        Assert.False(ValidateOnSharedStack(withoutIssuer, false).IsValid);
    }

    [Fact]
    public void MissingSensitiveKeys_ValidateLikeTheLegacyEmptyDefaults()
    {
        var legacy = SystemSettingsCatalog.BuildDefaults();
        legacy[SystemSettingKeys.PublicBaseUrl] = "https://accounts.example.com";
        legacy[SystemSettingKeys.JwtIssuer] = "https://accounts.example.com";
        // The legacy default leaves the administrator username blank; a valid snapshot has one.
        legacy[SystemSettingKeys.AdminUsername] = "root-admin";
        Assert.Empty(SettingsSnapshotValidator.Validate(legacy, false));

        // The new stack with the sensitive keys entirely unset must reach the same verdict.
        var sharedInput = ToSharedInput(legacy);
        foreach (var sensitiveKey in SystemSettingsCatalog.Definitions.Where(d => d.IsSecret))
        {
            sharedInput.Remove(SharedSettingKeys.NormalizedByLegacyKey[sensitiveKey.Key]);
        }

        var result = ProductionRegistry.Validate(sharedInput);
        Assert.True(result.IsValid);
    }

    [Fact]
    public void CompositeErrors_AreClosedKeyScopedCodes()
    {
        var legacy = SystemSettingsCatalog.BuildDefaults();
        legacy[SystemSettingKeys.PublicBaseUrl] = "http://accounts.example.com";
        legacy[SystemSettingKeys.JwtIssuer] = "http://accounts.example.com";

        var result = ProductionRegistry.Validate(ToSharedInput(legacy));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error =>
            error.Key == "endpoints.public_base_url" &&
            error.ErrorCode == SignaCoreSettingCompositeValidator.HttpsRequiredCode);
        foreach (var error in result.Errors)
        {
            Assert.DoesNotContain("accounts.example.com", error.ErrorCode, StringComparison.Ordinal);
            Assert.Matches("^[a-z0-9][a-z0-9._-]*$", error.ErrorCode);
        }
    }

    [Fact]
    public void UnknownKeys_AreRejectedByTheRegistry()
    {
        var legacy = SystemSettingsCatalog.BuildDefaults();
        legacy[SystemSettingKeys.PublicBaseUrl] = "https://accounts.example.com";
        legacy[SystemSettingKeys.JwtIssuer] = "https://accounts.example.com";
        var sharedInput = ToSharedInput(legacy);
        sharedInput["unknown.key"] = "value";

        var result = ProductionRegistry.Validate(sharedInput);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.ErrorCode == WellKnownServiceSettingValidationErrorCodes.Unknown);
    }

    private static ServiceSettingValidationResult ValidateOnSharedStack(
        Dictionary<string, string> legacySnapshot,
        bool isDevelopment) =>
        (isDevelopment ? DevelopmentRegistry : ProductionRegistry)
        .Validate(ToSharedInput(legacySnapshot));

    private static Dictionary<string, string?> ToSharedInput(Dictionary<string, string> legacySnapshot)
    {
        var shared = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var (legacyKey, value) in legacySnapshot)
        {
            shared[SharedSettingKeys.NormalizedByLegacyKey[legacyKey]] = value;
        }

        return shared;
    }
}
