using ServiceMantle.Configuration;
using SignaCore.Host.Configuration;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

/// <summary>
/// The frozen accept/reject contract of the shared setting stack on complete candidates. Every
/// case below carries a pinned verdict captured from the retired legacy validator's behavior
/// baseline (the equivalence rounds of tasks #101–#146); nothing here computes an expectation by
/// running a second implementation. The candidate entry is
/// <see cref="SharedSettingComposition.ValidateCompleteCandidate"/> — input completeness and
/// integer Number text first, then the shared registry with the composite validator.
/// </summary>
public sealed class SharedSettingContractTests
{
    /// <summary>A base64 string of 32 bytes, satisfying the SMS HMAC key rule.</summary>
    private static string HmacKey32 { get; } = Convert.ToBase64String(
        System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

    public static TheoryData<string, Dictionary<string, string>, bool, bool> SnapshotCases
    {
        get
        {
            TheoryData<string, Dictionary<string, string>, bool, bool> cases = [];

            void Add(
                string name,
                Dictionary<string, string> overrides,
                bool isDevelopment,
                bool expectedValid)
            {
                var snapshot = ServiceSettingDefinitions.BuildLegacyDefaults();
                // The setup-collected pair has no default, and the blank administrator default is
                // rejected, so a valid baseline names both explicitly.
                snapshot[SystemSettingKeys.PublicBaseUrl] = "https://accounts.example.com";
                snapshot[SystemSettingKeys.JwtIssuer] = "https://accounts.example.com";
                snapshot[SystemSettingKeys.AdminUsername] = "root-admin";
                foreach (var (key, value) in overrides)
                {
                    snapshot[key] = value;
                }

                cases.Add(name, snapshot, isDevelopment, expectedValid);
            }

            Add("defaults-with-setup-pair", [], isDevelopment: false, expectedValid: true);
            Add("base-url-trailing-slash", new Dictionary<string, string>
            {
                [SystemSettingKeys.PublicBaseUrl] = "https://accounts.example.com/",
                [SystemSettingKeys.JwtIssuer] = "https://accounts.example.com"
            }, isDevelopment: false, expectedValid: true);
            Add("base-url-not-absolute", new Dictionary<string, string>
            {
                [SystemSettingKeys.PublicBaseUrl] = "accounts.example.com"
            }, isDevelopment: false, expectedValid: false);
            Add("base-url-with-query", new Dictionary<string, string>
            {
                [SystemSettingKeys.PublicBaseUrl] = "https://accounts.example.com/?x=1"
            }, isDevelopment: false, expectedValid: false);
            Add("base-url-http-without-opt-in", new Dictionary<string, string>
            {
                [SystemSettingKeys.PublicBaseUrl] = "http://accounts.example.com",
                [SystemSettingKeys.JwtIssuer] = "http://accounts.example.com"
            }, isDevelopment: false, expectedValid: false);
            Add("base-url-http-with-explicit-opt-in", new Dictionary<string, string>
            {
                [SystemSettingKeys.PublicBaseUrl] = "http://accounts.example.com",
                [SystemSettingKeys.JwtIssuer] = "http://accounts.example.com",
                [SystemSettingKeys.SecurityAllowNonHttpsIssuer] = "true"
            }, isDevelopment: false, expectedValid: true);
            Add("issuer-mismatch", new Dictionary<string, string>
            {
                [SystemSettingKeys.JwtIssuer] = "https://other.example.com"
            }, isDevelopment: false, expectedValid: false);
            Add("issuer-blank", new Dictionary<string, string>
            {
                [SystemSettingKeys.JwtIssuer] = " "
            }, isDevelopment: false, expectedValid: false);
            Add("audience-blank", new Dictionary<string, string>
            {
                [SystemSettingKeys.JwtAudience] = ""
            }, isDevelopment: false, expectedValid: false);
            Add("admin-username-blank", new Dictionary<string, string>
            {
                [SystemSettingKeys.AdminUsername] = ""
            }, isDevelopment: false, expectedValid: false);
            Add("token-hours-below-range", new Dictionary<string, string>
            {
                [SystemSettingKeys.JwtTokenExpirationHours] = "0"
            }, isDevelopment: false, expectedValid: false);
            Add("token-hours-above-range", new Dictionary<string, string>
            {
                [SystemSettingKeys.JwtTokenExpirationHours] = "25"
            }, isDevelopment: false, expectedValid: false);
            Add("refresh-days-below-range", new Dictionary<string, string>
            {
                [SystemSettingKeys.RefreshTokenExpirationDays] = "0"
            }, isDevelopment: false, expectedValid: false);
            Add("work-factor-above-range", new Dictionary<string, string>
            {
                [SystemSettingKeys.PasswordHasherWorkFactor] = "16"
            }, isDevelopment: false, expectedValid: false);
            Add("number-not-an-integer", new Dictionary<string, string>
            {
                [SystemSettingKeys.JwtTokenExpirationHours] = "2.5"
            }, isDevelopment: false, expectedValid: false);
            Add("number-not-numeric", new Dictionary<string, string>
            {
                [SystemSettingKeys.ConsulPort] = "eight-thousand"
            }, isDevelopment: false, expectedValid: false);
            Add("boolean-invalid", new Dictionary<string, string>
            {
                [SystemSettingKeys.LdapEnabled] = "yes"
            }, isDevelopment: false, expectedValid: false);
            Add("json-invalid", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsBypassPhones] = "[1, 2"
            }, isDevelopment: false, expectedValid: false);
            Add("json-array-root-violation", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsProfiles] = "[]"
            }, isDevelopment: false, expectedValid: false);
            Add("json-object-root-violation", new Dictionary<string, string>
            {
                [SystemSettingKeys.ReverseProxyKnownProxies] = "{}"
            }, isDevelopment: false, expectedValid: false);
            Add("sms-limits-invalid", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsOtpTtlSeconds] = "10"
            }, isDevelopment: false, expectedValid: false);
            Add("sms-hmac-key-too-short", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsOtpHmacKey] = Convert.ToBase64String(new byte[16])
            }, isDevelopment: false, expectedValid: false);
            Add("sms-hmac-key-not-base64", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsOtpHmacKey] = "not base64 !!"
            }, isDevelopment: false, expectedValid: false);
            Add("sms-logging-profile-in-production", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsProfiles] = """{"development":{"provider":"Logging"}}"""
            }, isDevelopment: false, expectedValid: false);
            // Development allows the Logging provider, but the HMAC key requirement applies in
            // every environment: a profile without a usable key is rejected even in development.
            Add("sms-logging-profile-in-development-without-hmac-key", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsProfiles] = """{"development":{"provider":"Logging"}}"""
            }, isDevelopment: true, expectedValid: false);
            Add("sms-logging-profile-in-development-with-hmac-key", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsOtpHmacKey] = HmacKey32,
                [SystemSettingKeys.SmsProfiles] = """{"development":{"provider":"Logging"}}"""
            }, isDevelopment: true, expectedValid: true);
            Add("sms-logging-profile-in-production-with-hmac-key", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsOtpHmacKey] = HmacKey32,
                [SystemSettingKeys.SmsProfiles] = """{"development":{"provider":"Logging"}}"""
            }, isDevelopment: false, expectedValid: false);
            Add("sms-alibaba-profile-complete", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsOtpHmacKey] = HmacKey32,
                [SystemSettingKeys.SmsProfiles] =
                    """{"main":{"provider":"AlibabaCloud","accessKeyId":"id","accessKeySecret":"secret","signName":"sign","templateId":"tpl"}}"""
            }, isDevelopment: false, expectedValid: true);
            Add("sms-tencent-profile-incomplete", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsOtpHmacKey] = HmacKey32,
                [SystemSettingKeys.SmsProfiles] =
                    """{"main":{"provider":"TencentCloud","accessKeyId":"id","accessKeySecret":"secret","signName":"sign","templateId":"tpl"}}"""
            }, isDevelopment: false, expectedValid: false);
            Add("sms-unsupported-provider", new Dictionary<string, string>
            {
                [SystemSettingKeys.SmsOtpHmacKey] = HmacKey32,
                [SystemSettingKeys.SmsProfiles] =
                    """{"main":{"provider":"OtherCloud","accessKeyId":"id","accessKeySecret":"secret","signName":"sign","templateId":"tpl"}}"""
            }, isDevelopment: false, expectedValid: false);
            Add("ldap-enabled-with-valid-directory", new Dictionary<string, string>
            {
                [SystemSettingKeys.LdapEnabled] = "true",
                [SystemSettingKeys.LdapDefaultDirectoryKey] = "main",
                [SystemSettingKeys.LdapDirectories] =
                    """[{"key":"main","hosts":["ldap.example.com"],"baseDn":"dc=example,dc=com","bindUsername":"uid=admin","bindPassword":"secret","port":636,"timeoutSeconds":10}]"""
            }, isDevelopment: false, expectedValid: true);
            Add("ldap-enabled-without-directories", new Dictionary<string, string>
            {
                [SystemSettingKeys.LdapEnabled] = "true",
                [SystemSettingKeys.LdapDefaultDirectoryKey] = "main"
            }, isDevelopment: false, expectedValid: false);
            Add("wechat-partial-credentials", new Dictionary<string, string>
            {
                [SystemSettingKeys.WechatAppId] = "wx123"
            }, isDevelopment: false, expectedValid: false);
            Add("wechat-complete-credentials", new Dictionary<string, string>
            {
                [SystemSettingKeys.WechatAppId] = "wx123",
                [SystemSettingKeys.WechatAppSecret] = "secret"
            }, isDevelopment: false, expectedValid: true);
            Add("wechat-api-url-not-https", new Dictionary<string, string>
            {
                [SystemSettingKeys.WechatAppId] = "wx123",
                [SystemSettingKeys.WechatAppSecret] = "secret",
                [SystemSettingKeys.WechatApiBaseUrl] = "http://api.weixin.qq.com"
            }, isDevelopment: false, expectedValid: false);
            Add("known-proxies-single-ip", new Dictionary<string, string>
            {
                [SystemSettingKeys.ReverseProxyKnownProxies] = """["10.0.0.1"]"""
            }, isDevelopment: false, expectedValid: true);
            // A CIDR block is not a parseable IPAddress; both the legacy and shared rule reject it.
            Add("known-proxies-with-cidr-entry", new Dictionary<string, string>
            {
                [SystemSettingKeys.ReverseProxyKnownProxies] = """["10.0.0.1","192.168.0.0/24"]"""
            }, isDevelopment: false, expectedValid: false);
            Add("known-proxies-invalid-entry", new Dictionary<string, string>
            {
                [SystemSettingKeys.ReverseProxyKnownProxies] = """["not-an-ip"]"""
            }, isDevelopment: false, expectedValid: false);
            Add("empty-string-optionals-present", new Dictionary<string, string>
            {
                [SystemSettingKeys.LokiUri] = "",
                [SystemSettingKeys.OpenTelemetryOtlpEndpoint] = "",
                [SystemSettingKeys.WechatAppId] = ""
            }, isDevelopment: false, expectedValid: true);

            return cases;
        }
    }

    [Theory]
    [MemberData(nameof(SnapshotCases))]
    public void CompleteCandidates_MatchTheFrozenVerdicts(
        string name,
        Dictionary<string, string> legacySnapshot,
        bool isDevelopment,
        bool expectedValid)
    {
        Assert.NotEmpty(name);

        var errors = SharedSettingComposition.ValidateCompleteCandidate(legacySnapshot, isDevelopment);

        Assert.Equal(expectedValid, errors.Count == 0);
    }

    [Fact]
    public void MissingSetupKeys_AreRejectedBeforeTheRegistryFillsDefaults()
    {
        var legacy = ServiceSettingDefinitions.BuildLegacyDefaults();
        legacy[SystemSettingKeys.PublicBaseUrl] = "https://accounts.example.com";
        legacy[SystemSettingKeys.JwtIssuer] = "https://accounts.example.com";
        legacy.Remove(SystemSettingKeys.JwtIssuer);

        var errors = SharedSettingComposition.ValidateCompleteCandidate(legacy, false);

        Assert.Contains(errors, error =>
            error.Key == "jwt.issuer" && error.ErrorCode == SettingCandidateValidation.MissingCode);
    }

    [Fact]
    public void MissingSensitiveKeys_ValidateLikeTheLegacyEmptyDefaults()
    {
        var legacy = ServiceSettingDefinitions.BuildLegacyDefaults();
        legacy[SystemSettingKeys.PublicBaseUrl] = "https://accounts.example.com";
        legacy[SystemSettingKeys.JwtIssuer] = "https://accounts.example.com";
        // The legacy default leaves the administrator username blank; a valid snapshot has one.
        legacy[SystemSettingKeys.AdminUsername] = "root-admin";

        // A shared-stack snapshot with the sensitive keys entirely unset (missing means unset)
        // must reach the same verdict the legacy empty defaults produced.
        var sharedInput = ToSharedInput(legacy);
        foreach (var sensitiveKey in ServiceSettingDefinitions.Table.Where(d => d.IsSensitive))
        {
            sharedInput.Remove(sensitiveKey.Key);
        }

        var result = SharedSettingComposition.CreateRegistry(isDevelopment: false).Validate(sharedInput);
        Assert.True(result.IsValid);
    }

    [Fact]
    public void CompositeErrors_AreClosedKeyScopedCodes()
    {
        var legacy = ServiceSettingDefinitions.BuildLegacyDefaults();
        legacy[SystemSettingKeys.PublicBaseUrl] = "http://accounts.example.com";
        legacy[SystemSettingKeys.JwtIssuer] = "http://accounts.example.com";

        var result = SharedSettingComposition.CreateRegistry(isDevelopment: false)
            .Validate(ToSharedInput(legacy));

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
        var legacy = ServiceSettingDefinitions.BuildLegacyDefaults();
        legacy[SystemSettingKeys.PublicBaseUrl] = "https://accounts.example.com";
        legacy[SystemSettingKeys.JwtIssuer] = "https://accounts.example.com";
        var sharedInput = ToSharedInput(legacy);
        sharedInput["unknown.key"] = "value";

        var result = SharedSettingComposition.CreateRegistry(isDevelopment: false).Validate(sharedInput);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.ErrorCode == WellKnownServiceSettingValidationErrorCodes.Unknown);
    }

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
