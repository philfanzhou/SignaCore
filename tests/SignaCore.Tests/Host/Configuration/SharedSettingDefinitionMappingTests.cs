using System.Text.Json;
using System.Text.RegularExpressions;
using ServiceMantle.Configuration;
using SignaCore.Host.Configuration;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

/// <summary>
/// The full old-key → normalized-key mapping table and the registered product definitions, pinned
/// entry by entry against fixed expected values. This is the reviewed comparison list task #101
/// requires plus the task #143 catalog retirement: any change to the mapping, the definition
/// table, or the registered projection must show up here against a literal expectation.
/// </summary>
public sealed partial class SharedSettingDefinitionMappingTests
{
    public static TheoryData<string, string> PinnedPairs => new()
    {
        // ---- Public identity of the deployment ----
        { "Endpoints:PublicBaseUrl", "endpoints.public_base_url" },
        { "Jwt:Issuer", "jwt.issuer" },
        // ---- Token policy ----
        { "Jwt:Audience", "jwt.audience" },
        { "Jwt:TokenExpirationHours", "jwt.token_expiration_hours" },
        { "RefreshToken:ExpirationDays", "refresh_token.expiration_days" },
        { "PasswordHasher:WorkFactor", "password_hasher.work_factor" },
        { "Security:AllowNonHttpsIssuer", "security.allow_non_https_issuer" },
        // ---- Administrative console ----
        { "AdminWeb:AllowedOrigins", "admin_web.allowed_origins" },
        { "Admin:Username", "admin.username" },
        // ---- Callback policy ----
        { "Callback:AllowedDomains", "callback.allowed_domains" },
        { "Callback:AllowPrivateAddresses", "callback.allow_private_addresses" },
        { "Callback:RequireHttps", "callback.require_https" },
        { "ReverseProxy:KnownProxies", "reverse_proxy.known_proxies" },
        // ---- SMS ----
        { "Sms:OtpTtlSeconds", "sms.otp_ttl_seconds" },
        { "Sms:MaxAttempts", "sms.max_attempts" },
        { "Sms:LockoutSeconds", "sms.lockout_seconds" },
        { "Sms:MinSendIntervalSeconds", "sms.min_send_interval_seconds" },
        { "Sms:MaxSendsPerHour", "sms.max_sends_per_hour" },
        { "Sms:MaxSendsPerDay", "sms.max_sends_per_day" },
        { "Sms:OtpHmacKey", "sms.otp_hmac_key" },
        { "Sms:BypassCode", "sms.bypass_code" },
        { "Sms:BypassPhones", "sms.bypass_phones" },
        { "Sms:Profiles", "sms.profiles" },
        // ---- WeChat ----
        { "WeChat:AppId", "wechat.app_id" },
        { "WeChat:AppSecret", "wechat.app_secret" },
        { "WeChat:ApiBaseUrl", "wechat.api_base_url" },
        // ---- LDAP ----
        { "Ldap:Enabled", "ldap.enabled" },
        { "Ldap:DefaultDirectoryKey", "ldap.default_directory_key" },
        { "Ldap:MaxConcurrentOperations", "ldap.max_concurrent_operations" },
        { "Ldap:Directories", "ldap.directories" },
        // ---- Observability ----
        { "Loki:Uri", "loki.uri" },
        { "OpenTelemetry:OtlpEndpoint", "opentelemetry.otlp_endpoint" },
        // ---- Consul service discovery ----
        { "Consul:Host", "consul.host" },
        { "Consul:Port", "consul.port" },
        { "Consul:Token", "consul.token" },
        { "Consul:Discovery:Enabled", "consul.discovery.enabled" },
        { "Consul:Discovery:Register", "consul.discovery.register" },
        { "Consul:Discovery:Deregister", "consul.discovery.deregister" },
        { "Consul:Discovery:ServiceName", "consul.discovery.service_name" },
        { "Consul:Discovery:HealthCheckPath", "consul.discovery.health_check_path" },
        { "Consul:Discovery:PreferIPAddress", "consul.discovery.prefer_ip_address" },
        { "Consul:Discovery:IPAddress", "consul.discovery.ip_address" },
        { "Consul:Discovery:Port", "consul.discovery.port" }
    };

    /// <summary>
    /// The fixed expectation of every product definition: the normalized key, its shared value
    /// type, sensitivity, requirement, and shared default. This is the retired catalog's content
    /// as a reviewed literal list — the "no silent key loss" evidence of task #143.
    /// </summary>
    public static TheoryData<string, string, bool, bool, string?> PinnedDefinitions => new()
    {
        // ---- Public identity of the deployment ----
        { "endpoints.public_base_url", "String", false, true, null },
        { "jwt.issuer", "String", false, true, null },
        // ---- Token policy ----
        { "jwt.audience", "String", false, true, "SignaCore.Services" },
        { "jwt.token_expiration_hours", "Number", false, true, "2" },
        { "refresh_token.expiration_days", "Number", false, true, "7" },
        { "password_hasher.work_factor", "Number", false, true, "11" },
        { "security.allow_non_https_issuer", "Boolean", false, true, "false" },
        // ---- Administrative console ----
        { "admin_web.allowed_origins", "Json", false, false, null },
        { "admin.username", "String", false, false, null },
        // ---- Callback policy ----
        { "callback.allowed_domains", "Json", false, false, null },
        { "callback.allow_private_addresses", "Boolean", false, true, "false" },
        { "callback.require_https", "Boolean", false, true, "true" },
        { "reverse_proxy.known_proxies", "Json", false, false, null },
        // ---- SMS ----
        { "sms.otp_ttl_seconds", "Number", false, true, "300" },
        { "sms.max_attempts", "Number", false, true, "5" },
        { "sms.lockout_seconds", "Number", false, true, "600" },
        { "sms.min_send_interval_seconds", "Number", false, true, "60" },
        { "sms.max_sends_per_hour", "Number", false, true, "5" },
        { "sms.max_sends_per_day", "Number", false, true, "10" },
        { "sms.otp_hmac_key", "String", true, false, null },
        { "sms.bypass_code", "String", true, false, null },
        { "sms.bypass_phones", "Json", false, false, null },
        { "sms.profiles", "Json", true, false, null },
        // ---- WeChat ----
        { "wechat.app_id", "String", false, false, null },
        { "wechat.app_secret", "String", true, false, null },
        { "wechat.api_base_url", "String", false, true, "https://api.weixin.qq.com" },
        // ---- LDAP ----
        { "ldap.enabled", "Boolean", false, true, "false" },
        { "ldap.default_directory_key", "String", false, false, null },
        { "ldap.max_concurrent_operations", "Number", false, true, "20" },
        { "ldap.directories", "Json", true, false, null },
        // ---- Observability ----
        { "loki.uri", "String", false, false, null },
        { "opentelemetry.otlp_endpoint", "String", false, false, null },
        // ---- Consul service discovery ----
        { "consul.host", "String", false, true, "host.docker.internal" },
        { "consul.port", "Number", false, true, "8500" },
        { "consul.token", "String", true, false, null },
        { "consul.discovery.enabled", "Boolean", false, true, "false" },
        { "consul.discovery.register", "Boolean", false, true, "false" },
        { "consul.discovery.deregister", "Boolean", false, true, "false" },
        { "consul.discovery.service_name", "String", false, true, "SignaCore" },
        { "consul.discovery.health_check_path", "String", false, true, "/health/ready" },
        { "consul.discovery.prefer_ip_address", "Boolean", false, true, "false" },
        { "consul.discovery.ip_address", "String", false, false, null },
        { "consul.discovery.port", "Number", false, true, "0" }
    };

    private static readonly Dictionary<string, ServiceSettingDefinition> SharedDefinitions =
        new ServiceSettingDefinitions().GetDefinitions().ToDictionary(
            definition => definition.Key, StringComparer.Ordinal);

    [GeneratedRegex("^[a-z0-9][a-z0-9._-]{0,127}$")]
    private static partial Regex NormalizedKeyPattern();

    [Theory]
    [MemberData(nameof(PinnedPairs))]
    public void EveryPinnedPair_MatchesTheRegisteredMapping(string legacyKey, string normalizedKey)
    {
        Assert.Equal(normalizedKey, SharedSettingKeys.NormalizedByLegacyKey[legacyKey]);
        Assert.Equal(legacyKey, SharedSettingKeys.LegacyByNormalizedKey[normalizedKey]);
    }

    [Fact]
    public void TheMapping_CoversTheDefinitionTableExactlyOnce()
    {
        // The per-pair theory above pins every entry of the mapping, so equal counts plus
        // containment of every table row prove the bijection with no uncovered key.
        Assert.Equal(PinnedPairs.Count, SharedSettingKeys.NormalizedByLegacyKey.Count);
        Assert.Equal(PinnedPairs.Count, ServiceSettingDefinitions.Table.Count);

        foreach (var definition in ServiceSettingDefinitions.Table)
        {
            Assert.Contains(definition.Key, SharedSettingKeys.LegacyByNormalizedKey.Keys);
        }
    }

    /// <summary>
    /// The registered projection matches the pinned expectation for every key, and the count is
    /// exactly the pinned count: no key is silently dropped, added, or reconfigured.
    /// </summary>
    [Theory]
    [MemberData(nameof(PinnedDefinitions))]
    public void EveryRegisteredDefinition_MatchesThePinnedExpectation(
        string key,
        string valueType,
        bool isSensitive,
        bool isRequired,
        string? defaultValue)
    {
        Assert.Equal(PinnedDefinitions.Count, SharedDefinitions.Count);

        var shared = SharedDefinitions[key];
        Assert.Equal(valueType, shared.ValueType.ToString());
        Assert.Equal(isSensitive, shared.IsSensitive);
        Assert.Equal(isRequired, shared.IsRequired);
        Assert.Equal(defaultValue, shared.DefaultValue);
        Assert.True(shared.RequiresRestart);
    }

    [Theory]
    [InlineData("sms.otp_hmac_key")]
    [InlineData("sms.bypass_code")]
    [InlineData("sms.profiles")]
    [InlineData("wechat.app_secret")]
    [InlineData("ldap.directories")]
    [InlineData("consul.token")]
    public void SensitiveKeys_AreOptionalAndCarryNoDefault(string normalizedKey)
    {
        var shared = SharedDefinitions[normalizedKey];
        Assert.True(shared.IsSensitive);
        Assert.False(shared.IsRequired);
        Assert.Null(shared.DefaultValue);
    }

    [Theory]
    [InlineData("endpoints.public_base_url")]
    [InlineData("jwt.issuer")]
    public void SetupCollectedKeys_AreRequiredWithoutDefaults(string normalizedKey)
    {
        var shared = SharedDefinitions[normalizedKey];
        Assert.True(shared.IsRequired);
        Assert.Null(shared.DefaultValue);
    }

    [Theory]
    [InlineData("admin.username", "")]
    [InlineData("loki.uri", "")]
    [InlineData("opentelemetry.otlp_endpoint", "")]
    [InlineData("wechat.app_id", "")]
    [InlineData("ldap.default_directory_key", "")]
    [InlineData("consul.discovery.ip_address", "")]
    [InlineData("admin_web.allowed_origins", "[]")]
    [InlineData("callback.allowed_domains", "[]")]
    [InlineData("reverse_proxy.known_proxies", "[]")]
    [InlineData("sms.bypass_phones", "[]")]
    public void EmptyLegacyDefaults_AreNotMigratedAndStayOptional(string normalizedKey, string legacyDefault)
    {
        var product = ServiceSettingDefinitions.Find(normalizedKey)!;
        Assert.Equal(legacyDefault, product.LegacyDefault);

        var shared = SharedDefinitions[normalizedKey];
        Assert.Null(shared.DefaultValue);
        Assert.False(shared.IsRequired);
    }

    [Fact]
    public void AllKeys_AreNormalizedAndAllKeysRequireRestart()
    {
        foreach (var definition in SharedDefinitions.Values)
        {
            Assert.Matches(NormalizedKeyPattern(), definition.Key);
            Assert.True(definition.RequiresRestart);
        }
    }

    [Theory]
    [InlineData("jwt.token_expiration_hours", 1, 24)]
    [InlineData("refresh_token.expiration_days", 1, 365)]
    [InlineData("password_hasher.work_factor", 10, 15)]
    public void LegacyRanges_AreRegisteredAsNumberRangeConstraints(string key, int minimum, int maximum)
    {
        var constraint = SharedDefinitions[key].Constraints
            .OfType<NumberRangeSettingConstraint>()
            .Single();
        Assert.Equal((decimal)minimum, constraint.Minimum);
        Assert.Equal((decimal)maximum, constraint.Maximum);
    }

    [Theory]
    [InlineData("jwt.token_expiration_hours")]
    [InlineData("refresh_token.expiration_days")]
    [InlineData("password_hasher.work_factor")]
    [InlineData("sms.otp_ttl_seconds")]
    [InlineData("sms.max_attempts")]
    [InlineData("sms.lockout_seconds")]
    [InlineData("sms.min_send_interval_seconds")]
    [InlineData("sms.max_sends_per_hour")]
    [InlineData("sms.max_sends_per_day")]
    [InlineData("ldap.max_concurrent_operations")]
    [InlineData("consul.port")]
    [InlineData("consul.discovery.port")]
    public void EveryNumberKey_HasTheIntegerConstraint(string key)
    {
        Assert.Contains(
            SharedDefinitions[key].Constraints,
            constraint => constraint is IntegerSettingConstraint);
    }

    [Theory]
    [InlineData("admin_web.allowed_origins", JsonValueKind.Array)]
    [InlineData("callback.allowed_domains", JsonValueKind.Array)]
    [InlineData("sms.bypass_phones", JsonValueKind.Array)]
    [InlineData("reverse_proxy.known_proxies", JsonValueKind.Array)]
    [InlineData("ldap.directories", JsonValueKind.Array)]
    [InlineData("sms.profiles", JsonValueKind.Object)]
    public void FixedRootJsonKeys_HaveTheRootKindConstraint(string key, JsonValueKind kind)
    {
        var constraint = SharedDefinitions[key].Constraints
            .OfType<JsonRootKindSettingConstraint>()
            .Single();
        Assert.Contains(kind, constraint.AllowedKinds);
    }

    [Fact]
    public void TheRegistry_BuildsFromTheProviderAndRejectsDuplicates()
    {
        var registry = new ServiceSettingDefinitionRegistry([new ServiceSettingDefinitions()]);
        Assert.Equal(SharedDefinitions.Count, registry.Definitions.Count);

        Assert.Throws<ServiceSettingDefinitionException>(() => new ServiceSettingDefinitionRegistry(
            [new ServiceSettingDefinitions(), new ServiceSettingDefinitions()]));
    }
}
