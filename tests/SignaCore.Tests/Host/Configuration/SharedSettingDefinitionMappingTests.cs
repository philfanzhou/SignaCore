using System.Text.Json;
using System.Text.RegularExpressions;
using ServiceMantle.Configuration;
using SignaCore.Host.Configuration;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

/// <summary>
/// The full old-key → normalized-key mapping table, pinned entry by entry, and its equivalence
/// with the legacy catalog. This is the reviewed comparison list task #101 requires: any change to
/// either side must show up here.
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
    public void TheMapping_CoversTheWholeCatalogExactlyOnce()
    {
        Assert.Equal(
            SystemSettingsCatalog.Definitions.Count,
            SharedSettingKeys.NormalizedByLegacyKey.Count);
        foreach (var legacy in SystemSettingsCatalog.Definitions)
        {
            Assert.Contains(legacy.Key, SharedSettingKeys.NormalizedByLegacyKey.Keys);
        }
    }

    [Fact]
    public void EveryRegisteredDefinition_MatchesItsLegacyCatalogEntry()
    {
        Assert.Equal(SystemSettingsCatalog.Definitions.Count, SharedDefinitions.Count);

        foreach (var legacy in SystemSettingsCatalog.Definitions)
        {
            var shared = SharedDefinitions[SharedSettingKeys.NormalizedByLegacyKey[legacy.Key]];
            Assert.Equal(MapValueType(legacy.ValueType), shared.ValueType);
            Assert.Equal(legacy.IsSecret, shared.IsSensitive);
            Assert.Equal(legacy.RestartRequired, shared.RequiresRestart);
            Assert.Equal(IsOptional(legacy), !shared.IsRequired);

            if (legacy.IsSecret || legacy.DefaultValue is not { } legacyDefault ||
                ServiceSettingDefinitions.IsEmptyDefault(legacy.ValueType, legacyDefault))
            {
                Assert.Null(shared.DefaultValue);
            }
            else
            {
                Assert.Equal(legacy.DefaultValue, shared.DefaultValue);
            }
        }
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
        var legacy = SystemSettingsCatalog.Find(SharedSettingKeys.LegacyByNormalizedKey[normalizedKey])!;
        Assert.Equal(legacyDefault, legacy.DefaultValue);

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

    private static ServiceSettingValueType MapValueType(string valueType) => valueType switch
    {
        "String" => ServiceSettingValueType.String,
        "Number" => ServiceSettingValueType.Number,
        "Boolean" => ServiceSettingValueType.Boolean,
        "Json" => ServiceSettingValueType.Json,
        _ => throw new InvalidOperationException(valueType)
    };

    private static bool IsOptional(SystemSettingDefinition legacy) =>
        legacy.IsSecret ||
        (legacy.DefaultValue is { } value && ServiceSettingDefinitions.IsEmptyDefault(legacy.ValueType, value));
}
