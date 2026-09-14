namespace SignaCore.Host.Configuration;

/// <summary>
/// The one-to-one mapping between the legacy database-backed setting keys and the ServiceMantle
/// normalized setting keys (<c>:</c> becomes <c>.</c>, PascalCase segments become snake_case).
/// </summary>
/// <remarks>
/// The mapping is written out entry by entry instead of being derived by a text converter, so the
/// new key of every product setting is a reviewed, pinned fact. The definition and equivalence
/// tests assert this table against <see cref="SystemSettingsCatalog"/> in both directions.
/// </remarks>
internal static class SharedSettingKeys
{
    internal static readonly IReadOnlyDictionary<string, string> NormalizedByLegacyKey =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // ---- Public identity of the deployment ----
            [SystemSettingKeys.PublicBaseUrl] = "endpoints.public_base_url",
            [SystemSettingKeys.JwtIssuer] = "jwt.issuer",

            // ---- Token policy ----
            [SystemSettingKeys.JwtAudience] = "jwt.audience",
            [SystemSettingKeys.JwtTokenExpirationHours] = "jwt.token_expiration_hours",
            [SystemSettingKeys.RefreshTokenExpirationDays] = "refresh_token.expiration_days",
            [SystemSettingKeys.PasswordHasherWorkFactor] = "password_hasher.work_factor",
            [SystemSettingKeys.SecurityAllowNonHttpsIssuer] = "security.allow_non_https_issuer",

            // ---- Administrative console ----
            [SystemSettingKeys.AdminWebAllowedOrigins] = "admin_web.allowed_origins",
            [SystemSettingKeys.AdminUsername] = "admin.username",

            // ---- Callback policy ----
            [SystemSettingKeys.CallbackAllowedDomains] = "callback.allowed_domains",
            [SystemSettingKeys.CallbackAllowPrivateAddresses] = "callback.allow_private_addresses",
            [SystemSettingKeys.CallbackRequireHttps] = "callback.require_https",
            [SystemSettingKeys.ReverseProxyKnownProxies] = "reverse_proxy.known_proxies",

            // ---- SMS ----
            [SystemSettingKeys.SmsOtpTtlSeconds] = "sms.otp_ttl_seconds",
            [SystemSettingKeys.SmsMaxAttempts] = "sms.max_attempts",
            [SystemSettingKeys.SmsLockoutSeconds] = "sms.lockout_seconds",
            [SystemSettingKeys.SmsMinSendIntervalSeconds] = "sms.min_send_interval_seconds",
            [SystemSettingKeys.SmsMaxSendsPerHour] = "sms.max_sends_per_hour",
            [SystemSettingKeys.SmsMaxSendsPerDay] = "sms.max_sends_per_day",
            [SystemSettingKeys.SmsOtpHmacKey] = "sms.otp_hmac_key",
            [SystemSettingKeys.SmsBypassCode] = "sms.bypass_code",
            [SystemSettingKeys.SmsBypassPhones] = "sms.bypass_phones",
            [SystemSettingKeys.SmsProfiles] = "sms.profiles",

            // ---- WeChat ----
            [SystemSettingKeys.WechatAppId] = "wechat.app_id",
            [SystemSettingKeys.WechatAppSecret] = "wechat.app_secret",
            [SystemSettingKeys.WechatApiBaseUrl] = "wechat.api_base_url",

            // ---- LDAP ----
            [SystemSettingKeys.LdapEnabled] = "ldap.enabled",
            [SystemSettingKeys.LdapDefaultDirectoryKey] = "ldap.default_directory_key",
            [SystemSettingKeys.LdapMaxConcurrentOperations] = "ldap.max_concurrent_operations",
            [SystemSettingKeys.LdapDirectories] = "ldap.directories",

            // ---- Observability ----
            [SystemSettingKeys.LokiUri] = "loki.uri",
            [SystemSettingKeys.OpenTelemetryOtlpEndpoint] = "opentelemetry.otlp_endpoint",

            // ---- Consul service discovery ----
            [SystemSettingKeys.ConsulHost] = "consul.host",
            [SystemSettingKeys.ConsulPort] = "consul.port",
            [SystemSettingKeys.ConsulToken] = "consul.token",
            [SystemSettingKeys.ConsulDiscoveryEnabled] = "consul.discovery.enabled",
            [SystemSettingKeys.ConsulDiscoveryRegister] = "consul.discovery.register",
            [SystemSettingKeys.ConsulDiscoveryDeregister] = "consul.discovery.deregister",
            [SystemSettingKeys.ConsulDiscoveryServiceName] = "consul.discovery.service_name",
            [SystemSettingKeys.ConsulDiscoveryHealthCheckPath] = "consul.discovery.health_check_path",
            [SystemSettingKeys.ConsulDiscoveryPreferIpAddress] = "consul.discovery.prefer_ip_address",
            [SystemSettingKeys.ConsulDiscoveryIpAddress] = "consul.discovery.ip_address",
            [SystemSettingKeys.ConsulDiscoveryPort] = "consul.discovery.port"
        };

    internal static readonly IReadOnlyDictionary<string, string> LegacyByNormalizedKey =
        NormalizedByLegacyKey.ToDictionary(
            pair => pair.Value,
            pair => pair.Key,
            StringComparer.Ordinal);
}
