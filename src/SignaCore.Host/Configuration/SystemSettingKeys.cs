namespace SignaCore.Host.Configuration;

/// <summary>
/// Configuration keys owned by <c>system_settings</c>. They intentionally reuse the existing
/// ASP.NET Core colon-separated names so the loader can hand values straight to
/// <c>IConfiguration</c> and every consumer keeps reading the key it already read.
/// </summary>
internal static class SystemSettingKeys
{
    public const string PublicBaseUrl = "Endpoints:PublicBaseUrl";

    public const string JwtIssuer = "Jwt:Issuer";
    public const string JwtAudience = "Jwt:Audience";
    public const string JwtTokenExpirationHours = "Jwt:TokenExpirationHours";
    public const string RefreshTokenExpirationDays = "RefreshToken:ExpirationDays";
    public const string PasswordHasherWorkFactor = "PasswordHasher:WorkFactor";
    public const string SecurityAllowNonHttpsIssuer = "Security:AllowNonHttpsIssuer";

    public const string AdminWebAllowedOrigins = "AdminWeb:AllowedOrigins";

    /// <summary>
    /// Username of the administrator account created by first-run setup. Only the username lives
    /// here; the password exists solely as a hash in <c>password_credentials</c>.
    /// </summary>
    public const string AdminUsername = "Admin:Username";

    /// <summary>Pre-change key that <see cref="AdminUsername"/> replaces, read only by the legacy import.</summary>
    public const string LegacyAdminBootstrapUsername = "AdminBootstrap:Username";

    public const string CallbackAllowedDomains = "Callback:AllowedDomains";
    public const string CallbackAllowPrivateAddresses = "Callback:AllowPrivateAddresses";
    public const string CallbackRequireHttps = "Callback:RequireHttps";

    public const string ReverseProxyKnownProxies = "ReverseProxy:KnownProxies";

    public const string SmsOtpTtlSeconds = "Sms:OtpTtlSeconds";
    public const string SmsMaxAttempts = "Sms:MaxAttempts";
    public const string SmsLockoutSeconds = "Sms:LockoutSeconds";
    public const string SmsMinSendIntervalSeconds = "Sms:MinSendIntervalSeconds";
    public const string SmsMaxSendsPerHour = "Sms:MaxSendsPerHour";
    public const string SmsMaxSendsPerDay = "Sms:MaxSendsPerDay";
    public const string SmsOtpHmacKey = "Sms:OtpHmacKey";
    public const string SmsBypassCode = "Sms:BypassCode";
    public const string SmsBypassPhones = "Sms:BypassPhones";
    public const string SmsProfiles = "Sms:Profiles";

    public const string WechatAppId = "WeChat:AppId";
    public const string WechatAppSecret = "WeChat:AppSecret";
    public const string WechatApiBaseUrl = "WeChat:ApiBaseUrl";

    public const string LdapEnabled = "Ldap:Enabled";
    public const string LdapDefaultDirectoryKey = "Ldap:DefaultDirectoryKey";
    public const string LdapMaxConcurrentOperations = "Ldap:MaxConcurrentOperations";
    public const string LdapDirectories = "Ldap:Directories";

    public const string LokiUri = "Loki:Uri";
    public const string OpenTelemetryOtlpEndpoint = "OpenTelemetry:OtlpEndpoint";

    public const string ConsulHost = "Consul:Host";
    public const string ConsulPort = "Consul:Port";
    public const string ConsulToken = "Consul:Token";
    public const string ConsulDiscoveryEnabled = "Consul:Discovery:Enabled";
    public const string ConsulDiscoveryRegister = "Consul:Discovery:Register";
    public const string ConsulDiscoveryDeregister = "Consul:Discovery:Deregister";
    public const string ConsulDiscoveryServiceName = "Consul:Discovery:ServiceName";
    public const string ConsulDiscoveryHealthCheckPath = "Consul:Discovery:HealthCheckPath";
    public const string ConsulDiscoveryPreferIpAddress = "Consul:Discovery:PreferIPAddress";
    public const string ConsulDiscoveryIpAddress = "Consul:Discovery:IPAddress";
    public const string ConsulDiscoveryPort = "Consul:Discovery:Port";
}
