using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Host.Configuration;

/// <summary>
/// The versioned application code that owns safe product defaults for a new installation, and the
/// single list of which keys the database is authoritative for.
/// <para>
/// Anything not listed here is not database-backed configuration: host port, logging sinks, and the
/// bootstrap file location stay with appsettings and the launcher.
/// </para>
/// </summary>
internal static class SystemSettingsCatalog
{
    private static readonly SystemSettingDefinition[] DefinitionList =
    [
        // ---- Public identity of the deployment ----
        // No defaults: first-run setup collects the canonical public base URL and derives the issuer
        // from it, so a deployment can never silently start advertising a placeholder issuer.
        new(SystemSettingKeys.PublicBaseUrl, SettingValueTypes.String, IsSecret: false, DefaultValue: null),
        new(SystemSettingKeys.JwtIssuer, SettingValueTypes.String, IsSecret: false, DefaultValue: null),

        // ---- Token policy ----
        new(SystemSettingKeys.JwtAudience, SettingValueTypes.String, IsSecret: false, "SignaCore.Services"),
        new(SystemSettingKeys.JwtTokenExpirationHours, SettingValueTypes.Number, IsSecret: false, "2"),
        new(SystemSettingKeys.RefreshTokenExpirationDays, SettingValueTypes.Number, IsSecret: false, "7"),
        new(
            SystemSettingKeys.PasswordHasherWorkFactor,
            SettingValueTypes.Number,
            IsSecret: false,
            IdentityConstants.BCryptWorkFactor.ToString(System.Globalization.CultureInfo.InvariantCulture)),
        new(SystemSettingKeys.SecurityAllowNonHttpsIssuer, SettingValueTypes.Boolean, IsSecret: false, "false"),

        // ---- Administrative console ----
        new(SystemSettingKeys.AdminWebAllowedOrigins, SettingValueTypes.Json, IsSecret: false, "[]"),
        new(SystemSettingKeys.AdminUsername, SettingValueTypes.String, IsSecret: false, ""),

        // ---- Callback policy ----
        new(SystemSettingKeys.CallbackAllowedDomains, SettingValueTypes.Json, IsSecret: false, "[]"),
        new(SystemSettingKeys.CallbackAllowPrivateAddresses, SettingValueTypes.Boolean, IsSecret: false, "false"),
        new(SystemSettingKeys.CallbackRequireHttps, SettingValueTypes.Boolean, IsSecret: false, "true"),

        new(SystemSettingKeys.ReverseProxyKnownProxies, SettingValueTypes.Json, IsSecret: false, "[]"),

        // ---- SMS: limits ship enabled, delivery ships disabled ----
        new(SystemSettingKeys.SmsOtpTtlSeconds, SettingValueTypes.Number, IsSecret: false, "300"),
        new(SystemSettingKeys.SmsMaxAttempts, SettingValueTypes.Number, IsSecret: false, "5"),
        new(SystemSettingKeys.SmsLockoutSeconds, SettingValueTypes.Number, IsSecret: false, "600"),
        new(SystemSettingKeys.SmsMinSendIntervalSeconds, SettingValueTypes.Number, IsSecret: false, "60"),
        new(SystemSettingKeys.SmsMaxSendsPerHour, SettingValueTypes.Number, IsSecret: false, "5"),
        new(SystemSettingKeys.SmsMaxSendsPerDay, SettingValueTypes.Number, IsSecret: false, "10"),
        new(SystemSettingKeys.SmsOtpHmacKey, SettingValueTypes.String, IsSecret: true, ""),
        new(SystemSettingKeys.SmsBypassCode, SettingValueTypes.String, IsSecret: true, ""),
        new(SystemSettingKeys.SmsBypassPhones, SettingValueTypes.Json, IsSecret: false, "[]"),
        // Profiles carry cloud access-key secrets, so the whole document is protected.
        new(SystemSettingKeys.SmsProfiles, SettingValueTypes.Json, IsSecret: true, "{}"),

        // ---- WeChat ----
        new(SystemSettingKeys.WechatAppId, SettingValueTypes.String, IsSecret: false, ""),
        new(SystemSettingKeys.WechatAppSecret, SettingValueTypes.String, IsSecret: true, ""),
        new(SystemSettingKeys.WechatApiBaseUrl, SettingValueTypes.String, IsSecret: false, "https://api.weixin.qq.com"),

        // ---- LDAP ----
        new(SystemSettingKeys.LdapEnabled, SettingValueTypes.Boolean, IsSecret: false, "false"),
        new(SystemSettingKeys.LdapDefaultDirectoryKey, SettingValueTypes.String, IsSecret: false, ""),
        new(SystemSettingKeys.LdapMaxConcurrentOperations, SettingValueTypes.Number, IsSecret: false, "20"),
        // Directory entries carry bind passwords.
        new(SystemSettingKeys.LdapDirectories, SettingValueTypes.Json, IsSecret: true, "[]"),

        // ---- Observability ----
        new(SystemSettingKeys.LokiUri, SettingValueTypes.String, IsSecret: false, ""),
        new(SystemSettingKeys.OpenTelemetryOtlpEndpoint, SettingValueTypes.String, IsSecret: false, ""),

        // ---- Consul service discovery (optional, disabled by default) ----
        new(SystemSettingKeys.ConsulHost, SettingValueTypes.String, IsSecret: false, "host.docker.internal"),
        new(SystemSettingKeys.ConsulPort, SettingValueTypes.Number, IsSecret: false, "8500"),
        new(SystemSettingKeys.ConsulToken, SettingValueTypes.String, IsSecret: true, ""),
        new(SystemSettingKeys.ConsulDiscoveryEnabled, SettingValueTypes.Boolean, IsSecret: false, "false"),
        new(SystemSettingKeys.ConsulDiscoveryRegister, SettingValueTypes.Boolean, IsSecret: false, "false"),
        new(SystemSettingKeys.ConsulDiscoveryDeregister, SettingValueTypes.Boolean, IsSecret: false, "false"),
        new(SystemSettingKeys.ConsulDiscoveryServiceName, SettingValueTypes.String, IsSecret: false, "SignaCore"),
        new(SystemSettingKeys.ConsulDiscoveryHealthCheckPath, SettingValueTypes.String, IsSecret: false, HealthEndpoints.Ready),
        new(SystemSettingKeys.ConsulDiscoveryPreferIpAddress, SettingValueTypes.Boolean, IsSecret: false, "false"),
        new(SystemSettingKeys.ConsulDiscoveryIpAddress, SettingValueTypes.String, IsSecret: false, ""),
        new(SystemSettingKeys.ConsulDiscoveryPort, SettingValueTypes.Number, IsSecret: false, "0")
    ];

    public static IReadOnlyList<SystemSettingDefinition> Definitions => DefinitionList;

    private static readonly Dictionary<string, SystemSettingDefinition> ByKey =
        DefinitionList.ToDictionary(definition => definition.Key, StringComparer.OrdinalIgnoreCase);

    public static bool IsManaged(string key) => ByKey.ContainsKey(key);

    public static SystemSettingDefinition? Find(string key) =>
        ByKey.TryGetValue(key, out var definition) ? definition : null;

    /// <summary>Keys that must be present in an activated snapshot.</summary>
    public static IEnumerable<string> RequiredKeys => DefinitionList.Select(definition => definition.Key);

    /// <summary>
    /// The default snapshot for a brand-new installation, before first-run setup supplies the values
    /// that have no safe default.
    /// </summary>
    public static Dictionary<string, string> BuildDefaults()
    {
        return DefinitionList
            .Where(definition => definition.HasDefault)
            .ToDictionary(
                definition => definition.Key,
                definition => definition.DefaultValue!,
                StringComparer.OrdinalIgnoreCase);
    }
}
