using System.Text.Json;
using ServiceMantle.Configuration;
using SignaCore.Database;

namespace SignaCore.Host.Configuration;

/// <summary>
/// One row of the authoritative SignaCore product setting table: the normalized shared key, its
/// value type and sensitivity, and the legacy wire default the input paths fall back to.
/// </summary>
/// <param name="Key">
/// The ServiceMantle normalized key, for example <c>jwt.audience</c>. The legacy colon-keyed
/// configuration form is derived through <see cref="SharedSettingKeys"/>, never duplicated here.
/// </param>
/// <param name="ValueType">The shared value type; it is also the legacy storage form.</param>
/// <param name="IsSensitive">Protected as a shared-protector envelope and never returned by queries.</param>
/// <param name="LegacyDefault">
/// The exact legacy catalog default, including the legacy empty forms (<c>""</c>, <c>[]</c>,
/// <c>{}</c>). <c>null</c> means the value has no default and is collected by first-run setup.
/// Sensitive keys and empty defaults are not carried into the shared definition (see
/// <see cref="SharedDefaultValue"/>), but the legacy input paths keep reading this column.
/// </param>
/// <param name="RestartRequired">
/// True while the owning subsystem has no explicit reload support. Every setting starts here; a
/// subsystem is moved out only once it can rebuild itself safely.
/// </param>
internal sealed record ProductSettingDefinition(
    string Key,
    ServiceSettingValueType ValueType,
    bool IsSensitive,
    string? LegacyDefault,
    bool RestartRequired = true)
{
    public bool HasLegacyDefault => LegacyDefault is not null;

    public bool HasEmptyLegacyDefault =>
        LegacyDefault is { } value && IsEmptyDefault(ValueType, value);

    /// <summary>
    /// Sensitive definitions (missing means unset) and the definitions whose legacy default was an
    /// empty string or an empty document. Everything else keeps the "must be present in the active
    /// snapshot" requirement.
    /// </summary>
    public bool IsOptional => IsSensitive || HasEmptyLegacyDefault;

    /// <summary>
    /// The shared-stack default: sensitive definitions cannot carry defaults (package contract),
    /// and legacy empty-string or empty-document defaults are deliberately not migrated — those
    /// keys start unset and the composite validator treats them exactly as the legacy validator
    /// treated the empty value.
    /// </summary>
    public string? SharedDefaultValue => IsOptional ? null : LegacyDefault;

    internal static bool IsEmptyDefault(ServiceSettingValueType valueType, string value) =>
        valueType switch
        {
            ServiceSettingValueType.String => value.Length == 0,
            ServiceSettingValueType.Json => value is "[]" or "{}",
            _ => false
        };
}

/// <summary>
/// Registers the SignaCore product settings on the shared ServiceMantle setting contract.
/// </summary>
/// <remarks>
/// <para>
/// The definition table below is the single authoritative catalog of the product's database-backed
/// settings; the retired legacy catalog no longer exists. Every row maps to exactly one normalized
/// key (see <see cref="SharedSettingKeys"/>) with the value type, restart flag, and legacy wire
/// default pinned in place. The mapping and definition tests assert the table against fixed
/// expected values entry by entry, so any change to either side shows up there.
/// </para>
/// <para>
/// Declared differences, fixed by task #101: sensitive definitions carry no default value and are
/// not required (missing means unset), and legacy empty-string / empty-document defaults are not
/// carried over — those keys are likewise optional and start unset, so a legacy snapshot carrying
/// the empty default and a new-stack snapshot with the key unset accept and reject the same
/// updates. Number keys keep the legacy integer semantics through
/// <see cref="IntegerSettingConstraint"/> and the legacy ranges through
/// <see cref="NumberRangeSettingConstraint"/>; the JSON keys with a fixed root kind use
/// <see cref="JsonRootKindSettingConstraint"/>. Cross-key rules stay in
/// <see cref="SignaCoreSettingCompositeValidator"/>.
/// </para>
/// </remarks>
internal sealed class ServiceSettingDefinitions : IServiceSettingDefinitionProvider
{
    internal const string IntegerErrorCode = "signacore.setting.integer";

    private static readonly IReadOnlyList<ProductSettingDefinition> DefinitionTable =
    [
        // ---- Public identity of the deployment ----
        // No defaults: first-run setup collects the canonical public base URL and derives the issuer
        // from it, so a deployment can never silently start advertising a placeholder issuer.
        new("endpoints.public_base_url", ServiceSettingValueType.String, IsSensitive: false, LegacyDefault: null),
        new("jwt.issuer", ServiceSettingValueType.String, IsSensitive: false, LegacyDefault: null),

        // ---- Token policy ----
        new("jwt.audience", ServiceSettingValueType.String, IsSensitive: false, LegacyDefault: "SignaCore.Services"),
        new("jwt.token_expiration_hours", ServiceSettingValueType.Number, IsSensitive: false, LegacyDefault: "2"),
        new("refresh_token.expiration_days", ServiceSettingValueType.Number, IsSensitive: false, LegacyDefault: "7"),
        new(
            "password_hasher.work_factor",
            ServiceSettingValueType.Number,
            IsSensitive: false,
            LegacyDefault: IdentityConstants.BCryptWorkFactor.ToString(System.Globalization.CultureInfo.InvariantCulture)),
        new("security.allow_non_https_issuer", ServiceSettingValueType.Boolean, IsSensitive: false, LegacyDefault: "false"),

        // ---- Administrative console ----
        new("admin_web.allowed_origins", ServiceSettingValueType.Json, IsSensitive: false, LegacyDefault: "[]"),
        new("admin.username", ServiceSettingValueType.String, IsSensitive: false, LegacyDefault: ""),

        // ---- Callback policy ----
        new("callback.allowed_domains", ServiceSettingValueType.Json, IsSensitive: false, LegacyDefault: "[]"),
        new("callback.allow_private_addresses", ServiceSettingValueType.Boolean, IsSensitive: false, LegacyDefault: "false"),
        new("callback.require_https", ServiceSettingValueType.Boolean, IsSensitive: false, LegacyDefault: "true"),

        new("reverse_proxy.known_proxies", ServiceSettingValueType.Json, IsSensitive: false, LegacyDefault: "[]"),

        // ---- SMS: limits ship enabled, delivery ships disabled ----
        new("sms.otp_ttl_seconds", ServiceSettingValueType.Number, IsSensitive: false, LegacyDefault: "300"),
        new("sms.max_attempts", ServiceSettingValueType.Number, IsSensitive: false, LegacyDefault: "5"),
        new("sms.lockout_seconds", ServiceSettingValueType.Number, IsSensitive: false, LegacyDefault: "600"),
        new("sms.min_send_interval_seconds", ServiceSettingValueType.Number, IsSensitive: false, LegacyDefault: "60"),
        new("sms.max_sends_per_hour", ServiceSettingValueType.Number, IsSensitive: false, LegacyDefault: "5"),
        new("sms.max_sends_per_day", ServiceSettingValueType.Number, IsSensitive: false, LegacyDefault: "10"),
        new("sms.otp_hmac_key", ServiceSettingValueType.String, IsSensitive: true, LegacyDefault: ""),
        new("sms.bypass_code", ServiceSettingValueType.String, IsSensitive: true, LegacyDefault: ""),
        new("sms.bypass_phones", ServiceSettingValueType.Json, IsSensitive: false, LegacyDefault: "[]"),
        // Profiles carry cloud access-key secrets, so the whole document is protected.
        new("sms.profiles", ServiceSettingValueType.Json, IsSensitive: true, LegacyDefault: "{}"),

        // ---- WeChat ----
        new("wechat.app_id", ServiceSettingValueType.String, IsSensitive: false, LegacyDefault: ""),
        new("wechat.app_secret", ServiceSettingValueType.String, IsSensitive: true, LegacyDefault: ""),
        new("wechat.api_base_url", ServiceSettingValueType.String, IsSensitive: false, LegacyDefault: "https://api.weixin.qq.com"),

        // ---- LDAP ----
        new("ldap.enabled", ServiceSettingValueType.Boolean, IsSensitive: false, LegacyDefault: "false"),
        new("ldap.default_directory_key", ServiceSettingValueType.String, IsSensitive: false, LegacyDefault: ""),
        new("ldap.max_concurrent_operations", ServiceSettingValueType.Number, IsSensitive: false, LegacyDefault: "20"),
        // Directory entries carry bind passwords.
        new("ldap.directories", ServiceSettingValueType.Json, IsSensitive: true, LegacyDefault: "[]"),

        // ---- Observability ----
        new("loki.uri", ServiceSettingValueType.String, IsSensitive: false, LegacyDefault: ""),
        // The complete Authorization header value sent to Loki (for example "Basic ..." or
        // "Bearer ..."); it is a credential, so it is protected and never returned by queries.
        new("loki.authorization", ServiceSettingValueType.String, IsSensitive: true, LegacyDefault: ""),
        new("opentelemetry.otlp_endpoint", ServiceSettingValueType.String, IsSensitive: false, LegacyDefault: ""),

        // ---- Consul service discovery (optional, disabled by default) ----
        new("consul.host", ServiceSettingValueType.String, IsSensitive: false, LegacyDefault: "host.docker.internal"),
        new("consul.port", ServiceSettingValueType.Number, IsSensitive: false, LegacyDefault: "8500"),
        new("consul.token", ServiceSettingValueType.String, IsSensitive: true, LegacyDefault: ""),
        new("consul.discovery.enabled", ServiceSettingValueType.Boolean, IsSensitive: false, LegacyDefault: "false"),
        new("consul.discovery.register", ServiceSettingValueType.Boolean, IsSensitive: false, LegacyDefault: "false"),
        new("consul.discovery.deregister", ServiceSettingValueType.Boolean, IsSensitive: false, LegacyDefault: "false"),
        new("consul.discovery.service_name", ServiceSettingValueType.String, IsSensitive: false, LegacyDefault: "SignaCore"),
        // The persisted default is the deployed readiness probe path the shared health endpoints
        // own; the literal is the contract, pinned by SharedSettingDefinitionMappingTests.
        new("consul.discovery.health_check_path", ServiceSettingValueType.String, IsSensitive: false, LegacyDefault: "/health/ready"),
        new("consul.discovery.prefer_ip_address", ServiceSettingValueType.Boolean, IsSensitive: false, LegacyDefault: "false"),
        new("consul.discovery.ip_address", ServiceSettingValueType.String, IsSensitive: false, LegacyDefault: ""),
        new("consul.discovery.port", ServiceSettingValueType.Number, IsSensitive: false, LegacyDefault: "0")
    ];

    /// <summary>The authoritative product definition table, one row per registered setting.</summary>
    internal static readonly IReadOnlyList<ProductSettingDefinition> Table = DefinitionTable;

    private static readonly IReadOnlyDictionary<string, ProductSettingDefinition> ByKey =
        DefinitionTable.ToDictionary(definition => definition.Key, StringComparer.Ordinal);

    /// <summary>The row of one normalized key, or <c>null</c> when the key is not a product setting.</summary>
    internal static ProductSettingDefinition? Find(string key) =>
        ByKey.TryGetValue(key, out var definition) ? definition : null;

    /// <summary>
    /// The legacy colon-keyed configuration key of a table row. The mapping is owned by
    /// <see cref="SharedSettingKeys"/>; this helper is the one lookup point for the input paths.
    /// </summary>
    internal static string LegacyKeyOf(ProductSettingDefinition definition) =>
        SharedSettingKeys.LegacyByNormalizedKey[definition.Key];

    /// <summary>
    /// The legacy-keyed default snapshot for a brand-new installation, before first-run setup
    /// supplies the values that have no safe default. Every key without a legacy default is absent.
    /// </summary>
    internal static Dictionary<string, string> BuildLegacyDefaults() =>
        DefinitionTable
            .Where(definition => definition.HasLegacyDefault)
            .ToDictionary(
                LegacyKeyOf,
                definition => definition.LegacyDefault!,
                StringComparer.OrdinalIgnoreCase);

    public IEnumerable<ServiceSettingDefinition> GetDefinitions()
    {
        foreach (var product in DefinitionTable)
        {
            yield return new ServiceSettingDefinition(
                product.Key,
                product.ValueType,
                isRequired: !product.IsOptional,
                isSensitive: product.IsSensitive,
                defaultValue: product.SharedDefaultValue,
                requiresRestart: product.RestartRequired,
                constraints: BuildConstraints(product));
        }
    }

    private static readonly IReadOnlyDictionary<string, (decimal Minimum, decimal Maximum)> Ranges =
        new Dictionary<string, (decimal, decimal)>(StringComparer.Ordinal)
        {
            ["jwt.token_expiration_hours"] = (1, 24),
            ["refresh_token.expiration_days"] = (1, 365),
            ["password_hasher.work_factor"] = (10, 15)
        };

    private static readonly IReadOnlyDictionary<string, JsonValueKind> JsonRootKinds =
        new Dictionary<string, JsonValueKind>(StringComparer.Ordinal)
        {
            ["admin_web.allowed_origins"] = JsonValueKind.Array,
            ["callback.allowed_domains"] = JsonValueKind.Array,
            ["sms.bypass_phones"] = JsonValueKind.Array,
            ["reverse_proxy.known_proxies"] = JsonValueKind.Array,
            ["ldap.directories"] = JsonValueKind.Array,
            ["sms.profiles"] = JsonValueKind.Object
        };

    private static IEnumerable<IServiceSettingValueConstraint> BuildConstraints(
        ProductSettingDefinition definition)
    {
        if (definition.ValueType == ServiceSettingValueType.Number)
        {
            yield return new IntegerSettingConstraint();
            if (Ranges.TryGetValue(definition.Key, out var range))
            {
                yield return new NumberRangeSettingConstraint(range.Minimum, range.Maximum);
            }
        }
        else if (definition.ValueType == ServiceSettingValueType.Json &&
                 JsonRootKinds.TryGetValue(definition.Key, out var rootKind))
        {
            yield return new JsonRootKindSettingConstraint([rootKind]);
        }
    }
}
