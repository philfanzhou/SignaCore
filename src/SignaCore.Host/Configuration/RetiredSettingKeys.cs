namespace SignaCore.Host.Configuration;

/// <summary>
/// The normalized shared setting keys SignaCore has retired from its catalog.
/// </summary>
/// <remarks>
/// <para>
/// A stored aggregate written by an older release may still carry rows for these keys. The shared
/// loader fails closed on any persisted key it has no definition for, so every SignaCore read of
/// the stored aggregate drops retired rows before materialization: a leftover row never blocks
/// startup, the management query path, or a management update. Operators may still delete the
/// rows explicitly (the upgrade notes in <c>docs/development/Configuration.md</c> describe the
/// one-row cleanup); the reads here ignore them either way.
/// </para>
/// <para>
/// Retiring a key requires exactly two facts here: its normalized name, and the release note that
/// tells operators the row can be dropped. A retired key must never re-enter the definition
/// table, the legacy key mapping, or the admin console.
/// </para>
/// </remarks>
internal static class RetiredSettingKeys
{
    /// <summary>
    /// Retired with the ServiceMantle 0.3.2 upgrade: the Loki endpoint accepts plain
    /// <c>http</c> and <c>https</c> alike, so the explicit insecure-transport switch is a dead key.
    /// </summary>
    internal const string LokiAllowInsecureHttp = "loki.allow_insecure_http";

    /// <summary>
    /// Retired by ADR 0008: the hosted-login HTTP test-origin allowlist and its Testing
    /// environment gate are gone — plain-HTTP redirect URIs and public base URLs are accepted
    /// structurally, so the list has nothing left to admit.
    /// </summary>
    internal const string HostedLoginHttpTestOrigins = "security.hosted_login_http_test_origins";

    /// <summary>
    /// Retired by ADR 0008: an http issuer no longer needs an explicit opt-in — http and https
    /// issuers are accepted equally, with issuer equality to the public base URL carrying the
    /// guarantee the switch used to gate.
    /// </summary>
    internal const string SecurityAllowNonHttpsIssuer = "security.allow_non_https_issuer";

    /// <summary>Every retired normalized key, compared case-sensitively like the definition table.</summary>
    internal static readonly IReadOnlySet<string> All =
        new HashSet<string>(StringComparer.Ordinal)
        {
            LokiAllowInsecureHttp,
            HostedLoginHttpTestOrigins,
            SecurityAllowNonHttpsIssuer
        };

    internal static bool IsRetired(string key) => All.Contains(key);
}
