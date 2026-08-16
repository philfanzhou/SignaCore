namespace SignaCore.Host;

/// <summary>
/// The public discovery routes.
/// <para>
/// RFC 7517 defines the JWKS <i>document</i> but no path for it: a conforming client is expected to
/// read <c>jwks_uri</c> out of the discovery metadata. In practice the key set is fetched by hand far
/// more often than by a discovery client — an operator checking which keys are live, a health probe, a
/// validator configured from a copied snippet — and every one of those reaches for
/// <c>/.well-known/jwks.json</c>, the shape popularised by Auth0 and by the <c>*.json</c> convention of
/// the well-known registry. A 404 there is indistinguishable from "this service publishes no keys",
/// which is the worst possible answer for a key-distribution endpoint.
/// </para>
/// <para>
/// So both paths serve the identical document. <see cref="Jwks"/> stays canonical and is the only one
/// discovery advertises; <see cref="JwksJson"/> is an alias, not a second contract, and must never
/// diverge from it.
/// </para>
/// </summary>
public static class WellKnownEndpoints
{
    /// <summary>Canonical JWKS route. This is what <c>jwks_uri</c> points at.</summary>
    public const string Jwks = "/.well-known/jwks";

    /// <summary>De-facto alias for <see cref="Jwks"/>, serving the same document.</summary>
    public const string JwksJson = "/.well-known/jwks.json";

    /// <summary>
    /// True for either JWKS route. Used by the pipeline stages that treat the key set as
    /// infrastructure — rate-limiting exemptions and the JWKS-specific limiter — so an alias request
    /// is never governed by different limits than the canonical one. The comparison is
    /// case-insensitive to match <see cref="Microsoft.AspNetCore.Http.PathString"/> and the routing
    /// table, which both resolve these paths regardless of casing.
    /// </summary>
    public static bool IsJwks(string path) =>
        string.Equals(path, Jwks, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(path, JwksJson, StringComparison.OrdinalIgnoreCase);
}
