using SignaCore.Database;

namespace SignaCore.Host;

/// <summary>
/// Builds the metadata served at <c>/.well-known/openid-configuration</c> and
/// <c>/.well-known/oauth-authorization-server</c> (RFC 8414).
/// <para>
/// The document describes exactly what this service implements and nothing else. SignaCore is not a
/// full OpenID Connect provider today: there is no authorization endpoint, no <c>id_token</c>, and no
/// UserInfo endpoint, so <see cref="ResponseTypesSupported"/> is empty and no endpoint is advertised
/// that a client cannot actually call. Advertising a capability that does not exist is worse than
/// omitting it — a conforming client would build a request it can never complete.
/// </para>
/// <para>
/// Conformance status and the deliberate gaps are documented in
/// docs/overview/StandardsConformance.md.
/// </para>
/// </summary>
public sealed record DiscoveryDocument(
    string Issuer,
    string JwksUri,
    string TokenEndpoint,
    string RevocationEndpoint,
    IReadOnlyList<string> GrantTypesSupported,
    IReadOnlyList<string> ResponseTypesSupported,
    IReadOnlyList<string> SubjectTypesSupported,
    IReadOnlyList<string> IdTokenSigningAlgValuesSupported,
    IReadOnlyList<string> TokenEndpointAuthMethodsSupported,
    IReadOnlyList<string> RevocationEndpointAuthMethodsSupported,
    IReadOnlyList<string> ClaimsSupported)
{
    public static DiscoveryDocument Create(
        string issuer,
        string baseUrl,
        IEnumerable<string> grantTypes)
    {
        var origin = baseUrl.TrimEnd('/');
        return new DiscoveryDocument(
            Issuer: issuer,
            JwksUri: $"{origin}/.well-known/jwks",
            // Discovery advertises the standards-shaped endpoints. The legacy /api/auth/token and
            // /api/auth/revoke routes stay available for existing consumers, but they are not what a
            // client that reads this document should call: their wire format is not RFC 6749.
            TokenEndpoint: $"{origin}/oauth2/token",
            RevocationEndpoint: $"{origin}/oauth2/revoke",
            // The honest set, taken from the registered validators rather than a literal, so a new
            // grant cannot ship without appearing here. Extension grants are advertised under the
            // absolute URIs RFC 6749 §4.5 requires, which is what /oauth2/token accepts.
            GrantTypesSupported: grantTypes
                .Select(OAuthGrantTypes.ToWire)
                .OrderBy(item => item, StringComparer.Ordinal)
                .ToArray(),
            // No authorization endpoint exists, so no response type can be requested.
            ResponseTypesSupported: [],
            SubjectTypesSupported: ["public"],
            IdTokenSigningAlgValuesSupported: ["RS256"],
            TokenEndpointAuthMethodsSupported: ["client_secret_basic", "client_secret_post"],
            RevocationEndpointAuthMethodsSupported: ["client_secret_basic", "client_secret_post"],
            // Must match the claim names that actually appear in issued tokens. Constants, not
            // literals — these once said sub/name/role while tokens carried ClaimTypes.* long URIs.
            ClaimsSupported:
            [
                IdentityConstants.ClaimSubject,
                IdentityConstants.ClaimName,
                IdentityConstants.ClaimRole,
                IdentityConstants.ClaimAuthMethod,
                IdentityConstants.ClaimNickname,
                IdentityConstants.ClaimClientId
            ]);
    }

    /// <summary>
    /// Serializes with the snake_case names the specifications require. The property names are written
    /// out rather than derived from a naming policy so a rename in C# cannot silently change the wire
    /// contract that downstream discovery clients parse.
    /// </summary>
    public IDictionary<string, object> ToMetadata() => new Dictionary<string, object>
    {
        ["issuer"] = Issuer,
        ["jwks_uri"] = JwksUri,
        ["token_endpoint"] = TokenEndpoint,
        ["revocation_endpoint"] = RevocationEndpoint,
        ["grant_types_supported"] = GrantTypesSupported,
        ["response_types_supported"] = ResponseTypesSupported,
        ["subject_types_supported"] = SubjectTypesSupported,
        ["id_token_signing_alg_values_supported"] = IdTokenSigningAlgValuesSupported,
        ["token_endpoint_auth_methods_supported"] = TokenEndpointAuthMethodsSupported,
        ["revocation_endpoint_auth_methods_supported"] = RevocationEndpointAuthMethodsSupported,
        ["claims_supported"] = ClaimsSupported
    };
}
