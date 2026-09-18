using SignaCore.Database;

namespace SignaCore.Host;

/// <summary>
/// Builds the metadata served at <c>/.well-known/openid-configuration</c> and
/// <c>/.well-known/oauth-authorization-server</c> (RFC 8414).
/// <para>
/// The document describes exactly what this service implements and nothing else. The interactive
/// Authorization Code flow core is delivered and advertised (<c>AC-07</c>): the authorization
/// endpoint, <c>code</c>, <c>authorization_code</c> with mandatory S256 PKCE, and the ID token
/// signed RS256. There is still no UserInfo endpoint (<c>#55</c>) and no interactive refresh
/// family (<c>#98</c>), so <c>userinfo_endpoint</c> is absent and <c>offline_access</c> is not in
/// <see cref="ScopesSupported"/> (<c>AC-12</c> advertises it only once rotation works end to end).
/// Advertising a capability that does not exist is worse than omitting it — a conforming client
/// would build a request it can never complete.
/// </para>
/// <para>
/// Conformance status and the deliberate gaps are documented in
/// docs/overview/StandardsConformance.md.
/// </para>
/// </summary>
public sealed record DiscoveryDocument(
    string Issuer,
    string JwksUri,
    string AuthorizationEndpoint,
    string TokenEndpoint,
    string RevocationEndpoint,
    IReadOnlyList<string> GrantTypesSupported,
    IReadOnlyList<string> ResponseTypesSupported,
    IReadOnlyList<string> CodeChallengeMethodsSupported,
    IReadOnlyList<string> ScopesSupported,
    IReadOnlyList<string> SubjectTypesSupported,
    IReadOnlyList<string> IdTokenSigningAlgValuesSupported,
    IReadOnlyList<string> TokenEndpointAuthMethodsSupported,
    IReadOnlyList<string> RevocationEndpointAuthMethodsSupported,
    IReadOnlyList<string> ClaimsSupported)
{
    /// <summary>The wire name of the interactive Authorization Code grant (<c>AC-06</c>/<c>AC-07</c>).</summary>
    public const string AuthorizationCodeGrantType = "authorization_code";

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
            AuthorizationEndpoint: $"{origin}/oauth2/authorize",
            TokenEndpoint: $"{origin}/oauth2/token",
            RevocationEndpoint: $"{origin}/oauth2/revoke",
            // The direct credential grants are the honest set, taken from the registered validators
            // rather than a literal, so a new grant cannot ship without appearing here. Extension
            // grants are advertised under the absolute URIs RFC 6749 §4.5 requires, which is what
            // /oauth2/token accepts. The interactive authorization_code grant is merged in
            // explicitly (AC-07): its redemption branch is deliberately not a registered validator,
            // so it must never appear here through validator registration.
            GrantTypesSupported: grantTypes
                .Select(OAuthGrantTypes.ToWire)
                .Append(AuthorizationCodeGrantType)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(item => item, StringComparer.Ordinal)
                .ToArray(),
            // The delivered interactive core: the authorization endpoint answers response_type=code.
            ResponseTypesSupported: ["code"],
            // RFC 7636: S256 is the only accepted code challenge method; plain is rejected.
            CodeChallengeMethodsSupported: ["S256"],
            // Only scopes a client can actually complete today. offline_access is deliberately
            // absent until the interactive refresh family works end to end (AC-12).
            ScopesSupported: ["openid", "profile"],
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
        ["authorization_endpoint"] = AuthorizationEndpoint,
        ["token_endpoint"] = TokenEndpoint,
        ["revocation_endpoint"] = RevocationEndpoint,
        ["grant_types_supported"] = GrantTypesSupported,
        ["response_types_supported"] = ResponseTypesSupported,
        ["code_challenge_methods_supported"] = CodeChallengeMethodsSupported,
        ["scopes_supported"] = ScopesSupported,
        ["subject_types_supported"] = SubjectTypesSupported,
        ["id_token_signing_alg_values_supported"] = IdTokenSigningAlgValuesSupported,
        ["token_endpoint_auth_methods_supported"] = TokenEndpointAuthMethodsSupported,
        ["revocation_endpoint_auth_methods_supported"] = RevocationEndpointAuthMethodsSupported,
        ["claims_supported"] = ClaimsSupported
    };
}
