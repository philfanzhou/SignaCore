using SignaCore.Database.Entity;

namespace SignaCore.Domain.Models;

/// <summary>An interactive OIDC client configuration after all cross-field checks succeed.</summary>
public sealed record ValidatedOidcClientConfiguration(
    OidcClientType ClientType,
    bool AllowAuthorizationCode,
    string AllowedScopes,
    bool AllowRefreshToken,
    int? IdentitySessionMaxAgeSeconds,
    IReadOnlyList<OidcRedirectUri> RedirectUris,
    IReadOnlyList<OidcRedirectUri> PostLogoutRedirectUris);
