using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Models;

namespace SignaCore.Domain.Validators;

public static class OidcClientConfigurationValidator
{
    public static ValidatedOidcClientConfiguration Validate(
        OidcClientType clientType,
        bool allowAuthorizationCode,
        IEnumerable<string> allowedScopes,
        bool allowRefreshToken,
        int? identitySessionMaxAgeSeconds,
        AudienceMode audienceMode,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        bool isDevelopment)
    {
        if (!Enum.IsDefined(clientType))
        {
            throw new OidcClientConfigurationException(
                "The interactive client type is unsupported.");
        }

        if (identitySessionMaxAgeSeconds is <= 0
            or > IdentityConstants.MaxIdentitySessionAgeSeconds)
        {
            throw new OidcClientConfigurationException(
                "The identity-session maximum age must be between 1 and 43200 seconds.");
        }

        var canonicalScopes = OidcScopeValidator.ValidateAndCanonicalize(
            allowedScopes,
            allowRefreshToken);
        var canonicalRedirectUris = OidcRedirectUriValidator.ValidateAndCanonicalize(
            redirectUris,
            isDevelopment);
        var canonicalPostLogoutRedirectUris = OidcRedirectUriValidator.ValidateAndCanonicalize(
            postLogoutRedirectUris,
            isDevelopment);

        if (clientType == OidcClientType.Public
            && (allowAuthorizationCode || allowRefreshToken))
        {
            throw new OidcClientConfigurationException(
                "Public clients are reserved and must remain fail closed.");
        }

        if (allowAuthorizationCode)
        {
            if (audienceMode != AudienceMode.PerApplication)
            {
                throw new OidcClientConfigurationException(
                    "Authorization Code flow requires a per-application audience.");
            }

            if (canonicalRedirectUris.Count == 0)
            {
                throw new OidcClientConfigurationException(
                    "Authorization Code flow requires at least one redirect URI.");
            }
        }

        return new ValidatedOidcClientConfiguration(
            clientType,
            allowAuthorizationCode,
            canonicalScopes,
            allowRefreshToken,
            identitySessionMaxAgeSeconds,
            canonicalRedirectUris,
            canonicalPostLogoutRedirectUris);
    }
}
