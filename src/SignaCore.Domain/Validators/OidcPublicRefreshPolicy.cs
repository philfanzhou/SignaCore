using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Domain.Validators;

/// <summary>The current registration requirements for a Public Code refresh family.</summary>
public static class OidcPublicRefreshPolicy
{
    public static bool Allows(AppRegistrationEntity application) =>
        application.IsActive
        && application.ClientType == OidcClientType.Public
        && string.IsNullOrEmpty(application.AppSecretHash)
        && application.AllowAuthorizationCode
        && application.AudienceMode == AudienceMode.PerApplication
        && application.AllowRefreshToken
        && application.IdentitySessionMaxAgeSeconds is >= 1 and <= IdentityConstants.MaxIdentitySessionAgeSeconds
        && OidcScopeValidator.ParseCanonical(application.AllowedScopes)
            .Contains(OidcScopeValidator.OfflineAccess);
}
