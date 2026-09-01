using SignaCore.Database.Entity;
using SignaCore.Domain.Models;
using SignaCore.Domain.Validators;

namespace SignaCore.Domain.Services;

/// <summary>
/// Validates a complete interactive OIDC configuration and writes it onto an application row.
/// <para>
/// The administration API and the <c>bootstrap-apps.json</c> pre-seed both go through here. Neither
/// carries its own membership, canonicalisation, or cross-field rules, so a configuration that one
/// path accepts cannot be rejected by the other.
/// </para>
/// <para>
/// Nothing is written until every check has passed. The caller owns the transaction: this method
/// only stages entity changes, so a rejection leaves the tracked graph untouched and a single
/// <c>SaveChanges</c> makes the accepted configuration effective as one unit.
/// </para>
/// </summary>
public static class OidcClientConfigurationApplier
{
    /// <summary>
    /// Applies <paramref name="input"/> to <paramref name="application"/> and reports which URI
    /// registrations the caller has to stage.
    /// </summary>
    /// <exception cref="OidcClientConfigurationException">
    /// The configuration is not acceptable. The application row is unchanged.
    /// </exception>
    public static OidcClientConfigurationChange Apply(
        AppRegistrationEntity application,
        OidcClientConfigurationInput input,
        bool isDevelopment)
    {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentNullException.ThrowIfNull(input);

        var clientType = ParseClientType(input.ClientType);
        var audienceMode = input.AudienceMode is null
            ? application.AudienceMode
            : ParseAudienceMode(input.AudienceMode);

        var validated = OidcClientConfigurationValidator.Validate(
            clientType,
            input.AllowAuthorizationCode,
            input.AllowedScopes ?? [OidcScopeValidator.OpenId],
            input.AllowRefreshToken,
            input.IdentitySessionMaxAgeSeconds,
            audienceMode,
            input.RedirectUris ?? [],
            input.PostLogoutRedirectUris ?? [],
            isDevelopment);

        application.ClientType = validated.ClientType;
        application.AllowAuthorizationCode = validated.AllowAuthorizationCode;
        application.AllowedScopes = validated.AllowedScopes;
        application.AllowRefreshToken = validated.AllowRefreshToken;
        application.IdentitySessionMaxAgeSeconds = validated.IdentitySessionMaxAgeSeconds;
        application.AudienceMode = audienceMode;

        var (added, removed) = Reconcile(application, validated);
        return new OidcClientConfigurationChange(validated, added, removed);
    }

    /// <summary>
    /// Brings the stored registrations in line with the validated sets. Rows whose kind and
    /// canonical value survive are left alone rather than recreated, so an administrator's stable
    /// registration identifiers do not change every time an unrelated policy field is edited.
    /// </summary>
    private static (IReadOnlyList<AppRedirectUriEntity> Added, IReadOnlyList<AppRedirectUriEntity> Removed) Reconcile(
        AppRegistrationEntity application,
        ValidatedOidcClientConfiguration validated)
    {
        var desired = new List<(RedirectUriKind Kind, string Uri)>();
        desired.AddRange(validated.RedirectUris
            .Select(uri => (RedirectUriKind.Redirect, uri.Value)));
        desired.AddRange(validated.PostLogoutRedirectUris
            .Select(uri => (RedirectUriKind.PostLogout, uri.Value)));

        var removed = application.RedirectUris
            .Where(existing => !desired.Any(item =>
                item.Kind == existing.Kind
                && string.Equals(item.Uri, existing.CanonicalUri, StringComparison.Ordinal)))
            .ToList();

        foreach (var registration in removed)
        {
            application.RedirectUris.Remove(registration);
        }

        var added = new List<AppRedirectUriEntity>();
        foreach (var (kind, uri) in desired)
        {
            var alreadyRegistered = application.RedirectUris.Any(existing =>
                existing.Kind == kind
                && string.Equals(existing.CanonicalUri, uri, StringComparison.Ordinal));
            if (alreadyRegistered)
            {
                continue;
            }

            var registration = new AppRedirectUriEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = application.Id,
                Kind = kind,
                CanonicalUri = uri
            };
            application.RedirectUris.Add(registration);
            added.Add(registration);
        }

        return (added, removed);
    }

    private static OidcClientType ParseClientType(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return OidcClientType.Confidential;
        }

        if (!Enum.TryParse<OidcClientType>(value, ignoreCase: true, out var clientType)
            || !Enum.IsDefined(clientType))
        {
            throw new OidcClientConfigurationException(
                "The interactive client type is unsupported.");
        }

        return clientType;
    }

    private static AudienceMode ParseAudienceMode(string value)
    {
        if (!Enum.TryParse<AudienceMode>(value, ignoreCase: true, out var audienceMode)
            || !Enum.IsDefined(audienceMode))
        {
            throw new OidcClientConfigurationException(
                "The audience mode is unsupported.");
        }

        return audienceMode;
    }
}
