using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Models;
using SignaCore.Domain.Validators;

namespace SignaCore.Host.Services;

/// <summary>
/// Rechecks a validated authorization request at the point a code is issued. PostgreSQL locks
/// the application and matching redirect row until the issuance commits; a policy update or URI
/// removal therefore cannot commit between this check and the new code. SQLite serializes writes
/// at the database level and fails a stale read transaction closed on a competing write.
/// </summary>
internal static class OidcCurrentAuthorizationPolicy
{
    public static async Task<bool> AllowsAsync(
        IdentityDbContext context,
        OidcAuthorizationValidationResult.Accepted accepted,
        CancellationToken cancellationToken, OidcRedirectUriPolicy? uriPolicy = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (context.Database.CurrentTransaction is null)
        {
            throw new InvalidOperationException("Authorization policy recheck requires a transaction.");
        }

        if (!(uriPolicy ?? OidcRedirectUriPolicy.Default).Allows(accepted.RegisteredRedirectUri)) return false;

        var sqlite = string.Equals(context.Database.ProviderName,
            "Microsoft.EntityFrameworkCore.Sqlite", StringComparison.Ordinal);
        AppRegistrationEntity? application;
        if (sqlite)
        {
            application = await context.AppRegistrations.AsNoTracking()
                .SingleOrDefaultAsync(app => app.Id == accepted.ApplicationId, cancellationToken);
        }
        else
        {
            application = (await context.AppRegistrations.FromSqlInterpolated(
                    $"SELECT * FROM app_registrations WHERE id = {accepted.ApplicationId} FOR UPDATE")
                .AsNoTracking().ToListAsync(cancellationToken)).SingleOrDefault();
        }

        if (application is null
            || !application.IsActive
            || !application.AllowAuthorizationCode
            || application.AudienceMode != AudienceMode.PerApplication
            || !string.Equals(application.AppId, accepted.ClientId, StringComparison.Ordinal)
            || (application.ClientType == OidcClientType.Public
                ? !string.IsNullOrEmpty(application.AppSecretHash)
                : application.ClientType != OidcClientType.Confidential)
            || !OidcScopeValidator.TryValidateRequested(
                accepted.CanonicalScope,
                OidcScopeValidator.ParseCanonical(application.AllowedScopes),
                application.ClientType == OidcClientType.Public
                    ? OidcPublicRefreshPolicy.Allows(application)
                    : application.AllowRefreshToken,
                out var canonicalScope)
            || !string.Equals(canonicalScope, accepted.CanonicalScope, StringComparison.Ordinal))
        {
            return false;
        }

        IReadOnlyList<AppRedirectUriEntity> redirects = sqlite
            ? await context.AppRedirectUris.AsNoTracking()
                .Where(uri => uri.AppRegistrationId == accepted.ApplicationId
                    && uri.Kind == RedirectUriKind.Redirect)
                .ToListAsync(cancellationToken)
            : await context.AppRedirectUris.FromSqlInterpolated(
                    $"SELECT * FROM app_redirect_uris WHERE app_registration_id = {accepted.ApplicationId} AND kind = {(int)RedirectUriKind.Redirect} FOR UPDATE")
                .AsNoTracking().ToListAsync(cancellationToken);

        return redirects.Any(uri => string.Equals(uri.CanonicalUri,
            accepted.RegisteredRedirectUri, StringComparison.Ordinal));
    }
}
