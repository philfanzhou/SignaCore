using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Validators;

namespace SignaCore.Host.Services;

internal static class OidcCurrentRedirectTrust
{
    internal static async Task<bool> AllowsAsync(IdentityDbContext context, Guid applicationId,
        RedirectUriKind kind, string uri, OidcRedirectUriPolicy policy, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!policy.Allows(uri)) return false;
        var sqlite = context.Database.ProviderName == "Microsoft.EntityFrameworkCore.Sqlite";
        var inTransaction = context.Database.CurrentTransaction is not null;
        var applications = !sqlite && inTransaction
            ? context.AppRegistrations.FromSqlInterpolated($"SELECT * FROM app_registrations WHERE id = {applicationId} FOR SHARE")
            : context.AppRegistrations.Where(app => app.Id == applicationId);
        var application = (await applications.AsNoTracking().ToListAsync(cancellationToken)).SingleOrDefault();
        if (application is null || !application.IsActive) return false;
        var registrations = !sqlite && inTransaction
            ? context.AppRedirectUris.FromSqlInterpolated($"SELECT * FROM app_redirect_uris WHERE app_registration_id = {applicationId} AND kind = {(int)kind} FOR SHARE")
            : context.AppRedirectUris.Where(registration => registration.AppRegistrationId == applicationId && registration.Kind == kind);
        return (await registrations.AsNoTracking().ToListAsync(cancellationToken))
            .Any(registration => string.Equals(uri, registration.CanonicalUri, StringComparison.Ordinal));
    }
}
