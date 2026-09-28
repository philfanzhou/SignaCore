using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public class AppRegistrationRepository : IAppRegistrationRepository
{
    private const string PostgreSqlProviderName = "Npgsql.EntityFrameworkCore.PostgreSQL";

    private readonly IdentityDbContext _dbContext;

    public AppRegistrationRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<AppRegistrationEntity?> GetByAppIdAsync(
        string appId,
        CancellationToken cancellationToken = default)
    {
        var normalizedAppId = IdentityValueNormalizer.Normalize(appId);
        return await _dbContext.AppRegistrations
            .FirstOrDefaultAsync(
                a => a.AppIdNormalized == normalizedAppId,
                cancellationToken);
    }

    public async Task<AppRegistrationEntity?> GetByAppIdWithOidcConfigurationAsync(
        string appId,
        CancellationToken cancellationToken)
    {
        var normalizedAppId = IdentityValueNormalizer.Normalize(appId);
        return await _dbContext.AppRegistrations
            .Include(app => app.RedirectUris)
            .Include(app => app.AllowedOrigins)
            .FirstOrDefaultAsync(
                app => app.AppIdNormalized == normalizedAppId,
                cancellationToken);
    }

    public async Task LockByAppIdAsync(string appId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Only PostgreSQL has row locks to take; SQLite serializes writers at the database level.
        if (!string.Equals(
                _dbContext.Database.ProviderName,
                PostgreSqlProviderName,
                StringComparison.Ordinal))
        {
            return;
        }

        if (_dbContext.Database.CurrentTransaction is null)
        {
            throw new InvalidOperationException(
                "Locking an application requires a caller-owned ambient transaction; none is active.");
        }

        var normalizedAppId = IdentityValueNormalizer.Normalize(appId);
        await _dbContext.AppRegistrations
            .FromSqlInterpolated(
                $"SELECT * FROM app_registrations WHERE app_id_normalized = {normalizedAppId} FOR UPDATE")
            .AsNoTracking()
            .ToListAsync(cancellationToken);
    }

    public async Task<AppRegistrationEntity?> ReadPolicyForFamilyWriteAsync(
        Guid applicationRowId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!string.Equals(
                _dbContext.Database.ProviderName,
                PostgreSqlProviderName,
                StringComparison.Ordinal))
        {
            return await _dbContext.AppRegistrations
                .AsNoTracking()
                .SingleOrDefaultAsync(app => app.Id == applicationRowId, cancellationToken);
        }

        if (_dbContext.Database.CurrentTransaction is null)
        {
            throw new InvalidOperationException(
                "Locking an application policy requires a caller-owned ambient transaction; none is active.");
        }

        // A shared row lock: family writers of one application do not serialize with each other,
        // only with the administrative FOR UPDATE that precedes the application's family revocation.
        return (await _dbContext.AppRegistrations
                .FromSqlInterpolated(
                    $"SELECT * FROM app_registrations WHERE id = {applicationRowId} FOR SHARE")
                .AsNoTracking()
                .ToListAsync(cancellationToken))
            .SingleOrDefault();
    }

    public Task AddAsync(
        AppRegistrationEntity app,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.AppRegistrations.Add(app);
        return Task.CompletedTask;
    }

    public Task AddRedirectUrisAsync(
        IEnumerable<AppRedirectUriEntity> registrations,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.AppRedirectUris.AddRange(registrations);
        return Task.CompletedTask;
    }

    public Task RemoveRedirectUrisAsync(
        IEnumerable<AppRedirectUriEntity> registrations,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.AppRedirectUris.RemoveRange(registrations);
        return Task.CompletedTask;
    }

    public Task ReplaceAllowedOriginsAsync(
        AppRegistrationEntity app,
        IEnumerable<AppAllowedOriginEntity> registrations,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.AppAllowedOrigins.RemoveRange(app.AllowedOrigins);
        var replacements = registrations.ToList();
        _dbContext.AppAllowedOrigins.AddRange(replacements);
        app.AllowedOrigins = replacements;
        return Task.CompletedTask;
    }

    public Task DeleteAsync(
        AppRegistrationEntity app,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.AppRegistrations.Remove(app);
        return Task.CompletedTask;
    }

    public async Task<int> DeactivateExpiredCallbacksAsync(
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext.AppRegistrations
            .Where(a => a.CallbackExpiresAt.HasValue && a.IsActive && a.CallbackExpiresAt! < utcNow)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(a => a.IsActive, false),
                cancellationToken);
    }
}
