using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public class AppRegistrationRepository : IAppRegistrationRepository
{
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
            .FirstOrDefaultAsync(
                app => app.AppIdNormalized == normalizedAppId,
                cancellationToken);
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
