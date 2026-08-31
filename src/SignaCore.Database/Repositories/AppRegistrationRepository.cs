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

    public async Task<AppRegistrationEntity?> GetByAppIdAsync(string appId)
    {
        var normalizedAppId = IdentityValueNormalizer.Normalize(appId);
        return await _dbContext.AppRegistrations
            .FirstOrDefaultAsync(a => a.AppIdNormalized == normalizedAppId);
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

    public Task AddAsync(AppRegistrationEntity app)
    {
        _dbContext.AppRegistrations.Add(app);
        return Task.CompletedTask;
    }

    public Task AddRedirectUrisAsync(IEnumerable<AppRedirectUriEntity> registrations)
    {
        _dbContext.AppRedirectUris.AddRange(registrations);
        return Task.CompletedTask;
    }

    public Task RemoveRedirectUrisAsync(IEnumerable<AppRedirectUriEntity> registrations)
    {
        _dbContext.AppRedirectUris.RemoveRange(registrations);
        return Task.CompletedTask;
    }

    public Task DeleteAsync(AppRegistrationEntity app)
    {
        _dbContext.AppRegistrations.Remove(app);
        return Task.CompletedTask;
    }

    public async Task<int> DeactivateExpiredCallbacksAsync(DateTimeOffset utcNow)
    {
        return await _dbContext.AppRegistrations
            .Where(a => a.CallbackExpiresAt.HasValue && a.IsActive && a.CallbackExpiresAt! < utcNow)
            .ExecuteUpdateAsync(setters => setters.SetProperty(a => a.IsActive, false));
    }
}
