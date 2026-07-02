using Microsoft.EntityFrameworkCore;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public class AppRegistrationRepository : IAppRegistrationRepository
{
    private readonly IdentityDbContext _dbContext;

    public AppRegistrationRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<AppRegistrationEntity?> GetByAppIdAsync(string appId)
    {
        return await _dbContext.AppRegistrations.FirstOrDefaultAsync(a => a.AppId == appId);
    }

    public Task AddAsync(AppRegistrationEntity app)
    {
        _dbContext.AppRegistrations.Add(app);
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
