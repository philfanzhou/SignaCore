using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IAppRegistrationRepository
{
    Task<AppRegistrationEntity?> GetByAppIdAsync(string appId);
    Task AddAsync(AppRegistrationEntity app);
    Task DeleteAsync(AppRegistrationEntity app);
    Task<int> DeactivateExpiredCallbacksAsync(DateTimeOffset utcNow);
}
