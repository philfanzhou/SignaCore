using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IAppRegistrationRepository
{
    Task<AppRegistrationEntity?> GetByAppIdAsync(string appId);
    Task<AppRegistrationEntity?> GetByAppIdWithOidcConfigurationAsync(
        string appId,
        CancellationToken cancellationToken);
    Task AddAsync(AppRegistrationEntity app);
    Task DeleteAsync(AppRegistrationEntity app);
    Task<int> DeactivateExpiredCallbacksAsync(DateTimeOffset utcNow);
}
