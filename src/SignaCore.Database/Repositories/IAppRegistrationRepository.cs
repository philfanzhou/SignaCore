using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IAppRegistrationRepository
{
    Task<AppRegistrationEntity?> GetByAppIdAsync(string appId);
    Task<AppRegistrationEntity?> GetByAppIdWithOidcConfigurationAsync(
        string appId,
        CancellationToken cancellationToken);
    Task AddAsync(AppRegistrationEntity app);

    /// <summary>Stages new browser URI registrations for an already-persisted application.</summary>
    Task AddRedirectUrisAsync(IEnumerable<AppRedirectUriEntity> registrations);

    /// <summary>
    /// Stages the deletion of browser URI registrations the caller has already detached from their
    /// application. The change becomes effective with the caller's unit of work.
    /// </summary>
    Task RemoveRedirectUrisAsync(IEnumerable<AppRedirectUriEntity> registrations);
    Task DeleteAsync(AppRegistrationEntity app);
    Task<int> DeactivateExpiredCallbacksAsync(DateTimeOffset utcNow);
}
