using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IAppRegistrationRepository
{
    Task<AppRegistrationEntity?> GetByAppIdAsync(
        string appId,
        CancellationToken cancellationToken = default);
    Task<AppRegistrationEntity?> GetByAppIdWithOidcConfigurationAsync(
        string appId,
        CancellationToken cancellationToken);
    Task AddAsync(AppRegistrationEntity app, CancellationToken cancellationToken = default);

    /// <summary>Stages new browser URI registrations for an already-persisted application.</summary>
    Task AddRedirectUrisAsync(
        IEnumerable<AppRedirectUriEntity> registrations,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Stages the deletion of browser URI registrations the caller has already detached from their
    /// application. The change becomes effective with the caller's unit of work.
    /// </summary>
    Task RemoveRedirectUrisAsync(
        IEnumerable<AppRedirectUriEntity> registrations,
        CancellationToken cancellationToken = default);
    Task DeleteAsync(AppRegistrationEntity app, CancellationToken cancellationToken = default);
    Task<int> DeactivateExpiredCallbacksAsync(
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default);
}
