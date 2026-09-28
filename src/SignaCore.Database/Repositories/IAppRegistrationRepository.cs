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

    /// <summary>
    /// Serializes an administrative change of one application with the transactions that decide
    /// on its current policy. PostgreSQL takes a <c>FOR UPDATE</c> lock on the application row
    /// that is held until the caller's transaction ends and requires that transaction; SQLite
    /// relies on its single-writer serialization and takes no lock here. Callers lock
    /// before any read or write of the application's dependent state, so the lock order stays
    /// application row first, then its redirect URIs and refresh families.
    /// </summary>
    Task LockByAppIdAsync(string appId, CancellationToken cancellationToken);

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
    Task ReplaceAllowedOriginsAsync(
        AppRegistrationEntity app,
        IEnumerable<AppAllowedOriginEntity> registrations,
        CancellationToken cancellationToken = default);
    Task DeleteAsync(AppRegistrationEntity app, CancellationToken cancellationToken = default);
    Task<int> DeactivateExpiredCallbacksAsync(
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default);
}
