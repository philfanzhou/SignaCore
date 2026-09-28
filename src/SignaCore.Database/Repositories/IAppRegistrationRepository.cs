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

    /// <summary>
    /// Reads one application's current policy for a transaction that writes an interactive refresh
    /// family member of that application. PostgreSQL takes a <c>FOR SHARE</c> lock on the row, held
    /// until the caller's transaction ends and requiring that transaction: it conflicts with the
    /// administrative <see cref="LockByAppIdAsync"/> but not with other family writers, so a change
    /// that locked first commits before this read returns, and a change that locks later waits for
    /// the writer's commit and then revokes what it wrote. SQLite relies on its single-writer
    /// serialization and reads the row within the caller's transaction.
    /// </summary>
    Task<AppRegistrationEntity?> ReadPolicyForFamilyWriteAsync(
        Guid applicationRowId,
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
    Task ReplaceAllowedOriginsAsync(
        AppRegistrationEntity app,
        IEnumerable<AppAllowedOriginEntity> registrations,
        CancellationToken cancellationToken = default);
    Task DeleteAsync(AppRegistrationEntity app, CancellationToken cancellationToken = default);
    Task<int> DeactivateExpiredCallbacksAsync(
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default);
}
