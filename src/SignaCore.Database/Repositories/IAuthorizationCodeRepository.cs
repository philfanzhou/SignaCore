using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IAuthorizationCodeRepository
{
    Task AddAsync(
        AuthorizationCodeEntity code,
        CancellationToken cancellationToken = default);

    Task<AuthorizationCodeEntity?> GetByCodeDigestAsync(
        string codeDigest,
        CancellationToken cancellationToken = default);

    Task<AuthorizationCodeEntity?> LockByIdAsync(
        Guid codeId,
        CancellationToken cancellationToken = default);

    Task<bool> TryConsumeAsync(
        Guid codeId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Points the consumed code row at its refresh family root (<c>EV-21</c>): a single
    /// conditional update of the still-unlinked row, so a code can never be re-pointed at a
    /// second family. Returns the number of rows linked (0 or 1).
    /// </summary>
    Task<int> LinkRefreshFamilyAsync(
        Guid codeId,
        Guid rootId,
        CancellationToken cancellationToken = default);

    Task<int> RemoveExpiredBeforeAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default);
}
