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

    Task<int> RemoveExpiredBeforeAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default);
}
