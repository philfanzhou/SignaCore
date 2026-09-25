using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

/// <summary>
/// Persistence of management bearer sessions against a caller-supplied
/// <see cref="IdentityDbContext"/>. The lifecycle service passes its own short-lived,
/// non-retrying context per operation, so no request-scoped business context is ever saved by
/// these calls. Each write is a single statement.
/// </summary>
public interface IManagementBearerSessionRepository
{
    /// <summary>Inserts one session row and saves only that context.</summary>
    Task AddAsync(IdentityDbContext db, ManagementBearerSessionEntity session, CancellationToken cancellationToken);

    /// <summary>Reads one session by digest without tracking it.</summary>
    Task<ManagementBearerSessionEntity?> FindByDigestAsync(
        IdentityDbContext db,
        string tokenDigest,
        CancellationToken cancellationToken);

    /// <summary>
    /// Reads the username of <paramref name="accountId"/>'s password credential whose normalized
    /// username is <paramref name="usernameNormalized"/>, only when that account is active.
    /// </summary>
    Task<string?> FindActiveCredentialUsernameAsync(
        IdentityDbContext db,
        Guid accountId,
        string usernameNormalized,
        CancellationToken cancellationToken);

    /// <summary>
    /// Sets <c>revoked_at</c> to <paramref name="now"/> only for an unrevoked, unexpired session,
    /// so the first revocation instant is never overwritten. Returns the affected row count.
    /// </summary>
    Task<int> RevokeAsync(IdentityDbContext db, string tokenDigest, DateTimeOffset now, CancellationToken cancellationToken);

    /// <summary>
    /// Deletes at most one batch of sessions that expired at least the retention period before
    /// <paramref name="now"/>, oldest first. Returns the deleted row count.
    /// </summary>
    Task<int> DeleteExpiredAsync(IdentityDbContext db, DateTimeOffset now, CancellationToken cancellationToken);
}
