using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

/// <summary>
/// Persistence access to the <c>PS-04</c> identity session rows. Write operations join a
/// caller-owned ambient transaction when one exists and leave the only commit to the caller;
/// without one, each write runs as a whole inside <c>CreateExecutionStrategy()</c> because
/// PostgreSQL enables <c>EnableRetryOnFailure()</c> (<c>PS-22</c>).
/// </summary>
public interface IIdentitySessionRepository
{
    /// <summary>Stages a new session row; effective with the caller's unit of work.</summary>
    Task AddAsync(
        IdentitySessionEntity session,
        CancellationToken cancellationToken = default);

    /// <summary>Read-only ownership check used by creation; never writes.</summary>
    Task<bool> PasswordCredentialExistsForAccountAsync(
        Guid passwordCredentialId,
        Guid accountId,
        CancellationToken cancellationToken = default);

    /// <summary>Read-only row lookup by id; zero writes, no classification.</summary>
    Task<IdentitySessionEntity?> GetByIdAsync(
        Guid sessionId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Row lock for the canonical lock order ("lock the session, then write code/family/logout
    /// state"): PostgreSQL <c>SELECT ... FOR UPDATE</c>, SQLite a plain read inside the
    /// transaction (its file-level write lock serializes writers). Requires a caller-owned
    /// ambient transaction; the returned row is tracked so the caller's transaction can update
    /// it. Returns <c>null</c> for a missing row.
    /// </summary>
    /// <exception cref="InvalidOperationException">No ambient transaction exists.</exception>
    Task<IdentitySessionEntity?> LockByIdAsync(
        Guid sessionId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// The single conditional activity update: only a row that is unrevoked, inside both
    /// deadlines at <paramref name="now"/>, and stale (<c>last_seen_at &lt;=</c>
    /// <paramref name="staleBefore"/>) is written; the new idle deadline is capped at the row's
    /// own <c>absolute_expires_at</c>. Returns the affected row count (0 or 1) and never changes
    /// <c>absolute_expires_at</c>, <c>auth_time</c>, or the revocation columns.
    /// </summary>
    Task<int> TouchActivityAsync(
        Guid sessionId,
        DateTimeOffset now,
        DateTimeOffset staleBefore,
        DateTimeOffset idleExpiresAtCandidate,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// The conditional revocation update: only an unrevoked row is written, so the first
    /// revocation stays authoritative. Returns the affected row count (0 or 1).
    /// </summary>
    Task<int> MarkRevokedAsync(
        Guid sessionId,
        string revocationReason,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes rows past the retention cutoff as one transactional unit and returns the deleted
    /// count. A cancelled or failed run rolls the whole unit back; no reference is ever nulled to
    /// enable a delete.
    /// </summary>
    /// <summary>
    /// Lists the identity sessions of one account, newest authentication first, paged. The
    /// account index backs the filter; the rows carry no credential, cookie, or token value.
    /// </summary>
    Task<IReadOnlyList<IdentitySessionEntity>> ListByAccountAsync(
        Guid accountId,
        int take,
        int skip,
        CancellationToken cancellationToken = default);

    /// <summary>The total number of identity sessions of one account.</summary>
    Task<int> CountByAccountAsync(
        Guid accountId,
        CancellationToken cancellationToken = default);

    Task<int> RemoveExpiredBeforeAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default);
}
