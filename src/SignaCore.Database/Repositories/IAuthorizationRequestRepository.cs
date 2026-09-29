using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IAuthorizationRequestRepository
{
    /// <summary>
    /// Stages a continuation row, forcing <see cref="AuthorizationRequestEntity.HandleDigest"/> into
    /// the versioned digest representation so a plaintext handle can never reach the database. The
    /// caller owns <c>SaveChanges</c> and any surrounding transaction.
    /// </summary>
    Task AddAsync(
        AuthorizationRequestEntity request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Looks a row up by its exact digest and returns it only while it is unconsumed and unexpired
    /// at <paramref name="now"/>. Read-only: a missing, expired, or consumed digest produces
    /// <c>null</c> with no write, no invented state, and no replay record (<c>EV-03</c>,
    /// <c>SC-18</c>).
    /// </summary>
    Task<AuthorizationRequestEntity?> GetActiveByHandleDigestAsync(
        string handleDigest,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically consumes the row matching <paramref name="handleDigest"/> with a conditional
    /// update guarded by <c>consumed_at IS NULL AND expires_at &gt; now</c>, using the single
    /// captured instant <paramref name="now"/> for both the comparison and the written value
    /// (<c>PS-22</c>). Concurrent consumers of the same handle: at most one returns <c>true</c>.
    /// <para>
    /// Inside an ambient transaction the update joins it and the caller owns the commit, which is
    /// how <c>EV-01</c> commits consumption together with session and code creation; a rollback
    /// leaves the row unconsumed (<c>EV-18</c>). Standalone, the update runs in its own transaction
    /// inside <c>Database.CreateExecutionStrategy()</c>.
    /// </para>
    /// </summary>
    Task<bool> TryConsumeAsync(
        string handleDigest,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Takes one browser SMS send slot (<c>PS-03</c>) with a single auto-committed conditional
    /// update: <c>sms_code_send_count + 1</c> where the digest matches, the row is unconsumed and
    /// unexpired at <paramref name="now"/>, and the count is below <paramref name="maximum"/>.
    /// Returns <c>true</c> exactly when a row changed. The update never joins a caller
    /// transaction — an ambient transaction is a programming error — and a taken slot is never
    /// refunded, so a caller that fails or is cancelled afterwards keeps the slot spent.
    /// </summary>
    Task<bool> TryTakeSmsCodeSendSlotAsync(
        string handleDigest,
        DateTimeOffset now,
        int maximum,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes rows whose <c>expires_at</c> is at or before <paramref name="cutoff"/> (now minus the
    /// retention window) as one transactional unit: cancellation or failure before the commit rolls
    /// the whole deletion back. No row is ever kept alive by nulling a reference, and nothing
    /// references this table, so no cascade exists.
    /// </summary>
    Task<int> RemoveExpiredBeforeAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default);
}
