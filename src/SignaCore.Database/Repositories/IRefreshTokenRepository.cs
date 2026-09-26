using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IRefreshTokenRepository
{
    Task<RefreshTokenEntity?> GetByTokenValueAsync(
        string tokenValue,
        CancellationToken cancellationToken = default);
    Task<bool> TryRevokeAsync(
        string tokenValue,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the token only when it was issued to <paramref name="appId"/>. RFC 7009 §2.1 requires
    /// the server to verify the token belongs to the client making the request, so that possession of
    /// another client's token is not by itself enough to revoke it. Interactive tokens must also
    /// be unconsumed and unexpired; only the named row changes, never its family or session
    /// (EV-14). Legacy token behavior is unchanged (EV-33).
    /// </summary>
    Task<bool> TryRevokeForAppAsync(
        string tokenValue,
        string appId,
        CancellationToken cancellationToken = default);
    Task<bool> TryRotateAsync(
        string tokenValue,
        RefreshTokenEntity replacement,
        CancellationToken cancellationToken = default);
    Task AddAsync(
        RefreshTokenEntity refreshToken,
        CancellationToken cancellationToken = default);

    Task RemoveRangeAsync(
        IEnumerable<RefreshTokenEntity> tokens,
        CancellationToken cancellationToken = default);
    Task<int> RemoveExpiredAndRevokedAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every unrevoked member of the interactive family whose root id is
    /// <paramref name="rootId"/> (<c>EV-24</c>): a conditional update over interactive rows only,
    /// so an already-revoked member keeps the first fact and a legacy singleton id matches nothing.
    /// Returns the number of members this call revoked.
    /// </summary>
    Task<int> RevokeFamilyAsync(
        Guid rootId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every unrevoked interactive refresh token bound to <paramref name="identitySessionId"/>
    /// (<c>EV-06</c>/<c>EV-15</c>): legacy rows have no session and are structurally out of reach.
    /// Returns the number of members this call revoked.
    /// </summary>
    Task<int> RevokeBySessionAsync(
        Guid identitySessionId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every unrevoked interactive refresh token of <paramref name="accountId"/>
    /// (<c>EV-08</c>): the account-disable transaction's family disposal. Interactive rows only —
    /// legacy rows have no identity session and are structurally out of reach (<c>PS-07</c>).
    /// Returns the number of members this call revoked.
    /// </summary>
    Task<int> RevokeByAccountAsync(
        Guid accountId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every unrevoked <em>legacy</em> refresh token of <paramref name="accountId"/>:
    /// rows with no identity session (<c>PS-07</c>), which <see cref="RevokeByAccountAsync"/> is
    /// structurally unable to reach. This is the self-service password-change transaction's
    /// legacy disposal, symmetric to but deliberately separate from the interactive-family
    /// primitive so the <c>EV-08</c> account-disable semantics stay unchanged. Returns the number
    /// of rows this call revoked.
    /// </summary>
    Task<int> RevokeLegacyByAccountAsync(
        Guid accountId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every unrevoked interactive refresh token issued to <paramref name="appId"/>
    /// (<c>EV-09</c>/<c>EV-11</c>): the application-deactivation and refresh-capability
    /// transactions' family disposal. Interactive rows only — legacy rows are structurally out
    /// of reach (<c>PS-07</c>). Returns the number of members this call revoked.
    /// </summary>
    Task<int> RevokeByApplicationAsync(
        string appId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes whole interactive families that are past every member's usable deadline and that no
    /// retained authorization code links to — children before roots, because the restrictive
    /// self-reference makes a single-statement whole-family delete provider-asymmetric. Returns
    /// the deleted member count.
    /// </summary>
    Task<int> RemoveInteractiveFamiliesAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Locks one refresh-token row for a caller-owned transaction following the canonical
    /// session-root-member order (<c>Persistence.md</c>): PostgreSQL takes an explicit
    /// <c>FOR UPDATE</c> row lock, SQLite relies on its writer serialization. Requires an active
    /// ambient transaction; returns the row, or <c>null</c> when missing.
    /// </summary>
    /// <exception cref="InvalidOperationException">No ambient transaction exists.</exception>
    Task<RefreshTokenEntity?> LockByIdAsync(
        Guid id,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads one refresh-token row without locking; returns <c>null</c> when missing.
    /// </summary>
    Task<RefreshTokenEntity?> GetByIdAsync(
        Guid id,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// The single conditional consumption write of the interactive rotation (<c>EV-29</c>): sets
    /// <c>consumed_at</c> only on an interactive row that is neither revoked nor already
    /// consumed, so exactly one concurrent rotation of the same member succeeds. Returns whether
    /// this call performed the consumption.
    /// </summary>
    Task<bool> TryConsumeInteractiveAsync(
        Guid memberId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every live — unconsumed and unrevoked — interactive member of
    /// <paramref name="familyId"/> that is a descendant of <paramref name="memberId"/>
    /// (<c>EV-31</c>): the walk follows the parent chain down through already-consumed or
    /// revoked links, and each live member is revoked by a conditional update that keeps the
    /// first fact authoritative. Returns the number of members revoked.
    /// </summary>
    Task<int> RevokeLiveDescendantsAsync(
        Guid familyId,
        Guid memberId,
        CancellationToken cancellationToken = default);
}
