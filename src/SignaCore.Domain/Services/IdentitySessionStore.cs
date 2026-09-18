using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;

namespace SignaCore.Domain.Services;

/// <summary>
/// The unique state classification of <see cref="IIdentitySessionStore.GetAsync"/>, decided under
/// one captured UTC instant: a missing row invents no state (<c>SC-18</c>), an explicit
/// revocation outranks every expiry (<c>EV-04</c>: expiry is a time result, never a revocation),
/// and an expiry boundary is inclusive — <c>now == expiry</c> is already expired. A complete
/// "live session" decision additionally requires the current account and application policy and
/// belongs to the per-request enforcement slice, not to this classification.
/// </summary>
public enum IdentitySessionState
{
    Missing,
    Revoked,
    AbsoluteExpired,
    IdleExpired,
    Active
}

/// <summary>
/// The classification plus the row it was decided on; <see cref="Session"/> is <c>null</c> only
/// for <see cref="IdentitySessionState.Missing"/>.
/// </summary>
public sealed record IdentitySessionLookup(
    IdentitySessionState State,
    IdentitySessionEntity? Session);

/// <summary>The unique outcome of one activity update attempt.</summary>
public enum IdentitySessionActivityResult
{
    /// <summary>The stale row was written: <c>last_seen_at = now</c>, idle slid and capped.</summary>
    Touched,

    /// <summary>The row is usable but its activity is younger than the write threshold; zero writes.</summary>
    NotStale,

    /// <summary>The row is missing, revoked, or expired; zero writes.</summary>
    Unavailable
}

/// <summary>The unique outcome of one explicit revocation attempt.</summary>
public enum IdentitySessionRevocationResult
{
    /// <summary>This call wrote the first revocation fact.</summary>
    Revoked,

    /// <summary>The row was already revoked; the first revocation's time and reason stay authoritative.</summary>
    AlreadyRevoked,

    /// <summary>No such row; no state was invented.</summary>
    Missing
}

/// <summary>
/// The closed set of canonical revocation reasons. The domain API accepts only this enum, never
/// free text; the database stores the canonical lowercase value and deliberately carries no value
/// check so later canonical events can extend the set without a schema change.
/// </summary>
public enum IdentitySessionRevocationReason
{
    Logout,
    Administrative,
    CodeReplay
}

/// <summary>
/// Domain service over the shared server-side identity sessions (<c>PS-04</c>): create, classify,
/// bounded activity slide, row lock, explicit revocation, and retention cleanup. Every operation
/// uses exactly one caller-captured UTC instant for all of its comparisons and writes
/// (<c>PS-22</c>), and every result comes exclusively from the shared database, so any instance
/// recovers any other instance's session; no cookie, Data Protection, or HTTP surface takes part
/// (<c>DF-06</c>). This slice exposes storage and domain semantics only — no route, no cookie
/// parsing, no per-request enforcement, no Discovery effect (<c>AC-03</c>/<c>AC-09</c>).
/// </summary>
public interface IIdentitySessionStore
{
    /// <summary>
    /// Creates a session with a fresh id that is never reused: <c>auth_time = last_seen_at =
    /// now</c>, idle <c>now + 30min</c>, absolute <c>now + 12h</c>, and the fixed Password auth
    /// method. The password credential must exist and belong to <paramref name="accountId"/>; a
    /// violation throws <see cref="InvalidOperationException"/> with zero writes. Inside a
    /// caller-owned transaction (the <c>EV-01</c> success transaction) the row commits or rolls
    /// back with it.
    /// </summary>
    Task<IdentitySessionEntity> CreateAsync(
        Guid accountId,
        Guid passwordCredentialId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Classifies one row under <paramref name="now"/> — <see cref="IdentitySessionState.Missing"/>,
    /// then <see cref="IdentitySessionState.Revoked"/> whatever the expiry columns say, then
    /// <see cref="IdentitySessionState.AbsoluteExpired"/>, then
    /// <see cref="IdentitySessionState.IdleExpired"/>, else
    /// <see cref="IdentitySessionState.Active"/> — with zero writes: an expired row is never
    /// marked revoked (<c>EV-04</c>) and a missing row is never invented (<c>SC-18</c>).
    /// </summary>
    Task<IdentitySessionLookup> GetAsync(
        Guid sessionId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Slides the idle deadline of a usable session whose activity is at least
    /// <see cref="IdentityConstants.IdentitySessionActivityThresholdMinutes"/> old, as one
    /// conditional update capped at the row's absolute deadline. Never extends the absolute
    /// deadline, never revives a revoked or expired row, and writes nothing when the row is not
    /// stale or not usable. Only successful browser authorization use may call this.
    /// </summary>
    Task<IdentitySessionActivityResult> TouchActivityAsync(
        Guid sessionId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Locks the session row for a caller-owned transaction that is about to write session-related
    /// state (code, family, logout requests), enforcing the canonical lock order. Requires an
    /// active ambient transaction; returns the tracked row, or <c>null</c> when missing.
    /// </summary>
    /// <exception cref="InvalidOperationException">No ambient transaction exists.</exception>
    Task<IdentitySessionEntity?> LockAsync(
        Guid sessionId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes the explicit revocation fact (<c>revoked_at = now</c> plus the canonical reason) if
    /// the row exists and is still unrevoked. The first revocation stays authoritative: a later
    /// one — whatever its reason — changes nothing. An expired but unrevoked row can still be
    /// revoked; revocation never rewrites the expiry columns.
    /// </summary>
    Task<IdentitySessionRevocationResult> RevokeAsync(
        Guid sessionId,
        IdentitySessionRevocationReason reason,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes rows whose idle deadline or revocation is older than
    /// <see cref="IdentityConstants.IdentitySessionRetentionHours"/> as of
    /// <paramref name="now"/>, returning the deleted count. Rows inside their retention window
    /// stay whatever their state; no reference is ever nulled to enable a delete, and a cancelled
    /// or failed run rolls the whole unit back. A session past its own retention window is still
    /// kept while any retained <c>authorization_codes</c> row references it (<c>PS-23</c>); the
    /// authorization-code cleanup segment runs before this one in the same cleanup round, so
    /// once the last referencing code is deleted the session becomes deletable.
    /// </summary>
    Task<int> CleanupExpiredAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}

public sealed class IdentitySessionStore : IIdentitySessionStore
{
    private readonly IIdentitySessionRepository _repository;
    private readonly IUnitOfWork _unitOfWork;

    public IdentitySessionStore(
        IIdentitySessionRepository repository,
        IUnitOfWork unitOfWork)
    {
        _repository = repository;
        _unitOfWork = unitOfWork;
    }

    public async Task<IdentitySessionEntity> CreateAsync(
        Guid accountId,
        Guid passwordCredentialId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // The restrictive references (PS-23) are proven before the insert, in the same unit of
        // work: a credential that does not exist or belongs to another account is a programming
        // or attack error, never a session. The message names no id (DF-06/DF-13 discipline).
        if (!await _repository.PasswordCredentialExistsForAccountAsync(
                passwordCredentialId, accountId, cancellationToken))
        {
            throw new InvalidOperationException(
                "The password credential does not exist or does not belong to the account.");
        }

        var session = new IdentitySessionEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            PasswordCredentialId = passwordCredentialId,
            AuthMethod = IdentityConstants.AuthMethodPassword,
            AuthTime = now,
            LastSeenAt = now,
            IdleExpiresAt = now.AddMinutes(IdentityConstants.IdentitySessionIdleTimeoutMinutes),
            AbsoluteExpiresAt = now.AddSeconds(IdentityConstants.MaxIdentitySessionAgeSeconds)
        };

        await _repository.AddAsync(session, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return session;
    }

    public async Task<IdentitySessionLookup> GetAsync(
        Guid sessionId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var session = await _repository.GetByIdAsync(sessionId, cancellationToken);
        return new IdentitySessionLookup(Classify(session, now), session);
    }

    public async Task<IdentitySessionActivityResult> TouchActivityAsync(
        Guid sessionId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var staleBefore = now.AddMinutes(-IdentityConstants.IdentitySessionActivityThresholdMinutes);
        var idleExpiresAtCandidate = now.AddMinutes(IdentityConstants.IdentitySessionIdleTimeoutMinutes);
        var affectedRows = await _repository.TouchActivityAsync(
            sessionId, now, staleBefore, idleExpiresAtCandidate, cancellationToken);
        if (affectedRows == 1)
        {
            return IdentitySessionActivityResult.Touched;
        }

        // The conditional update matched nothing; the classification read decides between "usable
        // but not stale" and "unusable" under the same captured instant.
        var session = await _repository.GetByIdAsync(sessionId, cancellationToken);
        return Classify(session, now) == IdentitySessionState.Active
            ? IdentitySessionActivityResult.NotStale
            : IdentitySessionActivityResult.Unavailable;
    }

    public Task<IdentitySessionEntity?> LockAsync(
        Guid sessionId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return _repository.LockByIdAsync(sessionId, cancellationToken);
    }

    public async Task<IdentitySessionRevocationResult> RevokeAsync(
        Guid sessionId,
        IdentitySessionRevocationReason reason,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var affectedRows = await _repository.MarkRevokedAsync(
            sessionId, ToDatabaseValue(reason), now, cancellationToken);
        if (affectedRows == 1)
        {
            return IdentitySessionRevocationResult.Revoked;
        }

        var session = await _repository.GetByIdAsync(sessionId, cancellationToken);
        return session is null
            ? IdentitySessionRevocationResult.Missing
            : IdentitySessionRevocationResult.AlreadyRevoked;
    }

    public Task<int> CleanupExpiredAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var retentionCutoff = now.AddHours(-IdentityConstants.IdentitySessionRetentionHours);
        return _repository.RemoveExpiredBeforeAsync(retentionCutoff, cancellationToken);
    }

    /// <summary>
    /// The one session-availability classification, shared by every enforcement slice
    /// (<see cref="GetAsync"/>, <see cref="TouchActivityAsync"/>, code redemption, authorize-side
    /// reuse): a missing row invents no state, an explicit revocation outranks every expiry, and
    /// an expiry boundary is inclusive. It decides session state only; account and application
    /// policy belong to the calling transaction.
    /// </summary>
    public static IdentitySessionState Classify(
        IdentitySessionEntity? session,
        DateTimeOffset now)
    {
        if (session is null)
        {
            return IdentitySessionState.Missing;
        }

        if (session.RevokedAt is not null)
        {
            return IdentitySessionState.Revoked;
        }

        // The boundaries are inclusive: an operation instant equal to a deadline is already past
        // it, and the absolute check precedes the idle check so a capped idle deadline reports the
        // absolute expiry.
        if (now >= session.AbsoluteExpiresAt)
        {
            return IdentitySessionState.AbsoluteExpired;
        }

        if (now >= session.IdleExpiresAt)
        {
            return IdentitySessionState.IdleExpired;
        }

        return IdentitySessionState.Active;
    }

    private static string ToDatabaseValue(IdentitySessionRevocationReason reason) => reason switch
    {
        IdentitySessionRevocationReason.Logout => "logout",
        IdentitySessionRevocationReason.Administrative => "administrative",
        IdentitySessionRevocationReason.CodeReplay => "code_replay",
        _ => throw new ArgumentOutOfRangeException(
            nameof(reason), reason, "Unknown identity session revocation reason.")
    };
}
