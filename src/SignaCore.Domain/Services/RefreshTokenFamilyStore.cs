using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Validators;

namespace SignaCore.Domain.Services;

/// <summary>
/// The closed revocation-cause set of the interactive refresh family writes (<c>PS-06</c>). The
/// refresh-token row itself stores only the boolean revocation fact — the first fact stays
/// authoritative and is never rewritten — so the reason exists to keep every caller of the family
/// API on one of the canonical events: code replay (<c>EV-24</c>), logout (<c>EV-06</c>),
/// administrative session revocation (<c>EV-15</c>), and the rotation-time <c>EV-32</c> causes
/// (session expiry, missing session authority, application max-age, scope removal) that revoke
/// the family in the rejecting refresh transaction itself.
/// </summary>
public enum RefreshFamilyRevocationReason
{
    CodeReplay,
    Logout,
    Administrative,

    /// <summary><c>EV-31</c>: detected reuse of a consumed member revoked that member's live descendants.</summary>
    RefreshReuse,

    /// <summary><c>EV-32</c>: the rejecting refresh found the session idle/absolute expired (or revoked).</summary>
    SessionExpired,

    /// <summary><c>EV-32</c>: the rejecting refresh found no session row — missing authority, never a guessed session.</summary>
    SessionMissing,

    /// <summary><c>EV-05</c>/<c>EV-32</c>: the application's per-session max-age was exceeded.</summary>
    ApplicationMaxAge,

    /// <summary><c>EV-13</c>/<c>EV-32</c>: a family scope member left the application's current allow list.</summary>
    ScopeRemoved,

    /// <summary><c>EV-08</c>: the account-disable transaction revoked every interactive family of the account.</summary>
    AccountDisabled,

    /// <summary><c>EV-09</c>: the application-deactivation transaction revoked the application's interactive families.</summary>
    ApplicationDisabled,

    /// <summary><c>EV-11</c>: the refresh-capability-off transaction revoked the application's interactive families.</summary>
    RefreshCapabilityDisabled
}

/// <summary>
/// The validated server-side inputs of one interactive refresh family root (<c>PS-06</c>/<c>EV-21</c>):
/// the account, the interactive client's AppId, the live identity session, and the byte-for-byte
/// authorization-code snapshots of the canonical scope and the original authentication time. The
/// plaintext token is never part of this shape — it exists only in the creation result.
/// </summary>
public sealed record InteractiveRefreshFamilyRootDescriptor(
    Guid AccountId,
    string AppId,
    Guid IdentitySessionId,
    string Scope,
    DateTimeOffset AuthTime);

/// <summary>
/// The single creation outcome of <see cref="IRefreshTokenFamilyStore.CreateRootAsync"/>.
/// <paramref name="RefreshToken"/> is the plaintext 43-character token, returned exactly once
/// here and never persisted, logged, or recoverable afterwards (<c>DF-09</c>);
/// <paramref name="RootId"/> is the public record id, safe for diagnostics (<c>DF-13</c>).
/// </summary>
public sealed record InteractiveRefreshFamilyRootCreation(
    Guid RootId,
    string RefreshToken,
    DateTimeOffset ExpiresAt);

/// <summary>
/// The marker classification of one digest-matched <c>refresh_tokens</c> row (<c>PS-06</c>/
/// <c>PS-07</c>): the complete interactive marker (session, canonical scope, auth time all
/// present), the all-null legacy marker, or anything in between — a partial marker no writer of
/// either kind can produce, which the caller must treat as corrupt state.
/// </summary>
public enum RefreshMemberMarker
{
    Interactive,
    Legacy,
    Partial
}

/// <summary>
/// The validated server-side inputs of one interactive family child (<c>EV-29</c>): the presented
/// member being consumed, the root it belongs to, and the byte-for-byte copies of the root's
/// account/client/session/scope/auth-time bindings and family deadline. The child id and digest
/// are the request-local stable values of one rotation attempt — stable across an
/// execution-strategy retry, so a replayed attempt never mints a second child and a commit of
/// this attempt can always be recognized as its own (<c>PS-22</c>). The plaintext token exists
/// only in the calling rotation, never in this shape.
/// </summary>
public sealed record InteractiveRefreshChildDescriptor(
    Guid ChildId,
    Guid ParentId,
    Guid RootId,
    Guid AccountId,
    string AppId,
    Guid IdentitySessionId,
    string Scope,
    DateTimeOffset AuthTime,
    DateTimeOffset FamilyDeadline,
    string TokenDigest);

/// <summary>
/// Domain service over the interactive refresh families (<c>PS-06</c>): family root creation
/// inside the caller's redemption transaction (<c>EV-21</c>), child creation and conditional
/// consumption inside the caller's rotation transaction (<c>EV-29</c>), live-descendant
/// revocation for detected reuse (<c>EV-31</c>), whole-family revocation by root (<c>EV-24</c>)
/// and by identity session (<c>EV-06</c>/<c>EV-15</c>), and the child-first retention cleanup.
/// Every write is a conditional update on which the first fact stays authoritative, and every
/// operation uses one caller-captured UTC instant (<c>PS-22</c>).
/// </summary>
public interface IRefreshTokenFamilyStore
{
    /// <summary>
    /// Creates one family root from values the caller's <c>EV-21</c> transaction already resolved
    /// and locked: a fresh 43-character token (32 CSPRNG bytes, unpadded base64url), a versioned
    /// SHA-256 digest stored, <c>family_id = id</c> with <c>parent_id</c> null, the complete
    /// interactive marker (account/application/session/scope/auth time), and
    /// <c>expires_at = now + <see cref="IdentityConstants.InteractiveRefreshFamilyLifetimeDays"/></c>
    /// days — the session bound is enforced at use time, never by the column. Inside a caller-owned
    /// transaction the staged row commits or rolls back with it.
    /// </summary>
    /// <exception cref="ArgumentException">An empty id, client, or non-canonical scope. The message never carries an input value.</exception>
    Task<InteractiveRefreshFamilyRootCreation> CreateRootAsync(
        InteractiveRefreshFamilyRootDescriptor descriptor,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Stages one family child inside the caller's rotation transaction (<c>EV-29</c>): the
    /// request-local stable id and digest of the attempt, <c>parent_id</c> = the presented member
    /// being consumed, <c>family_id</c> = the root, and byte-for-byte copies of the root's
    /// account/client/session/scope/auth-time bindings and family deadline — rotation never
    /// extends the family. The unique <c>parent_id</c> index is the database backstop that gives
    /// a presented member at most one child. Inside a caller-owned transaction the staged row
    /// commits or rolls back with it.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// An empty or duplicated id/parent/root relationship, an empty client, a non-canonical scope,
    /// or a non-digest token value. The message never carries an input value.
    /// </exception>
    Task CreateChildAsync(
        InteractiveRefreshChildDescriptor descriptor,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// The single conditional consumption write (<c>EV-29</c>): sets <c>consumed_at</c> on the
    /// presented member only while it is an interactive row that is neither revoked nor already
    /// consumed. Exactly one concurrent rotation of the same member can succeed; the loser
    /// observes the committed <c>consumed_at</c> and follows reuse handling instead.
    /// </summary>
    Task<bool> TryConsumeAsync(
        Guid memberId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every unrevoked member of one family identified by its root id (<c>EV-24</c>):
    /// a conditional update over interactive rows only, so an already-revoked member keeps the
    /// first fact. Returns the number of members this call revoked.
    /// </summary>
    Task<int> RevokeFamilyAsync(
        Guid rootId,
        RefreshFamilyRevocationReason reason,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// The <c>EV-31</c> reuse disposal: revokes every live — unconsumed and unrevoked —
    /// interactive member of the family that is a descendant of the presented (consumed) member,
    /// following the parent chain down through already-consumed or revoked links so a live member
    /// below them is still reached; ancestors and sibling families keep their facts. Returns the
    /// number of members this call revoked.
    /// </summary>
    Task<int> RevokeLiveDescendantsAsync(
        Guid familyId,
        Guid memberId,
        RefreshFamilyRevocationReason reason,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every unrevoked interactive refresh family bound to one identity session
    /// (<c>EV-06</c>/<c>EV-15</c>): a conditional update over interactive rows only — legacy
    /// rows have no session and are structurally out of reach. Returns the number of members
    /// this call revoked.
    /// </summary>
    Task<int> RevokeBySessionAsync(
        Guid identitySessionId,
        RefreshFamilyRevocationReason reason,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every unrevoked interactive refresh family of one account (<c>EV-08</c>): the
    /// account-disable transaction's family disposal, a conditional update over interactive rows
    /// only — legacy rows are structurally out of reach (<c>PS-07</c>). Returns the number of
    /// members this call revoked.
    /// </summary>
    Task<int> RevokeByAccountAsync(
        Guid accountId,
        RefreshFamilyRevocationReason reason,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every unrevoked interactive refresh family issued to one application
    /// (<c>EV-09</c>/<c>EV-11</c>): the application-deactivation and refresh-capability
    /// transactions' family disposal. Returns the number of members this call revoked.
    /// </summary>
    Task<int> RevokeByApplicationAsync(
        string appId,
        RefreshFamilyRevocationReason reason,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes whole interactive families that are past every member's usable deadline and that no
    /// retained authorization code links to, children before roots, returning the deleted member
    /// count. Under the restrictive family self-reference a single-statement whole-family delete
    /// is provider-asymmetric, so the child-first two-statement unit is the only admissible path.
    /// A family whose linked code is still inside its retention window stays, so a proved replay
    /// can never become a missing code (<c>SC-18</c>).
    /// </summary>
    Task<int> CleanupExpiredAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}

/// <inheritdoc cref="IRefreshTokenFamilyStore"/>
public sealed class RefreshTokenFamilyStore(
    IRefreshTokenRepository refreshTokens,
    IUnitOfWork unitOfWork,
    ILogger<RefreshTokenFamilyStore> logger) : IRefreshTokenFamilyStore
{
    public async Task<InteractiveRefreshFamilyRootCreation> CreateRootAsync(
        InteractiveRefreshFamilyRootDescriptor descriptor,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        cancellationToken.ThrowIfCancellationRequested();

        // Preconditions are programming errors of the calling EV-21 transaction, which resolved
        // every value itself. The messages name the offending concept and never an input value.
        if (descriptor.AccountId == Guid.Empty)
        {
            throw new ArgumentException("The account id must not be empty.", nameof(descriptor));
        }

        if (descriptor.IdentitySessionId == Guid.Empty)
        {
            throw new ArgumentException("The identity session id must not be empty.", nameof(descriptor));
        }

        if (string.IsNullOrEmpty(descriptor.AppId))
        {
            throw new ArgumentException("The client id must not be empty.", nameof(descriptor));
        }

        if (!IsCanonicalInteractiveScope(descriptor.Scope))
        {
            throw new ArgumentException("The scope must be the canonical interactive scope value.", nameof(descriptor));
        }

        var refreshToken = GenerateRefreshToken();
        var rootId = Guid.NewGuid();
        var expiresAt = now.AddDays(IdentityConstants.InteractiveRefreshFamilyLifetimeDays);
        await refreshTokens.AddAsync(new RefreshTokenEntity
        {
            Id = rootId,
            // PS-06: the root is its own family with no parent and the complete interactive marker.
            FamilyId = rootId,
            ParentId = null,
            AccountId = descriptor.AccountId,
            TokenValue = RefreshTokenDigest.Compute(refreshToken),
            CreatedAt = now,
            ExpiresAt = expiresAt,
            IsRevoked = false,
            AppId = descriptor.AppId,
            IdentitySessionId = descriptor.IdentitySessionId,
            Scope = descriptor.Scope,
            AuthTime = descriptor.AuthTime
        }, cancellationToken);

        // Flush the staged insert so a caller's immediate conditional link write
        // (authorization_codes.refresh_family_id) satisfies its restrictive reference; the
        // commit itself stays with the caller's transaction.
        await unitOfWork.SaveChangesAsync(cancellationToken);
        return new InteractiveRefreshFamilyRootCreation(rootId, refreshToken, expiresAt);
    }

    public async Task CreateChildAsync(
        InteractiveRefreshChildDescriptor descriptor,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        cancellationToken.ThrowIfCancellationRequested();

        // Preconditions are programming errors of the calling EV-29 transaction, which resolved
        // and locked every value itself. The messages name the offending concept, never a value.
        if (descriptor.ChildId == Guid.Empty
            || descriptor.ChildId == descriptor.ParentId
            || descriptor.ChildId == descriptor.RootId)
        {
            throw new ArgumentException("The child id must be a fresh id distinct from its family.", nameof(descriptor));
        }

        if (descriptor.ParentId == Guid.Empty || descriptor.RootId == Guid.Empty)
        {
            throw new ArgumentException("The parent and root ids must not be empty.", nameof(descriptor));
        }

        if (descriptor.AccountId == Guid.Empty || descriptor.IdentitySessionId == Guid.Empty)
        {
            throw new ArgumentException("The account and identity session ids must not be empty.", nameof(descriptor));
        }

        if (string.IsNullOrEmpty(descriptor.AppId))
        {
            throw new ArgumentException("The client id must not be empty.", nameof(descriptor));
        }

        if (!IsCanonicalInteractiveScope(descriptor.Scope))
        {
            throw new ArgumentException("The scope must be the canonical interactive scope value.", nameof(descriptor));
        }

        if (!RefreshTokenDigest.IsDigest(descriptor.TokenDigest))
        {
            throw new ArgumentException("The child token value must be a versioned refresh token digest.", nameof(descriptor));
        }

        await refreshTokens.AddAsync(new RefreshTokenEntity
        {
            Id = descriptor.ChildId,
            // EV-29: the child copies the root's bindings and deadline byte for byte; only the
            // parent relationship and the fresh credential are new.
            FamilyId = descriptor.RootId,
            ParentId = descriptor.ParentId,
            AccountId = descriptor.AccountId,
            TokenValue = descriptor.TokenDigest,
            CreatedAt = now,
            ExpiresAt = descriptor.FamilyDeadline,
            IsRevoked = false,
            AppId = descriptor.AppId,
            IdentitySessionId = descriptor.IdentitySessionId,
            Scope = descriptor.Scope,
            AuthTime = descriptor.AuthTime
        }, cancellationToken);

        // Flush inside the caller's transaction so the row is part of the same unit; the commit
        // stays with the caller.
        await unitOfWork.SaveChangesAsync(cancellationToken);
    }

    public Task<bool> TryConsumeAsync(
        Guid memberId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return refreshTokens.TryConsumeInteractiveAsync(memberId, now, cancellationToken);
    }

    public async Task<int> RevokeLiveDescendantsAsync(
        Guid familyId,
        Guid memberId,
        RefreshFamilyRevocationReason reason,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var revoked = await refreshTokens.RevokeLiveDescendantsAsync(
            familyId, memberId, cancellationToken);
        if (revoked > 0)
        {
            logger.LogInformation(
                "Revoked {Count} live descendants of a reused interactive refresh family member: RootId={RootId}, MemberId={MemberId}, Reason={Reason}",
                revoked,
                familyId,
                memberId,
                reason);
        }

        return revoked;
    }

    public async Task<int> RevokeFamilyAsync(
        Guid rootId,
        RefreshFamilyRevocationReason reason,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var revoked = await refreshTokens.RevokeFamilyAsync(rootId, cancellationToken);
        if (revoked > 0)
        {
            logger.LogInformation(
                "Revoked {Count} interactive refresh family members: RootId={RootId}, Reason={Reason}",
                revoked,
                rootId,
                reason);
        }

        return revoked;
    }

    public async Task<int> RevokeBySessionAsync(
        Guid identitySessionId,
        RefreshFamilyRevocationReason reason,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var revoked = await refreshTokens.RevokeBySessionAsync(identitySessionId, cancellationToken);
        if (revoked > 0)
        {
            logger.LogInformation(
                "Revoked {Count} interactive refresh family members by session: SessionId={SessionId}, Reason={Reason}",
                revoked,
                identitySessionId,
                reason);
        }

        return revoked;
    }

    public async Task<int> RevokeByAccountAsync(
        Guid accountId,
        RefreshFamilyRevocationReason reason,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var revoked = await refreshTokens.RevokeByAccountAsync(accountId, cancellationToken);
        if (revoked > 0)
        {
            logger.LogInformation(
                "Revoked {Count} interactive refresh family members by account: AccountId={AccountId}, Reason={Reason}",
                revoked,
                accountId,
                reason);
        }

        return revoked;
    }

    public async Task<int> RevokeByApplicationAsync(
        string appId,
        RefreshFamilyRevocationReason reason,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var revoked = await refreshTokens.RevokeByApplicationAsync(appId, cancellationToken);
        if (revoked > 0)
        {
            logger.LogInformation(
                "Revoked {Count} interactive refresh family members by application: AppId={AppId}, Reason={Reason}",
                revoked,
                appId,
                reason);
        }

        return revoked;
    }

    public Task<int> CleanupExpiredAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return refreshTokens.RemoveInteractiveFamiliesAsync(now, cancellationToken);
    }

    /// <summary>
    /// The marker classification of one digest-matched row (<c>PS-06</c>/<c>PS-07</c>): the
    /// complete interactive marker, the all-null legacy marker, or the partial marker no writer
    /// of either kind can produce, which the caller must fail closed on as corrupt state.
    /// </summary>
    public static RefreshMemberMarker ClassifyMarker(RefreshTokenEntity row)
    {
        ArgumentNullException.ThrowIfNull(row);
        var interactiveMarker = row.IdentitySessionId is not null
            && row.Scope is not null
            && row.AuthTime is not null;
        var legacyMarker = row.IdentitySessionId is null
            && row.Scope is null
            && row.AuthTime is null;
        return interactiveMarker ? RefreshMemberMarker.Interactive
            : legacyMarker ? RefreshMemberMarker.Legacy
            : RefreshMemberMarker.Partial;
    }

    /// <summary>
    /// The canonical interactive refresh token shape: 256 bits of CSPRNG output rendered as
    /// exactly 43 unpadded base64url characters — never by post-hoc filtering. Public because
    /// the rotation slice (<c>EV-29</c>) must generate the child credential once per HTTP
    /// attempt — outside the execution-strategy lambda — so a retried attempt reuses the same
    /// bytes and can recognize its own committed child.
    /// </summary>
    public static string GenerateRefreshToken()
    {
        Span<byte> entropy = stackalloc byte[32];
        RandomNumberGenerator.Fill(entropy);
        return Convert.ToBase64String(entropy)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <summary>
    /// The single canonical-form judgement over the full interactive vocabulary: <c>openid</c>
    /// present, unique members, only the three supported values, in the fixed
    /// <c>openid profile offline_access</c> order — the same <see cref="OidcScopeValidator"/>
    /// rules the code snapshot was built under, so the family copy cannot drift.
    /// </summary>
    private static bool IsCanonicalInteractiveScope(string? scope) =>
        OidcScopeValidator.TryValidateRequested(
            scope,
            new HashSet<string>(StringComparer.Ordinal)
            {
                OidcScopeValidator.OpenId,
                OidcScopeValidator.Profile,
                OidcScopeValidator.OfflineAccess
            },
            allowRefreshToken: true,
            out var canonicalScope)
        && string.Equals(canonicalScope, scope, StringComparison.Ordinal);
}
