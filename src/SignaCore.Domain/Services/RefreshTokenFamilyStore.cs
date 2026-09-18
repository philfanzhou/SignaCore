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
/// API on one of the canonical events: code replay (<c>EV-24</c>), logout (<c>EV-06</c>), and
/// administrative session revocation (<c>EV-15</c>).
/// </summary>
public enum RefreshFamilyRevocationReason
{
    CodeReplay,
    Logout,
    Administrative
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
/// Domain service over the interactive refresh families (<c>PS-06</c>): family root creation
/// inside the caller's redemption transaction (<c>EV-21</c>), whole-family revocation by root
/// (<c>EV-24</c>) and by identity session (<c>EV-06</c>/<c>EV-15</c>), and the child-first
/// retention cleanup. Rotation, consumption semantics, and reuse handling belong to the later
/// rotation slice and are deliberately absent. Every write is a conditional update on which the
/// first fact stays authoritative, and every operation uses one caller-captured UTC instant
/// (<c>PS-22</c>).
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
    /// Revokes every unrevoked member of one family identified by its root id (<c>EV-24</c>):
    /// a conditional update over interactive rows only, so an already-revoked member keeps the
    /// first fact. Returns the number of members this call revoked.
    /// </summary>
    Task<int> RevokeFamilyAsync(
        Guid rootId,
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

    public Task<int> CleanupExpiredAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return refreshTokens.RemoveInteractiveFamiliesAsync(now, cancellationToken);
    }

    /// <summary>
    /// The canonical interactive refresh token shape: 256 bits of CSPRNG output rendered as
    /// exactly 43 unpadded base64url characters — never by post-hoc filtering.
    /// </summary>
    private static string GenerateRefreshToken()
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
