using System.Security.Cryptography;
using System.Text;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;

namespace SignaCore.Domain.Services;

/// <summary>
/// The unique state classification of <see cref="IAuthorizationCodeStore.FindAsync"/>, decided
/// under one captured UTC instant. A bad shape, a missing digest, or a failed constant-time
/// comparison share the single <see cref="Missing"/> answer that invents no state
/// (<c>SC-18</c>); an explicit consumption outranks expiry whatever the clock says (an
/// expired-but-retained consumed code is still a replay, <c>EV-24</c>); the expiry boundary is
/// inclusive — <c>now == expires_at</c> is already expired.
/// </summary>
public enum AuthorizationCodeState
{
    Missing,
    Consumed,
    Expired,
    Unconsumed
}

/// <summary>
/// The classification plus the row it was decided on; <see cref="Entity"/> is <c>null</c> only
/// for <see cref="AuthorizationCodeState.Missing"/>.
/// </summary>
public sealed record AuthorizationCodeLookup(
    AuthorizationCodeState State,
    AuthorizationCodeEntity? Entity);

/// <summary>
/// The validated continuation snapshot an authorization code is created from: the client the
/// request was accepted for, plus the exact redirect URI, canonical scope, nonce, and S256
/// challenge snapshots. The PKCE verifier is never part of any persisted shape (<c>DF-04</c>).
/// </summary>
public sealed record AuthorizationCodeBinding(
    Guid ApplicationId,
    string RedirectUri,
    string Scope,
    string Nonce,
    string CodeChallenge);

/// <summary>
/// The single creation outcome of <see cref="IAuthorizationCodeStore.CreateAsync"/>.
/// <paramref name="Code"/> is the plaintext 43-character code, returned exactly once here and
/// never persisted, logged, or recoverable afterwards (<c>DF-03</c>). <paramref name="Id"/> is
/// the public record id, safe for diagnostics (<c>DF-13</c>).
/// </summary>
public sealed record AuthorizationCodeCreation(Guid Id, string Code);

/// <summary>
/// Domain service over the shared short-lived authorization codes (<c>PS-05</c>): create from an
/// authenticated session, classify by plaintext code, verify the redemption binding, row lock in
/// the canonical session-then-code order, atomic one-time consumption, and retention cleanup.
/// Every operation uses exactly one caller-captured UTC instant for all of its comparisons and
/// writes (<c>PS-22</c>), and every result comes exclusively from the shared database, so any
/// instance can redeem any instance's code (<c>SC-13</c>). This slice exposes storage and domain
/// semantics only — no route, no token issuance, no live-session/account/application policy
/// decision (those belong to the redemption slice), and no Discovery effect (<c>AC-03</c>).
/// </summary>
public interface IAuthorizationCodeStore
{
    /// <summary>
    /// Persists one code row from an already authenticated session and the validated binding
    /// snapshot, generating a fresh high-entropy 43-character <c>[A-Za-z0-9_-]</c> code
    /// (<c>IN-22</c>). <c>account_id</c> and <c>auth_time</c> are copied from
    /// <paramref name="session"/>; <c>expires_at</c> is <paramref name="now"/> plus
    /// <see cref="IdentityConstants.AuthorizationCodeLifetimeSeconds"/>. Live-session, account,
    /// and application policy are the caller's responsibility. Inside a caller-owned transaction
    /// (the <c>EV-01</c> success transaction) the row commits or rolls back with it.
    /// </summary>
    Task<AuthorizationCodeCreation> CreateAsync(
        IdentitySessionEntity session,
        AuthorizationCodeBinding binding,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Classifies one plaintext code under <paramref name="now"/> with zero writes. The unique
    /// order is: a malformed shape, a missing digest, or a failed constant-time comparison
    /// → <see cref="AuthorizationCodeState.Missing"/>; a non-null <c>consumed_at</c> →
    /// <see cref="AuthorizationCodeState.Consumed"/> whatever the expiry says; then
    /// <paramref name="now"/> ≥ <c>expires_at</c> → <see cref="AuthorizationCodeState.Expired"/>;
    /// otherwise <see cref="AuthorizationCodeState.Unconsumed"/>. Unvalidated raw input never
    /// becomes a query key.
    /// </summary>
    Task<AuthorizationCodeLookup> FindAsync(
        string code,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Pure, zero-I/O verification of the redemption binding: the client id must match, the
    /// redirect URI must equal the snapshot ordinally (no normalization), and the PKCE verifier
    /// must have the <c>IN-24</c> shape (43–128 ASCII <c>[A-Za-z0-9._~-]</c>) and hash to the
    /// stored S256 challenge under a constant-time comparison. Any mismatch returns
    /// <c>false</c> without distinguishing the reason. Scope is not a redemption input
    /// (<c>IN-25</c>) and takes no part here.
    /// </summary>
    bool VerifyBinding(
        AuthorizationCodeEntity code,
        Guid applicationId,
        string redirectUri,
        string codeVerifier);

    /// <summary>
    /// Locks the code row for a caller-owned redemption transaction, after
    /// <see cref="IIdentitySessionStore.LockAsync"/> has locked its session (<c>EV-20</c> lock
    /// order). Requires an active ambient transaction; returns a no-tracking snapshot (the
    /// tracked session row stays tracked), or <c>null</c> when missing.
    /// </summary>
    /// <exception cref="InvalidOperationException">No ambient transaction exists.</exception>
    Task<AuthorizationCodeEntity?> LockAsync(
        Guid codeId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically consumes the row at <paramref name="now"/>: a single conditional update of the
    /// unconsumed, unexpired row, so exactly one caller observes <c>true</c> and everyone else
    /// observes the committed outcome as <c>false</c> (<c>SC-13</c>). Expiry is never recorded as
    /// consumption. Inside a caller-owned transaction it commits or rolls back with it
    /// (<c>EV-21</c>/<c>EV-26</c>), and a committed consumption stays authoritative.
    /// </summary>
    Task<bool> TryConsumeAsync(
        Guid codeId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Points the consumed code row at its refresh family root (<c>EV-21</c>): a conditional
    /// update of the still-unlinked row, so a code can never be re-pointed at a second family.
    /// The referenced root must already be flushed in the caller's transaction. Returns
    /// <c>false</c> when no unlinked row matched — an invariant violation inside a redemption.
    /// </summary>
    Task<bool> LinkRefreshFamilyAsync(
        Guid codeId,
        Guid rootId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes rows whose <c>expires_at</c> is older than
    /// <see cref="IdentityConstants.AuthorizationCodeRetentionHours"/> as of
    /// <paramref name="now"/> — consumed and unconsumed alike — returning the deleted count. Rows
    /// inside the retention window stay, and a cancelled or failed run rolls the whole unit back.
    /// </summary>
    Task<int> CleanupExpiredAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}

public sealed class AuthorizationCodeStore : IAuthorizationCodeStore
{
    private const int VerifierMinimumLength = 43;
    private const int VerifierMaximumLength = 128;

    private readonly IAuthorizationCodeRepository _repository;
    private readonly IUnitOfWork _unitOfWork;

    public AuthorizationCodeStore(
        IAuthorizationCodeRepository repository,
        IUnitOfWork unitOfWork)
    {
        _repository = repository;
        _unitOfWork = unitOfWork;
    }

    public async Task<AuthorizationCodeCreation> CreateAsync(
        IdentitySessionEntity session,
        AuthorizationCodeBinding binding,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(binding);
        cancellationToken.ThrowIfCancellationRequested();

        var code = GenerateAuthorizationCode();
        var entity = new AuthorizationCodeEntity
        {
            Id = Guid.NewGuid(),
            CodeDigest = AuthorizationCodeDigest.Compute(code),
            AppRegistrationId = binding.ApplicationId,
            AccountId = session.AccountId,
            IdentitySessionId = session.Id,
            RedirectUri = binding.RedirectUri,
            Scope = binding.Scope,
            Nonce = binding.Nonce,
            CodeChallenge = binding.CodeChallenge,
            AuthTime = session.AuthTime,
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(IdentityConstants.AuthorizationCodeLifetimeSeconds)
        };

        await _repository.AddAsync(entity, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return new AuthorizationCodeCreation(entity.Id, code);
    }

    public async Task<AuthorizationCodeLookup> FindAsync(
        string code,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!IsAuthorizationCodeShape(code))
        {
            // Unvalidated raw input never becomes a query key; a malformed code shares the single
            // Missing answer with an absent digest (SC-18).
            return new AuthorizationCodeLookup(AuthorizationCodeState.Missing, null);
        }

        var codeDigest = AuthorizationCodeDigest.Compute(code);
        var entity = await _repository.GetByCodeDigestAsync(codeDigest, cancellationToken);
        if (entity is null || !AuthorizationCodeDigest.Matches(codeDigest, entity.CodeDigest))
        {
            return new AuthorizationCodeLookup(AuthorizationCodeState.Missing, null);
        }

        // The index answered the lookup; the release decision is a constant-time comparison so no
        // short-circuiting string equality sits between a stored digest and the caller.
        if (entity.ConsumedAt is not null)
        {
            return new AuthorizationCodeLookup(AuthorizationCodeState.Consumed, entity);
        }

        // The boundary is inclusive: the operation instant equal to the deadline is already past it.
        if (now >= entity.ExpiresAt)
        {
            return new AuthorizationCodeLookup(AuthorizationCodeState.Expired, entity);
        }

        return new AuthorizationCodeLookup(AuthorizationCodeState.Unconsumed, entity);
    }

    public bool VerifyBinding(
        AuthorizationCodeEntity code,
        Guid applicationId,
        string redirectUri,
        string codeVerifier)
    {
        ArgumentNullException.ThrowIfNull(code);

        if (code.AppRegistrationId != applicationId
            || !string.Equals(code.RedirectUri, redirectUri, StringComparison.Ordinal)
            || !IsVerifierShape(codeVerifier))
        {
            return false;
        }

        // RFC 7636 section 4.2: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))). The comparison is
        // constant-time so the mismatch reason stays indistinguishable.
        var computedChallenge = ComputeS256Challenge(codeVerifier);
        return AuthorizationCodeDigest.Matches(computedChallenge, code.CodeChallenge);
    }

    public Task<AuthorizationCodeEntity?> LockAsync(
        Guid codeId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return _repository.LockByIdAsync(codeId, cancellationToken);
    }

    public Task<bool> TryConsumeAsync(
        Guid codeId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return _repository.TryConsumeAsync(codeId, now, cancellationToken);
    }

    public async Task<bool> LinkRefreshFamilyAsync(
        Guid codeId,
        Guid rootId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await _repository.LinkRefreshFamilyAsync(codeId, rootId, cancellationToken) == 1;
    }

    public Task<int> CleanupExpiredAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var retentionCutoff = now.AddHours(-IdentityConstants.AuthorizationCodeRetentionHours);
        return _repository.RemoveExpiredBeforeAsync(retentionCutoff, cancellationToken);
    }

    /// <summary>
    /// 256 bits of CSPRNG output rendered as exactly 43 unpadded base64url characters — the
    /// <c>IN-22</c> shape by construction, never by post-hoc filtering.
    /// </summary>
    private static string GenerateAuthorizationCode()
    {
        Span<byte> entropy = stackalloc byte[32];
        RandomNumberGenerator.Fill(entropy);
        return Convert.ToBase64String(entropy)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static bool IsAuthorizationCodeShape(string? value)
    {
        return value is not null
            && value.Length == IdentityConstants.AuthorizationCodeLength
            && value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
    }

    /// <summary>The <c>IN-24</c> verifier shape: 43–128 ASCII <c>[A-Za-z0-9._~-]</c>.</summary>
    private static bool IsVerifierShape(string? value)
    {
        return value is not null
            && value.Length is >= VerifierMinimumLength and <= VerifierMaximumLength
            && value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '~' or '-');
    }

    private static string ComputeS256Challenge(string verifier)
    {
        var digest = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Convert.ToBase64String(digest)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
