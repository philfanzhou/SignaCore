using System.Security.Cryptography;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Models;

namespace SignaCore.Domain.Services;

/// <summary>
/// The single creation outcome of <see cref="IAuthorizationRequestStore.CreateAsync"/>.
/// <paramref name="LoginHandle"/> is the plaintext 43-character handle, returned exactly once here
/// and never persisted, logged, or recoverable afterwards (<c>DF-05</c>). <paramref name="Id"/> is
/// the public record id, safe for diagnostics (<c>DF-13</c>).
/// </summary>
public sealed record AuthorizationRequestCreation(Guid Id, string LoginHandle);

/// <summary>
/// Domain service over the shared authorization-request continuation rows (<c>PS-03</c>): create,
/// digest lookup, atomic one-time consumption, and retention cleanup. This slice exposes storage and
/// domain semantics only — no HTTP route, no token, no Discovery effect (<c>AC-02</c>). Orchestration
/// (when a continuation is created, revalidation of the current client/redirect/scope/account before
/// any redirect, and code issuance) belongs to the authorize slice; browser-side field validation
/// and CSRF belong to the login slice.
/// </summary>
public interface IAuthorizationRequestStore
{
    /// <summary>
    /// Persists one continuation row from an already accepted authorization request
    /// (<c>#93</c> validation output is the only source of the snapshot values), generating a fresh
    /// high-entropy 43-character <c>[A-Za-z0-9_-]</c> handle (<c>IN-10</c>). The row expires
    /// <see cref="IdentityConstants.LoginHandleLifetimeMinutes"/> after <paramref name="now"/>, the
    /// single captured UTC instant for every comparison and write in this operation (<c>PS-22</c>).
    /// Retrying after a failure creates a row under a new handle; a failed creation never leaves a
    /// readable row behind.
    /// </summary>
    Task<AuthorizationRequestCreation> CreateAsync(
        OidcAuthorizationValidationResult.Accepted accepted,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves an already shape-validated plaintext handle (<c>IN-10</c>/<c>IN-11</c>: exactly 43
    /// ASCII <c>[A-Za-z0-9_-]</c>) to its active row by digest. Returns <c>null</c> — the single
    /// "unavailable" answer — for a malformed handle, a missing digest, an expired row, or a
    /// consumed row, without any write, failure count, or replay audit (<c>EV-03</c>, <c>SC-18</c>).
    /// A fetched row is released only after a constant-time digest comparison
    /// (<see cref="LoginHandleDigest.Matches"/>). The result comes exclusively from the shared
    /// database, so any instance can recover any other instance's row; no cookie or protected blob
    /// takes part.
    /// </summary>
    Task<AuthorizationRequestEntity?> GetActiveAsync(
        string loginHandle,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically consumes the active row for <paramref name="loginHandle"/> at
    /// <paramref name="now"/>: exactly one caller observes <c>true</c>, everyone else observes the
    /// committed outcome as <c>false</c>. Callers revalidate the current client, exact redirect URI,
    /// scope, and account state before consuming (<c>EV-01</c>/<c>EV-02</c>); inside a caller-owned
    /// transaction the consumption commits or rolls back with it (<c>EV-18</c>), and a committed
    /// consumption stays authoritative. Expiry is never recorded as consumption.
    /// </summary>
    Task<bool> TryConsumeAsync(
        string loginHandle,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes rows expired for longer than
    /// <see cref="IdentityConstants.AuthorizationRequestRetentionHours"/> as of
    /// <paramref name="now"/>, returning the deleted count. Rows inside their lifetime or inside the
    /// retention window stay, no reference is ever nulled to enable a delete, and a cancelled or
    /// failed run rolls the whole unit back. Nothing references this table, so no retention
    /// reference can outlive the window.
    /// </summary>
    Task<int> CleanupExpiredAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}

public sealed class AuthorizationRequestStore : IAuthorizationRequestStore
{
    private readonly IAuthorizationRequestRepository _repository;
    private readonly IUnitOfWork _unitOfWork;

    public AuthorizationRequestStore(
        IAuthorizationRequestRepository repository,
        IUnitOfWork unitOfWork)
    {
        _repository = repository;
        _unitOfWork = unitOfWork;
    }

    public async Task<AuthorizationRequestCreation> CreateAsync(
        OidcAuthorizationValidationResult.Accepted accepted,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accepted);
        cancellationToken.ThrowIfCancellationRequested();

        var loginHandle = GenerateLoginHandle();
        var request = new AuthorizationRequestEntity
        {
            Id = Guid.NewGuid(),
            HandleDigest = LoginHandleDigest.Compute(loginHandle),
            AppRegistrationId = accepted.ApplicationId,
            RedirectUri = accepted.RegisteredRedirectUri,
            Scope = accepted.CanonicalScope,
            State = accepted.State,
            Nonce = accepted.Nonce,
            CodeChallenge = accepted.CodeChallenge,
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(IdentityConstants.LoginHandleLifetimeMinutes)
        };

        await _repository.AddAsync(request, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return new AuthorizationRequestCreation(request.Id, loginHandle);
    }

    public async Task<AuthorizationRequestEntity?> GetActiveAsync(
        string loginHandle,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!IsLoginHandleShape(loginHandle))
        {
            // Unvalidated raw input never becomes a query key; malformed input shares the single
            // "unavailable" answer with a missing digest (EV-03).
            return null;
        }

        var handleDigest = LoginHandleDigest.Compute(loginHandle);
        var request = await _repository.GetActiveByHandleDigestAsync(
            handleDigest,
            now,
            cancellationToken);
        if (request is null)
        {
            return null;
        }

        // The index answered the lookup; the release decision is a constant-time comparison so no
        // short-circuiting string equality sits between a stored digest and the caller.
        return LoginHandleDigest.Matches(handleDigest, request.HandleDigest) ? request : null;
    }

    public async Task<bool> TryConsumeAsync(
        string loginHandle,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!IsLoginHandleShape(loginHandle))
        {
            return false;
        }

        return await _repository.TryConsumeAsync(
            LoginHandleDigest.Compute(loginHandle),
            now,
            cancellationToken);
    }

    public Task<int> CleanupExpiredAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var retentionCutoff = now.AddHours(-IdentityConstants.AuthorizationRequestRetentionHours);
        return _repository.RemoveExpiredBeforeAsync(retentionCutoff, cancellationToken);
    }

    /// <summary>
    /// 256 bits of CSPRNG output rendered as exactly 43 unpadded base64url characters — the
    /// <c>IN-10</c> shape by construction, never by post-hoc filtering.
    /// </summary>
    private static string GenerateLoginHandle()
    {
        Span<byte> entropy = stackalloc byte[32];
        RandomNumberGenerator.Fill(entropy);
        return Convert.ToBase64String(entropy)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static bool IsLoginHandleShape(string? value)
    {
        return value is not null
            && value.Length == IdentityConstants.LoginHandleLength
            && value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
    }
}
