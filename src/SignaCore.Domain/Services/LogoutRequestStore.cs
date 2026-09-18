using System.Security.Cryptography;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;

namespace SignaCore.Domain.Services;

/// <summary>
/// The single creation outcome of <see cref="ILogoutRequestStore.CreateAsync"/>.
/// <paramref name="LogoutHandle"/> is the plaintext 43-character handle, returned exactly once
/// here and never persisted, logged, or recoverable afterwards (<c>DF-10</c>).
/// <paramref name="Id"/> is the public record id, safe for diagnostics (<c>DF-13</c>).
/// </summary>
public sealed record LogoutRequestCreation(Guid Id, string LogoutHandle);

/// <summary>
/// The validated server-side inputs of one prepared-logout row (<c>PS-08</c>): the authenticated
/// client, and the <c>sub</c>/<c>sid</c> snapshots of the validated ID token. The optional
/// verified post-logout URI and state are byte-for-byte registration/request snapshots. The ID
/// token itself is never part of this shape (<c>DF-08</c>).
/// </summary>
public sealed record LogoutRequestDescriptor(
    Guid ApplicationId,
    Guid AccountId,
    Guid IdentitySessionId,
    string? VerifiedPostLogoutRedirectUri,
    string? State);

/// <summary>
/// Domain service over the shared prepared-logout continuation rows (<c>PS-08</c>): create,
/// digest lookup, row lock for the completion transaction, atomic one-time consumption, and
/// retention cleanup. No HTTP surface and no session/family policy decisions live here —
/// orchestration belongs to the logout completion slice.
/// </summary>
public interface ILogoutRequestStore
{
    /// <summary>
    /// Persists one row from the already validated preparation, generating a fresh high-entropy
    /// 43-character <c>[A-Za-z0-9_-]</c> handle (<c>IN-35</c> shape). The row expires
    /// <see cref="IdentityConstants.LogoutHandleLifetimeMinutes"/> after <paramref name="now"/>,
    /// the single captured UTC instant for every comparison and write (<c>PS-22</c>).
    /// </summary>
    Task<LogoutRequestCreation> CreateAsync(
        LogoutRequestDescriptor descriptor,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves an already shape-validated plaintext handle to its active row by digest, or
    /// <c>null</c> — the single "unavailable" answer for a missing, expired, or consumed row —
    /// without any write or invented consumption (<c>SC-18</c>). The release decision is a
    /// constant-time digest comparison.
    /// </summary>
    Task<LogoutRequestEntity?> GetActiveAsync(
        string logoutHandle,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Locks the row for a caller-owned completion transaction, after
    /// <see cref="IIdentitySessionStore.LockAsync"/> has locked the session when one may exist
    /// (<c>EV-28</c> lock order). Requires an active ambient transaction.
    /// </summary>
    Task<LogoutRequestEntity?> LockAsync(
        Guid requestId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically consumes the active row of <paramref name="logoutHandle"/> at
    /// <paramref name="now"/>: exactly one caller observes <c>true</c>. Inside a caller-owned
    /// transaction the consumption commits or rolls back with it (<c>EV-18</c>).
    /// </summary>
    Task<bool> TryConsumeAsync(
        string logoutHandle,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes rows expired for longer than
    /// <see cref="IdentityConstants.LogoutRequestRetentionHours"/> as of <paramref name="now"/>,
    /// returning the deleted count. Nothing references this table.
    /// </summary>
    Task<int> CleanupExpiredAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default);
}

public sealed class LogoutRequestStore : ILogoutRequestStore
{
    private readonly ILogoutRequestRepository _repository;
    private readonly IUnitOfWork _unitOfWork;

    public LogoutRequestStore(
        ILogoutRequestRepository repository,
        IUnitOfWork unitOfWork)
    {
        _repository = repository;
        _unitOfWork = unitOfWork;
    }

    public async Task<LogoutRequestCreation> CreateAsync(
        LogoutRequestDescriptor descriptor,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        cancellationToken.ThrowIfCancellationRequested();

        var logoutHandle = GenerateLogoutHandle();
        var request = new LogoutRequestEntity
        {
            Id = Guid.NewGuid(),
            HandleDigest = LoginHandleDigest.Compute(logoutHandle),
            AppRegistrationId = descriptor.ApplicationId,
            AccountId = descriptor.AccountId,
            IdentitySessionId = descriptor.IdentitySessionId,
            PostLogoutRedirectUri = descriptor.VerifiedPostLogoutRedirectUri,
            State = descriptor.State,
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(IdentityConstants.LogoutHandleLifetimeMinutes)
        };

        await _repository.AddAsync(request, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return new LogoutRequestCreation(request.Id, logoutHandle);
    }

    public async Task<LogoutRequestEntity?> GetActiveAsync(
        string logoutHandle,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!IsLogoutHandleShape(logoutHandle))
        {
            // Unvalidated raw input never becomes a query key (SC-18).
            return null;
        }

        var handleDigest = LoginHandleDigest.Compute(logoutHandle);
        var request = await _repository.GetActiveByHandleDigestAsync(
            handleDigest,
            now,
            cancellationToken);
        if (request is null)
        {
            return null;
        }

        // The index answered the lookup; the release decision is a constant-time comparison.
        return LoginHandleDigest.Matches(handleDigest, request.HandleDigest) ? request : null;
    }

    public Task<LogoutRequestEntity?> LockAsync(
        Guid requestId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return _repository.LockByIdAsync(requestId, cancellationToken);
    }

    public async Task<bool> TryConsumeAsync(
        string logoutHandle,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!IsLogoutHandleShape(logoutHandle))
        {
            return false;
        }

        return await _repository.TryConsumeAsync(
            LoginHandleDigest.Compute(logoutHandle),
            now,
            cancellationToken);
    }

    public Task<int> CleanupExpiredAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var retentionCutoff = now.AddHours(-IdentityConstants.LogoutRequestRetentionHours);
        return _repository.RemoveExpiredBeforeAsync(retentionCutoff, cancellationToken);
    }

    /// <summary>
    /// 256 bits of CSPRNG output rendered as exactly 43 unpadded base64url characters — the
    /// <c>IN-35</c> shape by construction, never by post-hoc filtering.
    /// </summary>
    private static string GenerateLogoutHandle()
    {
        Span<byte> entropy = stackalloc byte[32];
        RandomNumberGenerator.Fill(entropy);
        return Convert.ToBase64String(entropy)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static bool IsLogoutHandleShape(string? value)
    {
        return value is not null
            && value.Length == IdentityConstants.LogoutHandleLength
            && value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
    }
}
