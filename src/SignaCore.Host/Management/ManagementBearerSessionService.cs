using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;

namespace SignaCore.Host.Management;

/// <summary>
/// Issues, validates, revokes, and cleans up management-only opaque bearer credentials
/// (#360, stage 2). The management bearer authentication scheme validates through it; no
/// endpoint issues or revokes a credential yet (#392).
/// <para>
/// Every operation runs on a fresh <see cref="IdentityDbContext"/> built without the retrying
/// execution strategy, never on the request-scoped business context: an issuance or revocation
/// is one single-statement unit of work attempted exactly once, and nothing the request staged
/// elsewhere is saved with it. A database failure or an unknown commit outcome answers
/// Unavailable; issuance never regenerates a credential to try again, so an unknown commit can
/// leave at most one unreachable row that expires on its own.
/// </para>
/// <para>
/// The caller's cancellation wins at every boundary — including after a commit — and surfaces as
/// an <see cref="OperationCanceledException"/> carrying the caller's token; a canceled issuance
/// never returns the credential. Validation is live: every call re-reads revocation, expiry,
/// account activity, and whether the account is still the configured bootstrap administrator.
/// A validation already completed is not recalled by a later revocation.
/// </para>
/// <para>
/// Instants come from <see cref="TimeProvider"/>, truncated to whole microseconds — the precision
/// both providers store — so a value compared or returned equals the value read back.
/// </para>
/// </summary>
internal sealed class ManagementBearerSessionService : IManagementBearerSessionCleanup
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(IdentityConstants.ManagementBearerLifetimeMinutes);

    private readonly DbContextOptions<IdentityDbContext> _contextOptions;
    private readonly AdminIdentityOptions _adminIdentity;
    private readonly IManagementBearerSessionRepository _repository;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<ManagementBearerSessionService> _logger;

    public ManagementBearerSessionService(
        DatabaseOptions databaseOptions,
        AdminIdentityOptions adminIdentity,
        IManagementBearerSessionRepository repository,
        TimeProvider timeProvider,
        ILogger<ManagementBearerSessionService> logger)
        : this(databaseOptions, adminIdentity, repository, timeProvider, logger, configureContext: null)
    {
    }

    /// <param name="configureContext">A test seam to add interceptors to the per-operation context.</param>
    internal ManagementBearerSessionService(
        DatabaseOptions databaseOptions,
        AdminIdentityOptions adminIdentity,
        IManagementBearerSessionRepository repository,
        TimeProvider timeProvider,
        ILogger<ManagementBearerSessionService> logger,
        Action<DbContextOptionsBuilder>? configureContext)
    {
        var builder = new DbContextOptionsBuilder<IdentityDbContext>();
        builder.UseIdentityDatabase(databaseOptions, enableRetryOnFailure: false);
        configureContext?.Invoke(builder);
        _contextOptions = builder.Options;
        _adminIdentity = adminIdentity;
        _repository = repository;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <summary>
    /// Issues a credential for <paramref name="accountId"/>. The caller must only pass an account
    /// that has just been authenticated as the bootstrap administrator.
    /// </summary>
    public async Task<ManagementBearerIssueResult> IssueAsync(Guid accountId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var token = ManagementBearerToken.Generate();
        var now = Now();
        var session = new ManagementBearerSessionEntity
        {
            Id = Guid.NewGuid(),
            TokenDigest = ManagementBearerToken.ComputeDigest(token),
            AccountId = accountId,
            CreatedAt = now,
            ExpiresAt = now + Lifetime
        };

        try
        {
            await using (var db = new IdentityDbContext(_contextOptions))
            {
                await _repository.AddAsync(db, session, cancellationToken);
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
        catch (Exception exception) when (IsCallerCancellation(exception, cancellationToken))
        {
            throw Canceled(exception, cancellationToken);
        }
        catch (Exception exception) when (IsStorageFailure(exception))
        {
            _logger.LogWarning("Management bearer issuance unavailable");
            return ManagementBearerIssueResult.Unavailable;
        }

        _logger.LogInformation("Management bearer session issued");
        return ManagementBearerIssueResult.Issued(token, session.ExpiresAt);
    }

    public async Task<ManagementBearerValidationResult> ValidateAsync(string? token, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!ManagementBearerToken.IsWellFormed(token))
        {
            return ManagementBearerValidationResult.Rejected(ManagementBearerRejectionReason.Malformed);
        }

        var digest = ManagementBearerToken.ComputeDigest(token!);
        try
        {
            await using var db = new IdentityDbContext(_contextOptions);
            var session = await _repository.FindByDigestAsync(db, digest, cancellationToken);
            var now = Now();
            ManagementBearerValidationResult result;
            if (session is null)
            {
                result = ManagementBearerValidationResult.Rejected(ManagementBearerRejectionReason.NotFound);
            }
            else if (session.RevokedAt is not null)
            {
                result = ManagementBearerValidationResult.Rejected(ManagementBearerRejectionReason.Revoked);
            }
            else if (now >= session.ExpiresAt)
            {
                result = ManagementBearerValidationResult.Rejected(ManagementBearerRejectionReason.Expired);
            }
            else
            {
                var operatorName = await FindEligibleOperatorAsync(db, session.AccountId, cancellationToken);
                result = operatorName is null
                    ? ManagementBearerValidationResult.Rejected(ManagementBearerRejectionReason.NotEligible)
                    : ManagementBearerValidationResult.Valid(session.AccountId, operatorName);
            }

            cancellationToken.ThrowIfCancellationRequested();
            return result;
        }
        catch (Exception exception) when (IsCallerCancellation(exception, cancellationToken))
        {
            throw Canceled(exception, cancellationToken);
        }
        catch (Exception exception) when (IsStorageFailure(exception))
        {
            _logger.LogWarning("Management bearer validation unavailable");
            return ManagementBearerValidationResult.Unavailable;
        }
    }

    /// <summary>
    /// Revokes an active credential. Only the first revocation writes its instant; a repeated,
    /// unknown, expired, or malformed credential answers <see cref="ManagementBearerRevocationResult.NotActive"/>.
    /// </summary>
    public async Task<ManagementBearerRevocationResult> RevokeAsync(string? token, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!ManagementBearerToken.IsWellFormed(token))
        {
            return ManagementBearerRevocationResult.NotActive;
        }

        var digest = ManagementBearerToken.ComputeDigest(token!);
        int affected;
        try
        {
            await using (var db = new IdentityDbContext(_contextOptions))
            {
                affected = await _repository.RevokeAsync(db, digest, Now(), cancellationToken);
            }

            cancellationToken.ThrowIfCancellationRequested();
        }
        catch (Exception exception) when (IsCallerCancellation(exception, cancellationToken))
        {
            throw Canceled(exception, cancellationToken);
        }
        catch (Exception exception) when (IsStorageFailure(exception))
        {
            _logger.LogWarning("Management bearer revocation unavailable");
            return ManagementBearerRevocationResult.Unavailable;
        }

        if (affected == 0)
        {
            return ManagementBearerRevocationResult.NotActive;
        }

        _logger.LogInformation("Management bearer session revoked");
        return ManagementBearerRevocationResult.Revoked;
    }

    /// <summary>
    /// Deletes one bounded batch of long-expired sessions. A storage failure propagates to the
    /// cleanup caller; the caller's cancellation surfaces with the caller's token.
    /// </summary>
    public async Task<int> CleanupExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            await using var db = new IdentityDbContext(_contextOptions);
            var deleted = await _repository.DeleteExpiredAsync(db, Truncate(now), cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return deleted;
        }
        catch (Exception exception) when (IsCallerCancellation(exception, cancellationToken))
        {
            throw Canceled(exception, cancellationToken);
        }
    }

    private async Task<string?> FindEligibleOperatorAsync(IdentityDbContext db, Guid accountId, CancellationToken cancellationToken)
    {
        var configured = _adminIdentity.Username;
        if (string.IsNullOrWhiteSpace(configured))
        {
            return null;
        }

        return await _repository.FindActiveCredentialUsernameAsync(
            db,
            accountId,
            IdentityValueNormalizer.Normalize(configured.Trim()),
            cancellationToken);
    }

    private DateTimeOffset Now() => Truncate(_timeProvider.GetUtcNow());

    private static DateTimeOffset Truncate(DateTimeOffset value)
    {
        var utc = value.ToUniversalTime();
        return new DateTimeOffset(utc.Ticks - utc.Ticks % TimeSpan.TicksPerMicrosecond, TimeSpan.Zero);
    }

    private static bool IsCallerCancellation(Exception exception, CancellationToken cancellationToken) =>
        cancellationToken.IsCancellationRequested
        && (exception is OperationCanceledException || IsStorageFailure(exception));

    private static Exception Canceled(Exception exception, CancellationToken cancellationToken) =>
        exception is OperationCanceledException canceled && canceled.CancellationToken == cancellationToken
            ? canceled
            : new OperationCanceledException(cancellationToken);

    // The original exception is dropped: provider messages can carry the host, constraint names,
    // or parameter values. The PostgreSQL provider's non-retrying strategy wraps a transient
    // failure in an InvalidOperationException that only advises enabling retries.
    private static bool IsStorageFailure(Exception exception) =>
        exception is DbException or DbUpdateException or TimeoutException or OperationCanceledException
        || exception is InvalidOperationException { InnerException: DbException or TimeoutException };
}
