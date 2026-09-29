using Microsoft.EntityFrameworkCore;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public class AuthorizationRequestRepository : IAuthorizationRequestRepository
{
    private readonly IdentityDbContext _dbContext;

    public AuthorizationRequestRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public Task AddAsync(
        AuthorizationRequestEntity request,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        request.HandleDigest = LoginHandleDigest.EnsureDigest(request.HandleDigest);
        _dbContext.AuthorizationRequests.Add(request);
        return Task.CompletedTask;
    }

    public async Task<AuthorizationRequestEntity?> GetActiveByHandleDigestAsync(
        string handleDigest,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext.AuthorizationRequests
            .AsNoTracking()
            .FirstOrDefaultAsync(
                request => request.HandleDigest == handleDigest
                    && request.ConsumedAt == null
                    && request.ExpiresAt > now,
                cancellationToken);
    }

    /// <summary>
    /// The concurrency semantics mirror <see cref="RefreshTokenRepository.TryRotateAsync"/>: the
    /// conditional update plus the lock its transaction holds make a second concurrent consumer
    /// block, re-evaluate <c>consumed_at</c>/<c>expires_at</c> after the first commit, match zero
    /// rows, and return <c>false</c>. The explicit transaction runs as a whole inside
    /// <c>CreateExecutionStrategy()</c> because PostgreSQL enables <c>EnableRetryOnFailure()</c>
    /// (<c>PS-22</c>).
    /// </summary>
    public async Task<bool> TryConsumeAsync(
        string handleDigest,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        // Consumption inside a caller-owned transaction (the EV-01 success transaction) joins it and
        // leaves the only commit to the caller.
        if (_dbContext.Database.CurrentTransaction is not null)
        {
            var ambientAffectedRows = await _dbContext.AuthorizationRequests
                .Where(request => request.HandleDigest == handleDigest
                    && request.ConsumedAt == null
                    && request.ExpiresAt > now)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(request => request.ConsumedAt, now), cancellationToken);
            return ambientAffectedRows == 1;
        }

        var executionStrategy = _dbContext.Database.CreateExecutionStrategy();
        return await executionStrategy.ExecuteAsync(async operationCancellationToken =>
        {
            await using var transaction = await _dbContext.Database.BeginTransactionAsync(
                operationCancellationToken);

            var affectedRows = await _dbContext.AuthorizationRequests
                .Where(request => request.HandleDigest == handleDigest
                    && request.ConsumedAt == null
                    && request.ExpiresAt > now)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(request => request.ConsumedAt, now), operationCancellationToken);

            if (affectedRows != 1)
            {
                await transaction.RollbackAsync(operationCancellationToken);
                return false;
            }

            await transaction.CommitAsync(operationCancellationToken);
            return true;
        }, cancellationToken);
    }

    /// <summary>
    /// One statement, outside any explicit transaction, so it auto-commits on both providers before
    /// the caller reads anything else (<c>PS-03</c>). Under the PostgreSQL retry strategy a
    /// connection lost after the commit may replay the statement: the count can then over-count by
    /// one, which only shrinks the budget and never admits an extra send.
    /// </summary>
    public async Task<bool> TryTakeSmsCodeSendSlotAsync(
        string handleDigest,
        DateTimeOffset now,
        int maximum,
        CancellationToken cancellationToken = default)
    {
        if (_dbContext.Database.CurrentTransaction is not null)
        {
            throw new InvalidOperationException(
                "The SMS send budget update must auto-commit outside any caller transaction.");
        }

        var affectedRows = await _dbContext.AuthorizationRequests
            .Where(request => request.HandleDigest == handleDigest
                && request.ConsumedAt == null
                && request.ExpiresAt > now
                && request.SmsCodeSendCount < maximum)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(request => request.SmsCodeSendCount, request => request.SmsCodeSendCount + 1),
                cancellationToken);
        return affectedRows == 1;
    }

    public async Task<int> RemoveExpiredBeforeAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default)
    {
        var executionStrategy = _dbContext.Database.CreateExecutionStrategy();
        return await executionStrategy.ExecuteAsync(async operationCancellationToken =>
        {
            await using var transaction = await _dbContext.Database.BeginTransactionAsync(
                operationCancellationToken);

            var deletedRows = await _dbContext.AuthorizationRequests
                .Where(request => request.ExpiresAt <= cutoff)
                .ExecuteDeleteAsync(operationCancellationToken);

            await transaction.CommitAsync(operationCancellationToken);
            return deletedRows;
        }, cancellationToken);
    }
}
