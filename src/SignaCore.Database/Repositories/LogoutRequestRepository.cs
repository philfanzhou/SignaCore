using Microsoft.EntityFrameworkCore;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface ILogoutRequestRepository
{
    Task AddAsync(
        LogoutRequestEntity request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the active (unconsumed, unexpired at <paramref name="now"/>) row of a handle
    /// digest, or <c>null</c> — the single "unavailable" answer a missing, expired, or consumed
    /// row shares (<c>IN-35</c>/<c>SC-18</c>).
    /// </summary>
    Task<LogoutRequestEntity?> GetActiveByHandleDigestAsync(
        string handleDigest,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Locks the row for a caller-owned completion transaction. Requires an active ambient
    /// transaction; PostgreSQL takes an explicit <c>FOR UPDATE</c> lock, SQLite relies on its
    /// single-writer serialization. Returns a no-tracking snapshot or <c>null</c> when missing.
    /// </summary>
    /// <exception cref="InvalidOperationException">No ambient transaction exists.</exception>
    Task<LogoutRequestEntity?> LockByIdAsync(
        Guid requestId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically consumes the active row of a handle digest at <paramref name="now"/>: the
    /// conditional update plus the lock its transaction holds make a second consumer observe
    /// <c>false</c>. Inside a caller-owned transaction it joins it and leaves the commit to the
    /// caller (<c>EV-06</c>/<c>EV-07</c>).
    /// </summary>
    Task<bool> TryConsumeAsync(
        string handleDigest,
        DateTimeOffset now,
        CancellationToken cancellationToken = default);

    Task<int> RemoveExpiredBeforeAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default);
}

public class LogoutRequestRepository : ILogoutRequestRepository
{
    private const string SqliteProviderName = "Microsoft.EntityFrameworkCore.Sqlite";

    private readonly IdentityDbContext _dbContext;

    public LogoutRequestRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public Task AddAsync(
        LogoutRequestEntity request,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        request.HandleDigest = LoginHandleDigest.EnsureDigest(request.HandleDigest);
        _dbContext.LogoutRequests.Add(request);
        return Task.CompletedTask;
    }

    public async Task<LogoutRequestEntity?> GetActiveByHandleDigestAsync(
        string handleDigest,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext.LogoutRequests
            .AsNoTracking()
            .FirstOrDefaultAsync(
                request => request.HandleDigest == handleDigest
                    && request.ConsumedAt == null
                    && request.ExpiresAt > now,
                cancellationToken);
    }

    /// <summary>
    /// Follows the <see cref="AuthorizationCodeRepository.LockByIdAsync"/> precedent: the
    /// completion transaction locks the session first (<c>EV-28</c>), then this request row.
    /// </summary>
    public async Task<LogoutRequestEntity?> LockByIdAsync(
        Guid requestId,
        CancellationToken cancellationToken = default)
    {
        if (_dbContext.Database.CurrentTransaction is null)
        {
            throw new InvalidOperationException(
                "Locking a logout request requires a caller-owned ambient transaction; none is active.");
        }

        if (string.Equals(
                _dbContext.Database.ProviderName,
                SqliteProviderName,
                StringComparison.Ordinal))
        {
            return await _dbContext.LogoutRequests
                .AsNoTracking()
                .FirstOrDefaultAsync(request => request.Id == requestId, cancellationToken);
        }

        var rows = await _dbContext.LogoutRequests
            .FromSqlInterpolated(
                $"SELECT * FROM logout_requests WHERE id = {requestId} FOR UPDATE")
            .AsNoTracking()
            .ToListAsync(cancellationToken);

        return rows.FirstOrDefault();
    }

    public async Task<bool> TryConsumeAsync(
        string handleDigest,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        // Consumption inside a caller-owned completion transaction joins it and leaves the only
        // commit to the caller.
        if (_dbContext.Database.CurrentTransaction is not null)
        {
            return await ExecuteConsumeAsync(handleDigest, now, cancellationToken) == 1;
        }

        var executionStrategy = _dbContext.Database.CreateExecutionStrategy();
        return await executionStrategy.ExecuteAsync(async operationCancellationToken =>
        {
            await using var transaction = await _dbContext.Database.BeginTransactionAsync(
                operationCancellationToken);

            var affectedRows = await ExecuteConsumeAsync(handleDigest, now, operationCancellationToken);
            if (affectedRows != 1)
            {
                await transaction.RollbackAsync(operationCancellationToken);
                return false;
            }

            await transaction.CommitAsync(operationCancellationToken);
            return true;
        }, cancellationToken);
    }

    private Task<int> ExecuteConsumeAsync(
        string handleDigest,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        return _dbContext.LogoutRequests
            .Where(request => request.HandleDigest == handleDigest
                && request.ConsumedAt == null
                && request.ExpiresAt > now)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(request => request.ConsumedAt, now),
                cancellationToken);
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

            var deletedRows = await _dbContext.LogoutRequests
                .Where(request => request.ExpiresAt <= cutoff)
                .ExecuteDeleteAsync(operationCancellationToken);

            await transaction.CommitAsync(operationCancellationToken);
            return deletedRows;
        }, cancellationToken);
    }
}
