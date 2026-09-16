using Microsoft.EntityFrameworkCore;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public class AuthorizationCodeRepository : IAuthorizationCodeRepository
{
    private const string SqliteProviderName = "Microsoft.EntityFrameworkCore.Sqlite";

    private readonly IdentityDbContext _dbContext;

    public AuthorizationCodeRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public Task AddAsync(
        AuthorizationCodeEntity code,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        code.CodeDigest = AuthorizationCodeDigest.EnsureDigest(code.CodeDigest);
        _dbContext.AuthorizationCodes.Add(code);
        return Task.CompletedTask;
    }

    public async Task<AuthorizationCodeEntity?> GetByCodeDigestAsync(
        string codeDigest,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext.AuthorizationCodes
            .AsNoTracking()
            .FirstOrDefaultAsync(code => code.CodeDigest == codeDigest, cancellationToken);
    }

    /// <summary>
    /// Follows the <c>IdentitySessionRepository.LockByIdAsync</c> precedent: PostgreSQL takes an
    /// explicit <c>FOR UPDATE</c> row lock that blocks a second locker until this transaction ends,
    /// while SQLite relies on its file-level writer serialization and reads inside the transaction.
    /// Unlike the session lock, the change tracker is not cleared: the canonical lock order locks
    /// the session first (<c>EV-20</c>), and clearing here would detach the caller's tracked
    /// session row. The snapshot is therefore returned no-tracking instead.
    /// </summary>
    public async Task<AuthorizationCodeEntity?> LockByIdAsync(
        Guid codeId,
        CancellationToken cancellationToken = default)
    {
        if (_dbContext.Database.CurrentTransaction is null)
        {
            throw new InvalidOperationException(
                "Locking an authorization code requires a caller-owned ambient transaction; none is active.");
        }

        if (string.Equals(
                _dbContext.Database.ProviderName,
                SqliteProviderName,
                StringComparison.Ordinal))
        {
            return await _dbContext.AuthorizationCodes
                .AsNoTracking()
                .FirstOrDefaultAsync(code => code.Id == codeId, cancellationToken);
        }

        var rows = await _dbContext.AuthorizationCodes
            .FromSqlInterpolated(
                $"SELECT * FROM authorization_codes WHERE id = {codeId} FOR UPDATE")
            .AsNoTracking()
            .ToListAsync(cancellationToken);

        return rows.FirstOrDefault();
    }

    /// <summary>
    /// The concurrency semantics mirror <see cref="AuthorizationRequestRepository.TryConsumeAsync"/>:
    /// the conditional update plus the lock its transaction holds make a second concurrent consumer
    /// block, re-evaluate <c>consumed_at</c>/<c>expires_at</c> after the first commit, match zero
    /// rows, and return <c>false</c>. The explicit transaction runs as a whole inside
    /// <c>CreateExecutionStrategy()</c> because PostgreSQL enables <c>EnableRetryOnFailure()</c>
    /// (<c>PS-22</c>).
    /// </summary>
    public async Task<bool> TryConsumeAsync(
        Guid codeId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        // Consumption inside a caller-owned transaction (the EV-21 redemption transaction) joins it
        // and leaves the only commit to the caller.
        if (_dbContext.Database.CurrentTransaction is not null)
        {
            return await ExecuteConsumeAsync(codeId, now, cancellationToken) == 1;
        }

        var executionStrategy = _dbContext.Database.CreateExecutionStrategy();
        return await executionStrategy.ExecuteAsync(async operationCancellationToken =>
        {
            await using var transaction = await _dbContext.Database.BeginTransactionAsync(
                operationCancellationToken);

            var affectedRows = await ExecuteConsumeAsync(codeId, now, operationCancellationToken);

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
        Guid codeId,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        return _dbContext.AuthorizationCodes
            .Where(code => code.Id == codeId
                && code.ConsumedAt == null
                && now < code.ExpiresAt)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(code => code.ConsumedAt, now),
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

            var deletedRows = await _dbContext.AuthorizationCodes
                .Where(code => code.ExpiresAt <= cutoff)
                .ExecuteDeleteAsync(operationCancellationToken);

            await transaction.CommitAsync(operationCancellationToken);
            return deletedRows;
        }, cancellationToken);
    }
}
