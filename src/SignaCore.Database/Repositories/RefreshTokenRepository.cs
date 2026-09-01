using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly IdentityDbContext _dbContext;

    public RefreshTokenRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<RefreshTokenEntity?> GetByTokenValueAsync(
        string tokenValue,
        CancellationToken cancellationToken = default)
    {
        var tokenDigest = RefreshTokenDigest.Compute(tokenValue);
        return await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(r => r.TokenValue == tokenDigest, cancellationToken);
    }

    public Task AddAsync(
        RefreshTokenEntity refreshToken,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        refreshToken.TokenValue = RefreshTokenDigest.EnsureDigest(refreshToken.TokenValue);
        _dbContext.RefreshTokens.Add(refreshToken);
        return Task.CompletedTask;
    }

    public async Task<bool> TryRevokeAsync(
        string tokenValue,
        CancellationToken cancellationToken = default)
    {
        var tokenDigest = RefreshTokenDigest.Compute(tokenValue);
        var affectedRows = await _dbContext.RefreshTokens
            .Where(token => token.TokenValue == tokenDigest && !token.IsRevoked)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(token => token.IsRevoked, true), cancellationToken);
        return affectedRows == 1;
    }

    /// <summary>
    /// The comparison is exact equality rather than normalization: both sides come from the same
    /// column, app_registrations.app_id — issuance writes <c>app.AppId</c>, and the identity of the
    /// revoking party is the same <c>app.AppId</c> resolved by gateway authentication. On top of
    /// that, <c>IdentityValueNormalizer.Normalize</c> does not translate to SQL, so putting it here
    /// would drag the whole query to client-side evaluation.
    /// </summary>
    public async Task<bool> TryRevokeForAppAsync(
        string tokenValue,
        string appId,
        CancellationToken cancellationToken = default)
    {
        var tokenDigest = RefreshTokenDigest.Compute(tokenValue);
        var affectedRows = await _dbContext.RefreshTokens
            .Where(token => token.TokenValue == tokenDigest
                && !token.IsRevoked
                && token.AppId == appId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(token => token.IsRevoked, true), cancellationToken);
        return affectedRows == 1;
    }

    /// <summary>
    /// Rotates a refresh token in one step: revoking the old token and inserting its replacement
    /// happen inside the same transaction and succeed or fail atomically.
    /// <para>
    /// The explicit transaction <b>must</b> run as a whole inside <c>CreateExecutionStrategy()</c>.
    /// PostgreSQL enables <c>EnableRetryOnFailure()</c> (see
    /// <see cref="IdentityDatabaseOptionsExtensions"/>), and the retrying strategy refuses to run
    /// commands inside a transaction the caller started itself: calling
    /// <c>BeginTransactionAsync</c> directly makes the first command throw
    /// <c>InvalidOperationException: ... does not support user-initiated transactions</c>, which
    /// ExceptionHandlingMiddleware turns into an HTTP 409 and takes the whole refresh flow down.
    /// SQLite does not enable retries and gets a NonRetryingExecutionStrategy, so the lambda runs
    /// exactly once and the behaviour is unchanged.
    /// </para>
    /// <para>
    /// The lambda is replayed as a whole, so every step inside it has to be written as if it may run
    /// again; nothing may be lifted out of it.
    /// </para>
    /// </summary>
    public async Task<bool> TryRotateAsync(
        string tokenValue,
        RefreshTokenEntity replacement,
        CancellationToken cancellationToken = default)
    {
        var tokenDigest = RefreshTokenDigest.Compute(tokenValue);
        replacement.TokenValue = RefreshTokenDigest.EnsureDigest(replacement.TokenValue);
        var executionStrategy = _dbContext.Database.CreateExecutionStrategy();
        return await executionStrategy.ExecuteAsync(async operationCancellationToken =>
        {
            await using var transaction = await _dbContext.Database.BeginTransactionAsync(
                operationCancellationToken);

            // The concurrency semantics come from this conditional update plus the lock the
            // transaction holds: when two requests rotate the same token at once, the later one
            // blocks on the row lock, re-evaluates is_revoked after the first commits, matches 0
            // rows, and returns false.
            var affectedRows = await _dbContext.RefreshTokens
                .Where(token => token.TokenValue == tokenDigest && !token.IsRevoked)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(token => token.IsRevoked, true), operationCancellationToken);

            if (affectedRows != 1)
            {
                // On the retry path, the replacement may already have been added by a previous
                // attempt. A rollback does not clear the ChangeTracker, so without detaching it
                // explicitly any later SaveChanges in this request would persist a token that must
                // not exist.
                _dbContext.Entry(replacement).State = EntityState.Detached;
                await transaction.RollbackAsync(operationCancellationToken);
                return false;
            }

            _dbContext.RefreshTokens.Add(replacement);

            // acceptAllChangesOnSuccess: false — pending state is not marked as saved until the
            // commit has succeeded. Otherwise the replacement would become Unchanged right after
            // SaveChanges, and if the commit failed and triggered a retry the replay would not
            // insert it again, leaving the half-finished state of "old token revoked, replacement
            // lost".
            await _dbContext.SaveChangesAsync(
                acceptAllChangesOnSuccess: false,
                operationCancellationToken);
            await transaction.CommitAsync(operationCancellationToken);
            _dbContext.ChangeTracker.AcceptAllChanges();
            return true;
        }, cancellationToken);
    }

    public Task RemoveRangeAsync(
        IEnumerable<RefreshTokenEntity> tokens,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.RefreshTokens.RemoveRange(tokens);
        return Task.CompletedTask;
    }

    public async Task<int> RemoveExpiredAndRevokedAsync(
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        return await _dbContext.RefreshTokens
            .Where(r => r.IsRevoked || r.ExpiresAt < now)
            .ExecuteDeleteAsync(cancellationToken);
    }
}
