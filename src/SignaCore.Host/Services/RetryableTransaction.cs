using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using SignaCore.Database;

namespace SignaCore.Host.Services;

/// <summary>
/// The host's one retryable-transaction envelope for multi-statement units: the whole unit runs
/// inside <c>CreateExecutionStrategy()</c> (PostgreSQL enables <c>EnableRetryOnFailure()</c>,
/// <c>PS-22</c>), a retried unit restarts from a cleared change tracker, and the explicit
/// transaction commits or rolls back as one. The work body keeps its own SaveChanges, Commit, and
/// Rollback calls, so a unit that commits without SaveChanges or rolls back conditionally stays
/// explicit at the point where it happens.
/// </summary>
internal static class RetryableTransaction
{
    public static Task ExecuteTransactionalAsync(
        this IdentityDbContext dbContext,
        Func<IDbContextTransaction, CancellationToken, Task> operation,
        CancellationToken cancellationToken) =>
        ExecuteTransactionalAsync<object?>(
            dbContext,
            async (transaction, token) =>
            {
                await operation(transaction, token);
                return null;
            },
            cancellationToken);

    public static Task<T> ExecuteTransactionalAsync<T>(
        this IdentityDbContext dbContext,
        Func<IDbContextTransaction, CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        var strategy = dbContext.Database.CreateExecutionStrategy();
        return strategy.ExecuteAsync(
            async operationToken =>
            {
                dbContext.ChangeTracker.Clear();
                await using var transaction =
                    await dbContext.Database.BeginTransactionAsync(operationToken);
                return await operation(transaction, operationToken);
            },
            cancellationToken);
    }
}
