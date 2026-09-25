using Npgsql;

namespace SignaCore.Database.RateLimiting;

/// <summary>
/// The PostgreSQL implementation of the PS-24 shared budget. Every call opens its own short
/// connection from a private <see cref="NpgsqlDataSource"/> and runs exactly one auto-committed
/// statement.
/// <para>
/// It deliberately bypasses <see cref="IdentityDbContext"/> and every EF execution strategy: a
/// dropped connection or a terminated backend is a transient error that a retrying strategy would
/// replay, counting one request twice or letting an unknown commit through. Here the statement
/// runs once; any failure the store cannot attribute to the caller answers
/// <see cref="OidcRateLimitAcquireResult.Unavailable"/> without the original exception, whose
/// message can name the database host.
/// </para>
/// <para>
/// Caller cancellation wins at every boundary — before the statement, while it waits for a row
/// lock, and after it returned — and surfaces as an <see cref="OperationCanceledException"/>
/// carrying the caller's token. A statement that committed before the cancellation was observed
/// keeps its permit: an unknown outcome may burn a permit but never grants one.
/// </para>
/// <para>SQLite has no shared implementation; constructing this store for it fails.</para>
/// </summary>
public sealed class PostgreSqlOidcRateLimitStore : IOidcRateLimitStore, IAsyncDisposable, IDisposable
{
    // One conditional UPSERT decides first use, window renewal, increment and rejection under the
    // row lock with the database clock. No returned row means the budget of an unexpired window is
    // exhausted; the rejected path writes nothing, so it never extends the window.
    private const string AcquireSql =
        """
        INSERT INTO oidc_rate_limit_buckets AS b (policy, partition_digest, window_expires_at, permit_count)
        VALUES (@policy, @partition_digest, statement_timestamp() + @window, 1)
        ON CONFLICT (policy, partition_digest) DO UPDATE SET
            permit_count = CASE WHEN b.window_expires_at <= statement_timestamp() THEN 1 ELSE b.permit_count + 1 END,
            window_expires_at = CASE WHEN b.window_expires_at <= statement_timestamp()
                THEN statement_timestamp() + @window ELSE b.window_expires_at END
        WHERE b.window_expires_at <= statement_timestamp() OR b.permit_count < @permit_limit
        RETURNING permit_count
        """;

    // The outer predicate is re-evaluated after the row lock is taken, so a row renewed by a
    // concurrent acquisition between the victim selection and the delete survives.
    private const string CleanupSql =
        """
        DELETE FROM oidc_rate_limit_buckets AS b
        USING (
            SELECT policy, partition_digest
            FROM oidc_rate_limit_buckets
            WHERE window_expires_at <= statement_timestamp() - @retention
            ORDER BY window_expires_at
            LIMIT @batch_size
        ) AS victim
        WHERE b.policy = victim.policy
            AND b.partition_digest = victim.partition_digest
            AND b.window_expires_at <= statement_timestamp() - @retention
        """;

    private static readonly TimeSpan Window = TimeSpan.FromSeconds(IdentityConstants.OidcRateLimitWindowSeconds);
    private static readonly TimeSpan Retention = TimeSpan.FromHours(IdentityConstants.OidcRateLimitBucketRetentionHours);

    private readonly NpgsqlDataSource _dataSource;
    private readonly Func<CancellationToken, ValueTask>? _afterStatement;

    public PostgreSqlOidcRateLimitStore(DatabaseOptions databaseOptions)
        : this(databaseOptions, afterStatement: null)
    {
    }

    /// <param name="afterStatement">
    /// A test seam invoked once after the statement really executed and before the outcome is
    /// returned, to inject a lost-commit failure or a late caller cancellation.
    /// </param>
    internal PostgreSqlOidcRateLimitStore(
        DatabaseOptions databaseOptions,
        Func<CancellationToken, ValueTask>? afterStatement)
    {
        ArgumentNullException.ThrowIfNull(databaseOptions);
        databaseOptions.Validate();
        if (databaseOptions.ProviderKind != DatabaseProvider.PostgreSql)
        {
            throw new InvalidOperationException("The shared OIDC rate-limit store requires PostgreSQL.");
        }

        _dataSource = NpgsqlDataSource.Create(databaseOptions.ConnectionString);
        _afterStatement = afterStatement;
    }

    public async Task<OidcRateLimitAcquireResult> AcquireAsync(
        string policy,
        string partitionDigest,
        CancellationToken cancellationToken)
    {
        // Programming errors, never Unavailable; the messages do not echo the rejected value.
        if (!OidcRateLimitBudgets.TryGetPermitLimit(policy, out var permitLimit))
        {
            throw new ArgumentException("The value is not a known OIDC rate-limit policy.", nameof(policy));
        }

        if (!OidcRateLimitBudgets.IsPartitionDigest(partitionDigest))
        {
            throw new ArgumentException(
                "The partition digest must be exactly 64 lowercase hex characters.",
                nameof(partitionDigest));
        }

        var (available, granted) = await ExecuteOnceAsync(
            async (command, token) =>
            {
                command.CommandText = AcquireSql;
                command.Parameters.Add(new NpgsqlParameter<string>("policy", policy));
                command.Parameters.Add(new NpgsqlParameter<string>("partition_digest", partitionDigest));
                command.Parameters.Add(new NpgsqlParameter<TimeSpan>("window", Window));
                command.Parameters.Add(new NpgsqlParameter<int>("permit_limit", permitLimit));
                return await command.ExecuteScalarAsync(token) is not null;
            },
            cancellationToken);

        if (!available)
        {
            return OidcRateLimitAcquireResult.Unavailable;
        }

        return granted ? OidcRateLimitAcquireResult.Granted : OidcRateLimitAcquireResult.Rejected;
    }

    public async Task<int?> DeleteExpiredAsync(CancellationToken cancellationToken)
    {
        var (available, deleted) = await ExecuteOnceAsync(
            (command, token) =>
            {
                command.CommandText = CleanupSql;
                command.Parameters.Add(new NpgsqlParameter<TimeSpan>("retention", Retention));
                command.Parameters.Add(new NpgsqlParameter<int>("batch_size", IdentityConstants.OidcRateLimitCleanupBatchSize));
                return command.ExecuteNonQueryAsync(token);
            },
            cancellationToken);

        return available ? deleted : null;
    }

    public ValueTask DisposeAsync() => _dataSource.DisposeAsync();

    public void Dispose() => _dataSource.Dispose();

    private async Task<(bool Available, T Value)> ExecuteOnceAsync<T>(
        Func<NpgsqlCommand, CancellationToken, Task<T>> statement,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(IdentityConstants.OidcRateLimitStoreTimeoutMilliseconds);
        try
        {
            await using var connection = await _dataSource.OpenConnectionAsync(budget.Token);
            await using var command = connection.CreateCommand();
            var value = await statement(command, budget.Token);
            if (_afterStatement is not null)
            {
                await _afterStatement(budget.Token);
            }

            cancellationToken.ThrowIfCancellationRequested();
            return (true, value);
        }
        catch (OperationCanceledException exception) when (exception.CancellationToken == cancellationToken)
        {
            throw;
        }
        catch (Exception) when (cancellationToken.IsCancellationRequested)
        {
            // The caller's cancellation wins over whatever the interrupted operation reported.
            throw new OperationCanceledException(cancellationToken);
        }
        catch (Exception exception) when (exception is NpgsqlException or TimeoutException or IOException
            || (exception is OperationCanceledException && budget.IsCancellationRequested))
        {
            return (false, default!);
        }
    }
}
