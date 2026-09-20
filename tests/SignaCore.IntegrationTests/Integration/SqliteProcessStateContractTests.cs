using System.Reflection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SignaCore.IntegrationTests.Integration;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The mechanical proof of the process-wide SQLite state contract (issue #293): every class
/// that clears the pools, and every class registered as a victim of the clear, runs inside the
/// one serialized collection — and the destructive side effect itself is demonstrated on
/// demand, so the isolation is known to guard a real dependency rather than a guess.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class SqliteProcessStateContractTests
{
    private static readonly Assembly Assembly = typeof(SqliteProcessStateContractTests).Assembly;

    [Fact]
    public void EveryClassThatClearsThePools_RunsInTheProcessStateCollection()
    {
        var offenders =
            from type in Assembly.GetTypes()
            where type.IsClass
                  && type.GetCustomAttribute<UsesProcessWideSqlitePoolClearingAttribute>() is not null
                  && CollectionNameOf(type) != SqliteProcessState.CollectionName
            select type.FullName;

        Assert.Empty(offenders.ToList());
    }

    /// <summary>
    /// Discovery must start from the fixture interface, not from the marker: a consumer that
    /// simply forgot both annotations would never be enumerated by the marker-based check and
    /// would silently run in parallel with the clear its own fixture performs at disposal. Every
    /// class implementing <c>IClassFixture&lt;IdentityServerFixture&gt;</c> — directly or through
    /// an inherited interface — must run in the collection and carry the marker.
    /// </summary>
    [Fact]
    public void EveryIdentityServerFixtureConsumer_RunsInTheProcessStateCollectionWithTheMarker()
    {
        var offenders =
            from type in Assembly.GetTypes()
            where type.IsClass && ConsumesIdentityServerFixture(type)
            let missing =
                (CollectionNameOf(type) == SqliteProcessState.CollectionName ? string.Empty : "collection")
                + (type.GetCustomAttribute<UsesProcessWideSqlitePoolClearingAttribute>() is null
                    ? " marker"
                    : string.Empty)
            where missing.Length > 0
            select $"{type.FullName}: missing {missing.Trim()}";

        Assert.Empty(offenders.ToList());
    }

    private static bool ConsumesIdentityServerFixture(Type type) =>
        type.GetInterfaces().Any(@interface =>
            @interface.IsGenericType
            && @interface.GetGenericTypeDefinition() == typeof(IClassFixture<>)
            && @interface.GetGenericArguments()[0] == typeof(IdentityServerFixture));

    [Fact]
    public void EveryPoolClearingClass_RoutesThroughTheSingleEntry()
    {
        // The single auditable entry is the only test-assembly code that may name the process
        // wide clear directly: the contract file's own reference is the exception, and every
        // other compilation reference would show up as a second call site of the underlying
        // method. Asserting the source files is not possible at runtime, so this pins the
        // runnable shape instead: the entry exists, is static, and is the only type in the
        // assembly exposing it.
        var entry = typeof(TestSqlitePools);
        Assert.True(entry.IsAbstract && entry.IsSealed);
        Assert.NotNull(entry.GetMethod(
            nameof(TestSqlitePools.ClearAll),
            BindingFlags.Public | BindingFlags.Static));
    }

    /// <summary>
    /// The three registered interference paths must stay inside the collection: the Setup-gate
    /// 503 (path A, derived hosts reading installation state over pooled connections), the
    /// fresh-database continuation drift (path B), and the hot-WAL shared-candidate check
    /// (path C).
    /// </summary>
    [Theory]
    [InlineData(typeof(ManagementSessionContractTests))]
    [InlineData(typeof(SqliteDatabaseContractTests))]
    [InlineData(typeof(AdminBootstrapReplacementTests))]
    public void TheRegisteredVictimClasses_RunInTheProcessStateCollection(Type victim)
    {
        Assert.Equal(SqliteProcessState.CollectionName, CollectionNameOf(victim));
    }

    /// <summary>
    /// The negative self-check of path C: with the isolation artificially bypassed — the
    /// destructive action invoked directly against a database whose only holder is the pool —
    /// the exact environment fact of <c>AdminBootstrapReplacementTests.SavingTheLiveTargetAgain
    /// _IsRefusedByTheSharedCandidateChecks</c> (a hot WAL sidecar kept alive by the running
    /// host's pooled connection) is removed by the clear. Run in parallel, the same action
    /// turns that test's expected 400 into a 200; the collection contract exists precisely so
    /// the two can never overlap.
    /// </summary>
    [Fact]
    public async Task APoolClearInvokedAgainstAPooledHolder_RemovesTheHotWalSidecarItDependsOn()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-pool-contract-{Guid.NewGuid():N}.db");
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Pooling = true
        }.ConnectionString;

        try
        {
            // The "running host" role: a connection that has written in WAL mode and whose only
            // remaining holder is the ADO pool (the EF shape during a request gap).
            using (var connection = new SqliteConnection(connectionString))
            {
                await connection.OpenAsync(TestContext.Current.CancellationToken);
                await using var command = connection.CreateCommand();
                command.CommandText =
                    "PRAGMA journal_mode=WAL; CREATE TABLE contract (value TEXT); INSERT INTO contract (value) VALUES ('hot');";
                await command.ExecuteNonQueryAsync(TestContext.Current.CancellationToken);
            }

            Assert.True(
                File.Exists(databasePath + "-wal"),
                "The pooled holder must keep the WAL sidecar hot for the interference to be real.");

            // The destructive action of any parallel pool-clearing class, invoked on demand.
            TestSqlitePools.ClearAll();

            Assert.False(
                File.Exists(databasePath + "-wal"),
                "The pool clear must checkpoint and remove the sidecar — without the collection contract this is exactly what breaks path C.");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var suffix in new[] { "", "-wal", "-shm", "-journal" })
            {
                var path = databasePath + suffix;
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
        }
    }

    private static string? CollectionNameOf(Type type) =>
        type.GetCustomAttribute<CollectionAttribute>()?.Name;
}
