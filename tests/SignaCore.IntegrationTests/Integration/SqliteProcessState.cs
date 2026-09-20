using Microsoft.Data.Sqlite;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>Holds the collection name constant of the process-wide SQLite state contract.</summary>
public static class SqliteProcessState
{
    /// <summary>
    /// The name of the one xUnit collection that serializes every test class touching
    /// process-wide SQLite state. xUnit runs classes of different collections in parallel and
    /// classes of the same collection sequentially, so mutual exclusion between two groups is
    /// only expressible by putting both groups into this single collection.
    /// </summary>
    public const string CollectionName = "sqlite-process-state";
}

/// <summary>
/// The mutual-exclusion contract of process-wide SQLite state (issue #293).
/// <para>
/// <see cref="SqliteConnection.ClearAllPools"/> is a process-global side effect: when a
/// parallel class's disposal closes the last pooled connection of a database another class is
/// using, SQLite checkpoints and removes that database's <c>-wal</c>/<c>-shm</c> sidecars, and
/// an in-flight host's pooled reads can fail mid-request. That single mechanism produced all
/// three registered interference paths: the Setup-gate 503 in
/// <c>ManagementSessionContractTests</c> (path A), the fresh-database continuation drift in
/// <c>SqliteDatabaseContractTests</c> (path B), and the hot-WAL shared-candidate check in
/// <c>AdminBootstrapReplacementTests</c> (path C).
/// </para>
/// <para>
/// The contract: every class that clears the pools — marked with
/// <see cref="UsesProcessWideSqlitePoolClearingAttribute"/> — and the classes that depend on
/// host connections staying alive, on hot WAL sidecars, or on shared-fixture installation
/// state run inside <see cref="SqliteProcessState.CollectionName"/>, never in parallel with
/// each other. Every consumer of <c>IdentityServerFixture</c> clears the pools through the
/// fixture's disposal, so consumers are auto-enumerated from the
/// <c>IClassFixture&lt;IdentityServerFixture&gt;</c> interface:
/// <c>SqliteProcessStateContractTests</c> asserts the membership mechanically from that
/// interface, not from the marker alone, so a class cannot slip out of the contract by
/// forgetting both annotations.
/// </para>
/// </summary>
[CollectionDefinition(SqliteProcessState.CollectionName)]
public sealed class SqliteProcessStateCollection;

/// <summary>
/// Marks a test class as performing the process-wide pool clear through the single auditable
/// entry — directly, or through the disposal of the <c>IdentityServerFixture</c> it consumes.
/// Every marked class is asserted to run in the
/// <see cref="SqliteProcessState.CollectionName"/> collection, and every fixture consumer is
/// asserted to carry the marker.
/// </summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class UsesProcessWideSqlitePoolClearingAttribute : Attribute;

/// <summary>
/// The single auditable entry for the process-wide SQLite pool clear. Test classes must call
/// this instead of <see cref="SqliteConnection.ClearAllPools"/> directly, so the process-global
/// side effects stay enumerable and the collection contract can be reviewed in one place.
/// </summary>
public static class TestSqlitePools
{
    public static void ClearAll() => SqliteConnection.ClearAllPools();
}
