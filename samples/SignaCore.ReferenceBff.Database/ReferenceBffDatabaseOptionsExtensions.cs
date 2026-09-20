using Microsoft.EntityFrameworkCore;

namespace SignaCore.ReferenceBff.Database;

/// <summary>
/// Provider wiring for the reference BFF's own database. The PostgreSQL migration history lives in
/// this assembly; the SQLite history lives in
/// <see cref="SqliteMigrationsAssemblyName"/>. No retrying execution strategy is configured: the
/// binding write is a caller-owned, single-attempt transaction.
/// </summary>
public static class ReferenceBffDatabaseOptionsExtensions
{
    /// <summary>The assembly that carries the reference BFF's SQLite migration history.</summary>
    public const string SqliteMigrationsAssemblyName = "SignaCore.ReferenceBff.Database.Migrations.Sqlite";

    /// <summary>Wires the PostgreSQL provider with this assembly as its migration history.</summary>
    public static DbContextOptionsBuilder<ReferenceBffDbContext> UseReferenceBffPostgreSql(
        this DbContextOptionsBuilder<ReferenceBffDbContext> optionsBuilder,
        string connectionString) =>
        optionsBuilder.UseNpgsql(
            connectionString,
            providerOptions => providerOptions.MigrationsAssembly(
                typeof(ReferenceBffDbContext).Assembly.FullName));

    /// <summary>Wires the SQLite provider with the dedicated SQLite assembly as its migration history.</summary>
    public static DbContextOptionsBuilder<ReferenceBffDbContext> UseReferenceBffSqlite(
        this DbContextOptionsBuilder<ReferenceBffDbContext> optionsBuilder,
        string connectionString) =>
        optionsBuilder.UseSqlite(
            connectionString,
            providerOptions => providerOptions.MigrationsAssembly(SqliteMigrationsAssemblyName));
}
