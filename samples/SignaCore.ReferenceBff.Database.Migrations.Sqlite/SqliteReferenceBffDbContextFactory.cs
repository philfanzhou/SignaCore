using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace SignaCore.ReferenceBff.Database.Migrations.Sqlite;

/// <summary>
/// Design-time factory for the SQLite migration history of the reference BFF database.
/// </summary>
public sealed class SqliteReferenceBffDbContextFactory
    : IDesignTimeDbContextFactory<ReferenceBffDbContext>
{
    public ReferenceBffDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("ReferenceBffDatabase__ConnectionString")
            ?? "Data Source=signacore-reference-bff-migrations.db";

        var optionsBuilder = new DbContextOptionsBuilder<ReferenceBffDbContext>();
        optionsBuilder.UseReferenceBffSqlite(connectionString);
        return new ReferenceBffDbContext(optionsBuilder.Options);
    }
}
