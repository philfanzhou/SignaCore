using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace QuantumZhou.Identity.Database.Migrations.Sqlite;

public sealed class SqliteIdentityDbContextFactory
    : IDesignTimeDbContextFactory<IdentityDbContext>
{
    public IdentityDbContext CreateDbContext(string[] args)
    {
        var databaseOptions = new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = Environment.GetEnvironmentVariable("Database__ConnectionString")
                ?? "Data Source=quantumzhou-identity-migrations.db"
        };

        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(databaseOptions);
        return new IdentityDbContext(optionsBuilder.Options);
    }
}
