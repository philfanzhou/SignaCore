using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace SignaCore.Database.Migrations.Sqlite;

public sealed class SqliteIdentityDbContextFactory
    : IDesignTimeDbContextFactory<IdentityDbContext>
{
    public IdentityDbContext CreateDbContext(string[] args)
    {
        var databaseOptions = new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = Environment.GetEnvironmentVariable("Database__ConnectionString")
                ?? "Data Source=signacore-migrations.db"
        };

        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(databaseOptions);
        return new IdentityDbContext(optionsBuilder.Options);
    }
}
