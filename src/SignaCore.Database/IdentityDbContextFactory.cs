using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace SignaCore.Database;

public class IdentityDbContextFactory : IDesignTimeDbContextFactory<IdentityDbContext>
{
    public IdentityDbContext CreateDbContext(string[] args)
    {
        var databaseOptions = new DatabaseOptions
        {
            Provider = Environment.GetEnvironmentVariable("Database__Provider")
                ?? "PostgreSQL",
            ServerVersion = Environment.GetEnvironmentVariable(
                    "Database__ServerVersion")
                ?? "15",
            ConnectionString = Environment.GetEnvironmentVariable(
                    "Database__ConnectionString")
                ?? "Host=localhost;Database=signacore;Username=postgres;Password=postgres"
        };

        if (databaseOptions.ProviderKind != DatabaseProvider.PostgreSql)
        {
            throw new InvalidOperationException(
                "PostgreSQL migrations require Database__Provider=PostgreSQL.");
        }

        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(databaseOptions);

        return new IdentityDbContext(optionsBuilder.Options);
    }
}
