using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace QuantumZhou.Identity.Database.Migrations.MySql;

public sealed class MySqlIdentityDbContextFactory
    : IDesignTimeDbContextFactory<IdentityDbContext>
{
    public IdentityDbContext CreateDbContext(string[] args)
    {
        var databaseOptions = new DatabaseOptions
        {
            Provider = Environment.GetEnvironmentVariable("Database__Provider") ?? "MySQL",
            ServerVersion = Environment.GetEnvironmentVariable("Database__ServerVersion") ?? "8.4",
            ConnectionString = Environment.GetEnvironmentVariable("Database__ConnectionString")
                ?? "Server=localhost;Database=quantumzhou_identity;User=root;Password=development"
        };

        if (databaseOptions.ProviderKind is not (DatabaseProvider.MySql or DatabaseProvider.MariaDb))
        {
            throw new InvalidOperationException(
                "MySQL migrations require Database__Provider to be MySQL or MariaDB.");
        }

        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(databaseOptions);
        return new IdentityDbContext(optionsBuilder.Options);
    }
}
