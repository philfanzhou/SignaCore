using Microsoft.EntityFrameworkCore;

namespace SignaCore.Database;

public static class IdentityDatabaseOptionsExtensions
{
    public static DbContextOptionsBuilder UseIdentityDatabase(
        this DbContextOptionsBuilder optionsBuilder,
        DatabaseOptions databaseOptions)
    {
        databaseOptions.Validate();

        return databaseOptions.ProviderKind switch
        {
            DatabaseProvider.PostgreSql => optionsBuilder.UseNpgsql(
                databaseOptions.ConnectionString,
                providerOptions =>
                {
                    providerOptions.MigrationsAssembly(typeof(IdentityDbContext).Assembly.FullName);
                    providerOptions.EnableRetryOnFailure(
                        maxRetryCount: 3,
                        maxRetryDelay: TimeSpan.FromSeconds(4),
                        errorCodesToAdd: null);
                }),
            DatabaseProvider.Sqlite => optionsBuilder.UseSqlite(
                databaseOptions.ConnectionString,
                providerOptions => providerOptions.MigrationsAssembly(
                    "SignaCore.Database.Migrations.Sqlite")),
            _ => throw new InvalidOperationException("Unsupported database provider.")
        };
    }
}
