using Microsoft.EntityFrameworkCore;

namespace SignaCore.Database;

public static class IdentityDatabaseOptionsExtensions
{
    /// <param name="enableRetryOnFailure">
    /// Whether the PostgreSQL provider retries transient connection failures. The default keeps the
    /// historical retrying strategy. The first-run setup completion transaction must pass
    /// <c>false</c>: a retrying strategy replays a caller-opened transaction whole, which the shared
    /// setup entry contract forbids (one attempt, then the caller retries).
    /// </param>
    public static DbContextOptionsBuilder UseIdentityDatabase(
        this DbContextOptionsBuilder optionsBuilder,
        DatabaseOptions databaseOptions,
        bool enableRetryOnFailure = true)
    {
        databaseOptions.Validate();

        return databaseOptions.ProviderKind switch
        {
            DatabaseProvider.PostgreSql => optionsBuilder.UseNpgsql(
                databaseOptions.ConnectionString,
                providerOptions =>
                {
                    providerOptions.MigrationsAssembly(typeof(IdentityDbContext).Assembly.FullName);
                    if (enableRetryOnFailure)
                    {
                        providerOptions.EnableRetryOnFailure(
                            maxRetryCount: 3,
                            maxRetryDelay: TimeSpan.FromSeconds(4),
                            errorCodesToAdd: null);
                    }
                }),
            DatabaseProvider.Sqlite => optionsBuilder.UseSqlite(
                databaseOptions.ConnectionString,
                providerOptions => providerOptions.MigrationsAssembly(
                    "SignaCore.Database.Migrations.Sqlite")),
            _ => throw new InvalidOperationException("Unsupported database provider.")
        };
    }
}
