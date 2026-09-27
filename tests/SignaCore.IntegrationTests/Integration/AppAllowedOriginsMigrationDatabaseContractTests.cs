using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SignaCore.Database;
using SignaCore.Database.Entity;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

public sealed class AppAllowedOriginsMigrationDatabaseContractTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task SQLite_UpgradeConstraintsCascadeDownAndUp()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(Ct);
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(connection, provider => provider.MigrationsAssembly(
                "SignaCore.Database.Migrations.Sqlite"))
            .Options;
        await VerifyAsync(options, isSqlite: true);
    }

    [Fact]
    public async Task PostgreSql_UpgradeConstraintsCascadeDownAndUp()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true",
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true for the PostgreSQL migration contract.");
        await using var container = new PostgreSqlBuilder(
            Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE")
            ?? "public.ecr.aws/docker/library/postgres:15-alpine").Build();
        await container.StartAsync(Ct);
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(new DatabaseOptions
        {
            Provider = "PostgreSQL",
            ServerVersion = "15",
            ConnectionString = container.GetConnectionString()
        });
        await VerifyAsync(optionsBuilder.Options, isSqlite: false);
    }

    private static async Task VerifyAsync(DbContextOptions<IdentityDbContext> options, bool isSqlite)
    {
        var appId = Guid.NewGuid();
        string target;
        string previous;
        await using (var db = new IdentityDbContext(options))
        {
            var migrations = db.Database.GetMigrations().ToArray();
            target = migrations.Single(name => name.EndsWith("_AddPublicAllowedOrigins", StringComparison.Ordinal));
            previous = migrations[Array.IndexOf(migrations, target) - 1];
            await db.GetService<IMigrator>().MigrateAsync(previous, Ct);
            Assert.False(await TableExistsAsync(db, isSqlite));
            db.AppRegistrations.Add(new AppRegistrationEntity
            {
                Id = appId,
                AppId = "origin-migration-app",
                AppName = "Origin Migration App",
                AppSecretHash = string.Empty,
                ClientType = OidcClientType.Public,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            });
            await db.SaveChangesAsync(Ct);
            await db.GetService<IMigrator>().MigrateAsync(target, Ct);
            Assert.True(await TableExistsAsync(db, isSqlite));
            Assert.False(db.Database.HasPendingModelChanges());
            Assert.Empty(await db.AppAllowedOrigins.ToListAsync(Ct));
        }

        await using (var db = new IdentityDbContext(options))
        {
            db.AppAllowedOrigins.Add(Origin(appId, "https://spa.example.test"));
            await db.SaveChangesAsync(Ct);
        }
        await using (var duplicate = new IdentityDbContext(options))
        {
            duplicate.AppAllowedOrigins.Add(Origin(appId, "https://spa.example.test"));
            await Assert.ThrowsAsync<DbUpdateException>(() => duplicate.SaveChangesAsync(Ct));
        }
        await using (var missingParent = new IdentityDbContext(options))
        {
            missingParent.AppAllowedOrigins.Add(Origin(Guid.NewGuid(), "https://other.example.test"));
            await Assert.ThrowsAsync<DbUpdateException>(() => missingParent.SaveChangesAsync(Ct));
        }

        await using (var db = new IdentityDbContext(options))
        {
            var app = await db.AppRegistrations.SingleAsync(row => row.Id == appId, Ct);
            db.AppRegistrations.Remove(app);
            await db.SaveChangesAsync(Ct);
            Assert.False(await db.AppAllowedOrigins.AnyAsync(Ct));

            // Down drops only the new table. An upgrade after Down starts with an empty set.
            await db.GetService<IMigrator>().MigrateAsync(previous, Ct);
            Assert.False(await TableExistsAsync(db, isSqlite));
            Assert.DoesNotContain(target, await db.Database.GetAppliedMigrationsAsync(Ct));
            await db.GetService<IMigrator>().MigrateAsync(target, Ct);
            Assert.True(await TableExistsAsync(db, isSqlite));
            Assert.Empty(await db.AppAllowedOrigins.ToListAsync(Ct));
        }
    }

    private static AppAllowedOriginEntity Origin(Guid appId, string value) => new()
    {
        Id = Guid.NewGuid(), AppRegistrationId = appId, CanonicalOrigin = value
    };

    private static async Task<bool> TableExistsAsync(IdentityDbContext db, bool isSqlite)
    {
        var connection = db.Database.GetDbConnection();
        if (connection.State != System.Data.ConnectionState.Open)
        {
            await connection.OpenAsync(Ct);
        }
        await using var command = connection.CreateCommand();
        command.CommandText = isSqlite
            ? "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='app_allowed_origins'"
            : "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='app_allowed_origins'";
        return Convert.ToInt32(await command.ExecuteScalarAsync(Ct)) == 1;
    }
}
