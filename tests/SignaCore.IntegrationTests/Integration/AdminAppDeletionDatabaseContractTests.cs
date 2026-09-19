using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The SQLite half of the <c>EV-34</c> application-deletion contract: the restrictive
/// <c>authorization_requests</c> reference is the only authority, so a repository-level delete of a
/// referenced application fails as a recognizable foreign-key violation whether the continuation is
/// still unexpired or expired-but-retained, nothing cascades or disappears on the refused path, and
/// the unchanged delete succeeds once the last reference is gone. The PostgreSQL half — including
/// the concurrent insert/delete window — lives in <see cref="ServerDatabaseContractTests"/>.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class AdminAppDeletionDatabaseContractTests
{
    [Fact]
    public async Task DeletingAReferencedApplication_FailsAsAForeignKeyViolation_InEveryRetentionState()
    {
        await using var database = new SqliteDeletionDatabase();
        var options = await database.InitializeAsync();
        var cancellationToken = TestContext.Current.CancellationToken;

        var appId = Guid.NewGuid();
        var unexpiredHandle = "deletion-live-handle-0123456789abcdefghij";
        var expiredRetainedHandle = "deletion-retained-handle-0123456789abcdefg";
        await SeedApplicationWithRedirectAsync(options, appId);
        var now = DateTimeOffset.UtcNow;
        await InsertContinuationAsync(options, appId, unexpiredHandle, now);
        // Expired long ago but still inside the 24-hour retention window: expiry is not deletion.
        await InsertContinuationAsync(
            options, appId, expiredRetainedHandle, now.AddHours(-2));

        await using (var context = new IdentityDbContext(options))
        {
            foreach (var handle in new[] { unexpiredHandle, expiredRetainedHandle })
            {
                var dumpBefore = await DumpTablesAsync(options);
                var continuationBefore = await context.AuthorizationRequests.AsNoTracking()
                    .CountAsync(row => row.AppRegistrationId == appId, cancellationToken);

                var exception = await Assert.ThrowsAsync<DbUpdateException>(() =>
                    DeleteApplicationAsync(options, appId));

                Assert.True(
                    DatabaseConstraintViolation.IsForeignKeyViolation(exception),
                    "The refused delete must be recognizable as a foreign-key violation.");
                Assert.Equal(continuationBefore, await context.AuthorizationRequests.AsNoTracking()
                    .CountAsync(row => row.AppRegistrationId == appId, cancellationToken));
                Assert.True(await context.AppRegistrations.AsNoTracking()
                    .AnyAsync(app => app.Id == appId, cancellationToken));
                Assert.True(await context.AppRedirectUris.AsNoTracking()
                    .AnyAsync(uri => uri.AppRegistrationId == appId, cancellationToken));
                Assert.Equal(dumpBefore, await DumpTablesAsync(options));
            }
        }
    }

    [Fact]
    public async Task OnceTheLastReferenceIsGone_TheUnchangedDeleteSucceedsAndCascades()
    {
        await using var database = new SqliteDeletionDatabase();
        var options = await database.InitializeAsync();
        var cancellationToken = TestContext.Current.CancellationToken;

        var appId = Guid.NewGuid();
        var handle = "deletion-releasable-handle-0123456789abcdefg";
        await SeedApplicationWithRedirectAsync(options, appId);
        await InsertContinuationAsync(options, appId, handle, DateTimeOffset.UtcNow);

        // Retention cleanup removes the continuation; the delete that failed before now succeeds
        // and takes the cascaded children with it.
        await using (var cleanupContext = new IdentityDbContext(options))
        {
            var continuation = await cleanupContext.AuthorizationRequests
                .SingleAsync(row => row.HandleDigest == LoginHandleDigest.Compute(handle), cancellationToken);
            cleanupContext.AuthorizationRequests.Remove(continuation);
            await cleanupContext.SaveChangesAsync(cancellationToken);
        }

        await DeleteApplicationAsync(options, appId);

        await using (var verify = new IdentityDbContext(options))
        {
            Assert.False(await verify.AppRegistrations.AsNoTracking()
                .AnyAsync(app => app.Id == appId, cancellationToken));
            Assert.False(await verify.AppRedirectUris.AsNoTracking()
                .AnyAsync(uri => uri.AppRegistrationId == appId, cancellationToken));
            Assert.Empty(await verify.AuthorizationRequests.AsNoTracking()
                .Where(row => row.AppRegistrationId == appId)
                .ToListAsync(cancellationToken));
        }
    }

    [Fact]
    public async Task AnUnreferencedApplication_DeletesDirectly()
    {
        await using var database = new SqliteDeletionDatabase();
        var options = await database.InitializeAsync();
        var appId = Guid.NewGuid();
        await SeedApplicationWithRedirectAsync(options, appId);

        await DeleteApplicationAsync(options, appId);

        await using (var verify = new IdentityDbContext(options))
        {
            Assert.False(await verify.AppRegistrations.AsNoTracking()
                .AnyAsync(app => app.Id == appId, TestContext.Current.CancellationToken));
            Assert.False(await verify.AppRedirectUris.AsNoTracking()
                .AnyAsync(uri => uri.AppRegistrationId == appId, TestContext.Current.CancellationToken));
        }
    }

    // ---- Helpers ----

    private static async Task SeedApplicationWithRedirectAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid appId)
    {
        await using var context = new IdentityDbContext(options);
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = appId,
            AppId = $"deletion-app-{appId:N}",
            AppSecretHash = "hash",
            AppName = "Deletion Contract App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            RedirectUris =
            [
                new AppRedirectUriEntity
                {
                    Id = Guid.NewGuid(),
                    AppRegistrationId = appId,
                    Kind = RedirectUriKind.Redirect,
                    CanonicalUri = "https://bff.deletion.test/callback"
                }
            ]
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    private static Task InsertContinuationAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid appId,
        string handle,
        DateTimeOffset createdAt)
    {
        return InsertContinuationAsync(options, appId, handle, createdAt, TestContext.Current.CancellationToken);
    }

    private static async Task InsertContinuationAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid appId,
        string handle,
        DateTimeOffset createdAt,
        CancellationToken cancellationToken)
    {
        await using var context = new IdentityDbContext(options);
        context.AuthorizationRequests.Add(new AuthorizationRequestEntity
        {
            Id = Guid.NewGuid(),
            HandleDigest = LoginHandleDigest.Compute(handle),
            AppRegistrationId = appId,
            RedirectUri = "https://bff.deletion.test/callback",
            Scope = "openid",
            State = "deletion-state",
            Nonce = "deletion-nonce",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CreatedAt = createdAt,
            ExpiresAt = createdAt.AddMinutes(IdentityConstants.LoginHandleLifetimeMinutes)
        });
        await context.SaveChangesAsync(cancellationToken);
    }

    private static async Task DeleteApplicationAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid appId)
    {
        await using var context = new IdentityDbContext(options);
        var app = await context.AppRegistrations
            .SingleAsync(app => app.Id == appId, TestContext.Current.CancellationToken);
        context.AppRegistrations.Remove(app);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    private static async Task<string> DumpTablesAsync(DbContextOptions<IdentityDbContext> options)
    {
        await using var context = new IdentityDbContext(options);
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        var connection = context.Database.GetDbConnection();

        var tableNames = new List<string>();
        await using (var tableCommand = connection.CreateCommand())
        {
            tableCommand.CommandText =
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name";
            await using var reader = await tableCommand.ExecuteReaderAsync(
                TestContext.Current.CancellationToken);
            while (await reader.ReadAsync(TestContext.Current.CancellationToken))
            {
                tableNames.Add(reader.GetString(0));
            }
        }

        var dump = new StringBuilder();
        foreach (var tableName in tableNames)
        {
            dump.Append("## ").AppendLine(tableName);
            await using var command = connection.CreateCommand();
            command.CommandText = $"SELECT * FROM \"{tableName}\" ORDER BY 1";
            await using var reader = await command.ExecuteReaderAsync(
                TestContext.Current.CancellationToken);
            while (await reader.ReadAsync(TestContext.Current.CancellationToken))
            {
                for (var ordinal = 0; ordinal < reader.FieldCount; ordinal++)
                {
                    dump.Append(reader.GetName(ordinal))
                        .Append('=')
                        .Append(reader.IsDBNull(ordinal) ? "NULL" : reader.GetValue(ordinal))
                        .Append('|');
                }

                dump.AppendLine();
            }
        }

        return dump.ToString();
    }

    /// <summary>A file-backed SQLite test database on the production migration chain.</summary>
    private sealed class SqliteDeletionDatabase : IAsyncDisposable
    {
        private readonly string _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-app-deletion-{Guid.NewGuid():N}.db");

        public DbContextOptions<IdentityDbContext> BuildOptions()
        {
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(new DatabaseOptions
            {
                Provider = "SQLite",
                ConnectionString = $"Data Source={_databasePath};Default Timeout=30"
            });
            return optionsBuilder.Options;
        }

        public async Task<DbContextOptions<IdentityDbContext>> InitializeAsync()
        {
            var options = BuildOptions();
            await using var context = new IdentityDbContext(options);
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
            return options;
        }

        public ValueTask DisposeAsync()
        {
            TestSqlitePools.ClearAll();
            if (File.Exists(_databasePath))
            {
                File.Delete(_databasePath);
            }

            return ValueTask.CompletedTask;
        }
    }
}
