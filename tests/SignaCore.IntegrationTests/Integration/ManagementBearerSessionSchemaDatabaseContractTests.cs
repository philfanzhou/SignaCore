using System.Data.Common;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Migrations.Operations;
using Microsoft.Extensions.Logging.Abstractions;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

public sealed class ManagementBearerSessionSchemaDatabaseContractTests
{
    private const string Table = "management_bearer_sessions";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly DateTimeOffset Instant = new(2026, 9, 25, 0, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task FreshSchema_EnforcesUniqueDigestTimeChecksForeignKeyAndRollback(string provider)
    {
        await using var fixture = await Harness.CreateAsync(provider);
        await using var db = fixture.Context();
        await db.Database.MigrateAsync(Ct);
        Assert.False(db.Database.HasPendingModelChanges());
        var migration = fixture.Migration(db);
        var table = Assert.Single(migration.UpOperations.OfType<CreateTableOperation>());
        Assert.Equal(Table, table.Name);
        Assert.Equal(new[] { "id" }, table.PrimaryKey!.Columns);
        Assert.Equal(3, table.CheckConstraints.Count);
        var foreignKey = Assert.Single(table.ForeignKeys);
        Assert.Equal(new[] { "account_id" }, foreignKey.Columns);
        Assert.Equal("accounts", foreignKey.PrincipalTable);
        Assert.Equal(new[] { "id" }, foreignKey.PrincipalColumns);
        Assert.Equal(ReferentialAction.Cascade, foreignKey.OnDelete);
        Assert.Equal(4, migration.UpOperations.Count);
        var indexes = migration.UpOperations.OfType<CreateIndexOperation>().ToArray();
        Assert.Equal(3, indexes.Length);
        Assert.All(indexes, index => Assert.Equal(Table, index.Table));
        Assert.Equal("token_digest", Assert.Single(Assert.Single(indexes, x => x.IsUnique).Columns));
        Assert.Contains(indexes, x => x.Columns.SequenceEqual(new[] { "expires_at" }));
        Assert.Contains(indexes, x => x.Columns.SequenceEqual(new[] { "account_id" }));
        Assert.Equal(Table, Assert.IsType<DropTableOperation>(Assert.Single(migration.DownOperations)).Name);
        var columns = await fixture.RowsAsync(db, $"SELECT * FROM {Table} LIMIT 0", includeHeader: true);
        Assert.Equal("id|token_digest|account_id|created_at|expires_at|revoked_at", Assert.Single(columns));
        var physicalIndexes = await fixture.RowsAsync(db, provider == "SQLite"
            ? "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='management_bearer_sessions'"
            : "SELECT indexname FROM pg_indexes WHERE schemaname=current_schema() AND tablename='management_bearer_sessions'");
        Assert.All(indexes, index => Assert.Contains(index.Name, physicalIndexes));
        var model = db.Model.FindEntityType(typeof(ManagementBearerSessionEntity))!;
        Assert.Equal(71, model.FindProperty(nameof(ManagementBearerSessionEntity.TokenDigest))!.GetMaxLength());
        Assert.False(model.FindProperty(nameof(ManagementBearerSessionEntity.TokenDigest))!.IsNullable);
        var times = table.Columns.Where(c => c.Name is "created_at" or "expires_at" or "revoked_at").ToArray();
        Assert.Equal(3, times.Length);
        Assert.All(times, c => Assert.Equal(provider == "SQLite" ? "INTEGER" : "timestamptz", c.ColumnType));
        Assert.Equal(new[] { "revoked_at" }, times.Where(c => c.IsNullable).Select(c => c.Name));
        var physicalColumns = await fixture.RowsAsync(db, provider == "SQLite"
            ? "SELECT name, type, [notnull] FROM pragma_table_info('management_bearer_sessions')"
            : "SELECT column_name, data_type, CASE WHEN is_nullable='NO' THEN 1 ELSE 0 END FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='management_bearer_sessions'");
        var idType = provider == "SQLite" ? "TEXT" : "uuid";
        var textType = provider == "SQLite" ? "TEXT" : "character varying";
        var timeType = provider == "SQLite" ? "INTEGER" : "timestamp with time zone";
        Assert.Equal(new[] { $"id|{idType}|1", $"token_digest|{textType}|1", $"account_id|{idType}|1",
            $"created_at|{timeType}|1", $"expires_at|{timeType}|1", $"revoked_at|{timeType}|0" }.Order(StringComparer.Ordinal), physicalColumns);

        var account = Guid.NewGuid();
        var peer = Guid.NewGuid();
        db.Accounts.AddRange(Account(account), Account(peer));
        var active = Session(account);
        var revoked = Session(account, 'b');
        revoked.RevokedAt = revoked.CreatedAt.AddTicks(10);
        var peerSession = Session(peer, 'c');
        // Equality at creation is valid for revocation, and expiry is not limited to 15 minutes by schema.
        peerSession.RevokedAt = peerSession.CreatedAt;
        peerSession.ExpiresAt = peerSession.CreatedAt.AddHours(1);
        db.ManagementBearerSessions.AddRange(active, revoked, peerSession);
        await db.SaveChangesAsync(Ct);
        db.ChangeTracker.Clear();
        var loaded = await db.ManagementBearerSessions.OrderBy(x => x.TokenDigest).ToArrayAsync(Ct);
        Assert.Equal(3, loaded.Length);
        Assert.All(loaded, row =>
        {
            Assert.Equal(Instant.AddTicks(1234560), row.CreatedAt);
            Assert.Equal(TimeSpan.Zero, row.CreatedAt.Offset);
            Assert.Equal(TimeSpan.Zero, row.ExpiresAt.Offset);
        });
        Assert.Null(loaded[0].RevokedAt);
        Assert.Equal(active.ExpiresAt, loaded[0].ExpiresAt);
        Assert.Equal(revoked.RevokedAt, loaded[1].RevokedAt);
        Assert.Equal(peerSession.RevokedAt, loaded[2].RevokedAt);
        var invalidRows = new List<ManagementBearerSessionEntity> { Session(account), Session(Guid.NewGuid(), 'd') };
        var duplicateId = Session(account, 'd');
        duplicateId.Id = active.Id;
        invalidRows.Add(duplicateId);
        foreach (var length in new[] { 70, 72 })
        {
            var invalid = Session(account, 'd');
            invalid.TokenDigest = new string('d', length);
            invalidRows.Add(invalid);
        }
        foreach (var delta in new[] { 0L, -10L })
        {
            var invalid = Session(account, 'd');
            invalid.ExpiresAt = invalid.CreatedAt.AddTicks(delta);
            invalidRows.Add(invalid);
        }
        var invalidRevocation = Session(account, 'd');
        invalidRevocation.RevokedAt = invalidRevocation.CreatedAt.AddTicks(-10);
        invalidRows.Add(invalidRevocation);
        var missingDigest = Session(account, 'd');
        missingDigest.TokenDigest = null!;
        invalidRows.Add(missingDigest);
        foreach (var invalid in invalidRows)
        {
            await using var write = fixture.Context();
            write.ManagementBearerSessions.Add(invalid);
            await Assert.ThrowsAsync<DbUpdateException>(() => write.SaveChangesAsync(Ct));
        }
        await using (var write = fixture.Context())
        await using (var transaction = await write.Database.BeginTransactionAsync(Ct))
        {
            write.ManagementBearerSessions.Add(Session(account, 'e'));
            await write.SaveChangesAsync(Ct);
            write.ManagementBearerSessions.Add(Session(Guid.NewGuid(), 'f'));
            await Assert.ThrowsAsync<DbUpdateException>(() => write.SaveChangesAsync(Ct));
            await transaction.RollbackAsync(Ct);
        }
        Assert.Equal(3, await db.ManagementBearerSessions.CountAsync(Ct));
        // Delete directly in the database, without tracked dependents, to prove physical ON DELETE CASCADE.
        await db.Accounts.Where(x => x.Id == account).ExecuteDeleteAsync(Ct);
        db.ChangeTracker.Clear();
        var remaining = Assert.Single(await db.ManagementBearerSessions.ToListAsync(Ct));
        Assert.Equal(peerSession.Id, remaining.Id);
        Assert.Equal(peerSession.TokenDigest, remaining.TokenDigest);
        Assert.Equal(peerSession.CreatedAt, remaining.CreatedAt);
        Assert.Equal(peerSession.ExpiresAt, remaining.ExpiresAt);
        Assert.Equal(peerSession.RevokedAt, remaining.RevokedAt);
        Assert.Equal(peer, remaining.AccountId);
        Assert.True(await db.Accounts.AnyAsync(x => x.Id == peer, Ct));
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task UpgradeFailureCancellationDownAndUp_PreserveEveryExistingArtifact(string provider)
    {
        await using var fixture = await Harness.CreateAsync(provider);
        string target;
        string previous;
        string schema;
        Dictionary<string, string> rows;
        await using (var db = fixture.Context())
        {
            var migrations = db.Database.GetMigrations().ToArray();
            target = migrations.Single(x => x.EndsWith("_AddManagementBearerSessions", StringComparison.Ordinal));
            previous = migrations[Array.IndexOf(migrations, target) - 1];
            await db.GetService<IMigrator>().MigrateAsync(previous, Ct);
            Assert.False(await fixture.TableExistsAsync(db));
            // The new migration only adds its table/index (asserted above). All seeded entity
            // mappings below match the direct predecessor; no current model targets older shapes.
            await fixture.SeedExistingAsync(db);
            schema = await fixture.ExistingSchemaAsync(db);
            rows = await fixture.ExistingRowsAsync(db);
        }
        foreach (var cancel in new[] { false, true })
        {
            using var caller = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            var fault = new AfterDdlFault(cancel ? caller : null);
            await using (var db = fixture.Context(fault))
            {
                var operation = db.GetService<IMigrator>().MigrateAsync(target, caller.Token);
                if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);
                else await Assert.ThrowsAsync<InvalidOperationException>(() => operation);
                Assert.True(fault.Observed);
            }
            await using var recovered = fixture.Context();
            var history = (await recovered.Database.GetAppliedMigrationsAsync(Ct)).ToArray();
            // Observe actual history/schema after the interrupted DDL. Never infer that an
            // arbitrary cancellation necessarily rolled back an already committed migration.
            Assert.Equal(history.Contains(target), await fixture.TableExistsAsync(recovered));
            Assert.Equal(schema, await fixture.ExistingSchemaAsync(recovered));
            Assert.Equal(rows, await fixture.ExistingRowsAsync(recovered));
            if (history.Contains(target)) await recovered.GetService<IMigrator>().MigrateAsync(previous, Ct);
        }
        await using (var db = fixture.Context())
        {
            await db.GetService<IMigrator>().MigrateAsync(target, Ct);
            Assert.Contains(target, await db.Database.GetAppliedMigrationsAsync(Ct));
            Assert.Empty(await db.ManagementBearerSessions.ToListAsync(Ct));
            Assert.False(db.Database.HasPendingModelChanges());
            Assert.Equal(schema, await fixture.ExistingSchemaAsync(db));
            Assert.Equal(rows, await fixture.ExistingRowsAsync(db));
            db.ManagementBearerSessions.Add(Session(await db.Accounts.Select(x => x.Id).FirstAsync(Ct)));
            await db.SaveChangesAsync(Ct);
            db.ChangeTracker.Clear();
            await db.GetService<IMigrator>().MigrateAsync(previous, Ct);
            Assert.False(await fixture.TableExistsAsync(db));
            Assert.DoesNotContain(target, await db.Database.GetAppliedMigrationsAsync(Ct));
            Assert.Equal(schema, await fixture.ExistingSchemaAsync(db));
            Assert.Equal(rows, await fixture.ExistingRowsAsync(db));
            await db.GetService<IMigrator>().MigrateAsync(target, Ct);
            Assert.Empty(await db.ManagementBearerSessions.ToListAsync(Ct));
            Assert.Equal(rows, await fixture.ExistingRowsAsync(db));
        }
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task IndependentConnections_CompeteForOneDigest(string provider)
    {
        await using var fixture = await Harness.CreateAsync(provider);
        var account = Guid.NewGuid();
        await using (var db = fixture.Context())
        {
            await db.Database.MigrateAsync(Ct);
            db.Accounts.Add(Account(account));
            await db.SaveChangesAsync(Ct);
        }
        var ready = 0;
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task<bool> InsertAsync()
        {
            await using var db = fixture.Context();
            await db.Database.OpenConnectionAsync(Ct);
            if (Interlocked.Increment(ref ready) == 2) gate.TrySetResult();
            await gate.Task.WaitAsync(Ct);
            db.ManagementBearerSessions.Add(Session(account));
            try { await db.SaveChangesAsync(Ct); return true; }
            catch (DbUpdateException exception)
            {
                Assert.True(exception.InnerException is Microsoft.Data.Sqlite.SqliteException { SqliteErrorCode: 19 }
                    or Npgsql.PostgresException { SqlState: Npgsql.PostgresErrorCodes.UniqueViolation });
                return false;
            }
        }
        var results = await Task.WhenAll(Task.Run(InsertAsync, Ct), Task.Run(InsertAsync, Ct));
        Assert.Single(results, success => success);
        await using var read = fixture.Context();
        Assert.Single(await read.ManagementBearerSessions.ToListAsync(Ct));
    }

    private static AccountEntity Account(Guid id) => new() { Id = id, IsActive = true, CreatedAt = Instant };

    private static ManagementBearerSessionEntity Session(Guid account, char digest = 'a') => new()
    {
        Id = Guid.NewGuid(), AccountId = account, TokenDigest = "sha256:" + new string(digest, 64),
        CreatedAt = Instant.AddTicks(1234560), ExpiresAt = Instant.AddMinutes(15).AddTicks(1234560)
    };

    private sealed class AfterDdlFault(CancellationTokenSource? caller) : DbCommandInterceptor
    {
        public bool Observed;
        public override ValueTask<int> NonQueryExecutedAsync(DbCommand command, CommandExecutedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("CREATE TABLE", StringComparison.Ordinal) && command.CommandText.Contains(Table, StringComparison.Ordinal))
            {
                Observed = true;
                if (caller is not null) { caller.Cancel(); throw new OperationCanceledException(caller.Token); }
                throw new InvalidOperationException("Injected failure after schema command execution.");
            }
            return ValueTask.FromResult(result);
        }
    }

    private sealed class Harness(string provider, DatabaseOptions database, string? path, PostgreSqlContainer? container) : IAsyncDisposable
    {
        private static readonly string[] ExistingTables = ["accounts", "password_credentials", "app_registrations", "identity_sessions", "refresh_tokens", "security_keys", "service_settings", "service_installations", "service_audit_logs", "service_data_protection_keys"];
        public static async Task<Harness> CreateAsync(string provider)
        {
            PostgreSqlContainer? container = null;
            string? path = null;
            try
            {
                string connection;
                if (provider == "PostgreSQL")
                {
                    Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true", "Enable the PostgreSQL database contract matrix.");
                    container = new PostgreSqlBuilder(Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") ?? "postgres:15-alpine").Build();
                    await container.StartAsync(Ct);
                    connection = container.GetConnectionString();
                }
                else
                {
                    path = Path.Combine(Path.GetTempPath(), $"management-bearer-schema-{Guid.NewGuid():N}.db");
                    connection = $"Data Source={path};Pooling=false";
                }
                return new Harness(provider, new DatabaseOptions { Provider = provider, ServerVersion = provider == "PostgreSQL" ? "15" : null, ConnectionString = connection }, path, container);
            }
            catch { if (container is not null) await container.DisposeAsync(); throw; }
        }
        public IdentityDbContext Context(IInterceptor? interceptor = null)
        {
            var builder = new DbContextOptionsBuilder<IdentityDbContext>();
            builder.UseIdentityDatabase(database, enableRetryOnFailure: false).UseLoggerFactory(NullLoggerFactory.Instance);
            if (interceptor is not null) builder.AddInterceptors(interceptor);
            return new IdentityDbContext(builder.Options);
        }
        public Migration Migration(IdentityDbContext db)
        {
            var assembly = db.GetService<IMigrationsAssembly>();
            return assembly.CreateMigration(assembly.Migrations.Single(x => x.Key.EndsWith("_AddManagementBearerSessions", StringComparison.Ordinal)).Value, db.Database.ProviderName!);
        }
        public async Task<bool> TableExistsAsync(IdentityDbContext db) => (await RowsAsync(db, provider == "SQLite"
            ? "SELECT name FROM sqlite_master WHERE type='table' AND name='management_bearer_sessions'"
            : "SELECT tablename FROM pg_tables WHERE schemaname=current_schema() AND tablename='management_bearer_sessions'")).Count == 1;
        public async Task<List<string>> RowsAsync(IdentityDbContext db, string sql, bool includeHeader = false)
        {
            await db.Database.OpenConnectionAsync(Ct);
            await using var command = db.Database.GetDbConnection().CreateCommand();
            command.CommandText = sql;
            await using var reader = await command.ExecuteReaderAsync(Ct);
            var rows = new List<string>();
            if (includeHeader) rows.Add(string.Join('|', Enumerable.Range(0, reader.FieldCount).Select(reader.GetName)));
            while (await reader.ReadAsync(Ct))
                rows.Add(string.Join('|', Enumerable.Range(0, reader.FieldCount).Select(i => reader.IsDBNull(i) ? "<null>" : Convert.ToString(reader.GetValue(i), CultureInfo.InvariantCulture))));
            return rows.Order(StringComparer.Ordinal).ToList();
        }
        private static string Hash(IEnumerable<string> values) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(values))));
        public async Task<string> ExistingSchemaAsync(IdentityDbContext db)
        {
            var rows = await RowsAsync(db, provider == "SQLite"
                ? "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE tbl_name <> 'management_bearer_sessions' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '__EF%' ORDER BY name"
                : "SELECT table_name,column_name,data_type,is_nullable,character_maximum_length,column_default FROM information_schema.columns WHERE table_schema=current_schema() AND table_name <> 'management_bearer_sessions' AND table_name NOT LIKE '__EF%' ORDER BY table_name,ordinal_position");
            if (provider == "PostgreSQL") rows.AddRange(await RowsAsync(db, "SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname=current_schema() AND tablename <> 'management_bearer_sessions' AND tablename NOT LIKE '__EF%' ORDER BY indexname"));
            return Hash(rows);
        }
        public async Task<Dictionary<string, string>> ExistingRowsAsync(IdentityDbContext db)
        {
            var result = new Dictionary<string, string>();
            foreach (var table in ExistingTables)
            {
                var rows = await RowsAsync(db, $"SELECT * FROM {table}");
                Assert.NotEmpty(rows);
                result.Add(table, Hash(rows));
            }
            return result;
        }
        public async Task SeedExistingAsync(IdentityDbContext db)
        {
            var account = Guid.NewGuid();
            var password = Guid.NewGuid();
            var token = Guid.NewGuid();
            db.Accounts.Add(new AccountEntity { Id = account, IsActive = true, CreatedAt = Instant, Nickname = "Schema account" });
            db.PasswordCredentials.Add(new PasswordCredentialEntity { Id = password, AccountId = account, Username = "schema_account", PasswordHash = "synthetic-hash", CreatedAt = Instant });
            db.AppRegistrations.Add(new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = "schema-client", AppName = "Schema client", AppSecretHash = "synthetic-hash", CreatedAt = Instant });
            db.IdentitySessions.Add(new IdentitySessionEntity { Id = Guid.NewGuid(), AccountId = account, PasswordCredentialId = password, AuthMethod = "pwd", AuthTime = Instant, LastSeenAt = Instant, IdleExpiresAt = Instant.AddMinutes(30), AbsoluteExpiresAt = Instant.AddHours(12) });
            db.RefreshTokens.Add(new RefreshTokenEntity { Id = token, FamilyId = token, AccountId = account, AppId = "schema-client", TokenValue = "sha256:" + new string('a', 64), CreatedAt = Instant, ExpiresAt = Instant.AddDays(1) });
            db.SecurityKeys.Add(new SecurityKeyEntity { Id = Guid.NewGuid(), KeyId = "schema-key", PublicKeyExponent = "synthetic-public", PublicKeyModulus = "synthetic-public", EncryptedPrivateKeyParams = "synthetic-envelope", EncryptionSalt = "synthetic-salt", CreatedAt = Instant, ExpiresAt = Instant.AddDays(1) });
            db.ServiceInstallations.Add(new ServiceInstallationEntity { ServiceId = "signacore", Status = InstallationStatus.Completed, CreatedAtUtc = Instant.UtcDateTime, CompletedAtUtc = Instant.UtcDateTime, Version = 1 });
            await db.SaveChangesAsync(Ct);
            await db.Database.ExecuteSqlAsync($"INSERT INTO service_settings (service_id, version, values_json, updated_at_utc, updated_by, restart_required) VALUES ({"signacore"}, {1L}, {"{}"}, {Instant.UtcDateTime}, {"schema-test"}, {false})", Ct);
            await db.Database.ExecuteSqlAsync($"INSERT INTO service_data_protection_keys (service_id, key_id, encrypted_xml) VALUES ({"signacore"}, {"schema-key"}, {"synthetic-envelope"})", Ct);
            await db.Database.ExecuteSqlAsync($"INSERT INTO service_audit_logs (id, action, occurred_at_utc, operator_source, outcome, target_id, target_type) VALUES ({Guid.NewGuid().ToString()}, {"schema.seed"}, {Instant.UtcDateTime}, {"system"}, {0}, {"schema-test"}, {"test"})", Ct);
            db.ChangeTracker.Clear();
        }
        public async ValueTask DisposeAsync()
        {
            if (container is not null) await container.DisposeAsync();
            if (path is not null) foreach (var file in new[] { path, path + "-wal", path + "-shm" }) File.Delete(file);
        }
    }
}
