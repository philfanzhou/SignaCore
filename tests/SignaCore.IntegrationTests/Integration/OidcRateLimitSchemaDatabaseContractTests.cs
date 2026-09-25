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

public sealed class OidcRateLimitSchemaDatabaseContractTests
{
    private const string Table = "oidc_rate_limit_buckets";
    private static readonly string[] Policies = ["oidc-authorize", "oidc-login", "oidc-token", "oidc-userinfo", "oidc-logout", "oidc-revoke"];
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly DateTimeOffset Instant = new(2026, 9, 25, 0, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task FreshSchema_EnforcesCompositeKeyChecksAndAtomicRollback(string provider)
    {
        await using var fixture = await Harness.CreateAsync(provider);
        await using var db = fixture.Context();
        await db.Database.MigrateAsync(Ct);
        Assert.False(db.Database.HasPendingModelChanges());
        var migration = fixture.Migration(db);
        var table = Assert.Single(migration.UpOperations.OfType<CreateTableOperation>());
        Assert.Equal(Table, table.Name);
        Assert.Equal(new[] { "policy", "partition_digest" }, table.PrimaryKey!.Columns);
        Assert.Equal(3, table.CheckConstraints.Count);
        Assert.Empty(table.ForeignKeys);
        Assert.Equal(2, migration.UpOperations.Count);
        var index = Assert.Single(migration.UpOperations.OfType<CreateIndexOperation>());
        Assert.Equal(new[] { "window_expires_at" }, index.Columns);
        Assert.Equal(Table, index.Table);
        Assert.Equal(Table, Assert.IsType<DropTableOperation>(Assert.Single(migration.DownOperations)).Name);
        var columns = await fixture.RowsAsync(db, $"SELECT * FROM {Table} LIMIT 0", includeHeader: true);
        Assert.Equal("policy|partition_digest|window_expires_at|permit_count", Assert.Single(columns));
        var indexes = await fixture.RowsAsync(db, provider == "SQLite"
            ? "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='oidc_rate_limit_buckets'"
            : "SELECT indexname FROM pg_indexes WHERE schemaname=current_schema() AND tablename='oidc_rate_limit_buckets'");
        Assert.Contains(index.Name, indexes);
        var model = db.Model.FindEntityType(typeof(OidcRateLimitBucketEntity))!;
        Assert.Equal(32, model.FindProperty(nameof(OidcRateLimitBucketEntity.Policy))!.GetMaxLength());
        Assert.Equal(64, model.FindProperty(nameof(OidcRateLimitBucketEntity.PartitionDigest))!.GetMaxLength());

        foreach (var policy in Policies) db.OidcRateLimitBuckets.Add(Bucket(policy));
        db.OidcRateLimitBuckets.Add(Bucket(Policies[0], new string('b', 64), 90));
        await db.SaveChangesAsync(Ct);
        db.ChangeTracker.Clear();
        Assert.Equal(7, await db.OidcRateLimitBuckets.CountAsync(Ct));
        Assert.All(await db.OidcRateLimitBuckets.ToListAsync(Ct), row => Assert.Equal(Instant.AddTicks(1234560), row.WindowExpiresAt));
        foreach (var invalid in new[]
        {
            Bucket(Policies[0]), Bucket("unknown"), Bucket(""), Bucket(new string('x', 33)),
            Bucket(Policies[0], ""), Bucket(Policies[0], new string('c', 63)),
            Bucket(Policies[0], new string('c', 65)),
            Bucket(Policies[0], new string('c', 64), 0), Bucket(Policies[0], new string('c', 64), 91)
        })
        {
            await using var write = fixture.Context();
            write.OidcRateLimitBuckets.Add(invalid);
            await Assert.ThrowsAsync<DbUpdateException>(() => write.SaveChangesAsync(Ct));
        }
        await using (var write = fixture.Context())
        await using (var transaction = await write.Database.BeginTransactionAsync(Ct))
        {
            write.OidcRateLimitBuckets.Add(Bucket(Policies[0], new string('d', 64)));
            await write.SaveChangesAsync(Ct);
            write.OidcRateLimitBuckets.Add(Bucket("invalid"));
            await Assert.ThrowsAsync<DbUpdateException>(() => write.SaveChangesAsync(Ct));
            await transaction.RollbackAsync(Ct);
        }
        Assert.Equal(7, await db.OidcRateLimitBuckets.CountAsync(Ct));
        Assert.False(await db.OidcRateLimitBuckets.AnyAsync(x => x.PartitionDigest == new string('d', 64), Ct));
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
            target = migrations.Single(x => x.EndsWith("_AddOidcRateLimitBuckets", StringComparison.Ordinal));
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
            Assert.Empty(await db.OidcRateLimitBuckets.ToListAsync(Ct));
            Assert.False(db.Database.HasPendingModelChanges());
            Assert.Equal(schema, await fixture.ExistingSchemaAsync(db));
            Assert.Equal(rows, await fixture.ExistingRowsAsync(db));
            db.OidcRateLimitBuckets.Add(Bucket(Policies[0]));
            await db.SaveChangesAsync(Ct);
            db.ChangeTracker.Clear();
            await db.GetService<IMigrator>().MigrateAsync(previous, Ct);
            Assert.False(await fixture.TableExistsAsync(db));
            Assert.DoesNotContain(target, await db.Database.GetAppliedMigrationsAsync(Ct));
            Assert.Equal(schema, await fixture.ExistingSchemaAsync(db));
            Assert.Equal(rows, await fixture.ExistingRowsAsync(db));
            await db.GetService<IMigrator>().MigrateAsync(target, Ct);
            Assert.Empty(await db.OidcRateLimitBuckets.ToListAsync(Ct));
            Assert.Equal(rows, await fixture.ExistingRowsAsync(db));
        }
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task IndependentConnections_CompeteForOneCompositeKey(string provider)
    {
        await using var fixture = await Harness.CreateAsync(provider);
        await using (var db = fixture.Context()) await db.Database.MigrateAsync(Ct);
        var ready = 0;
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task<bool> InsertAsync()
        {
            await using var db = fixture.Context();
            await db.Database.OpenConnectionAsync(Ct);
            if (Interlocked.Increment(ref ready) == 2) gate.TrySetResult();
            await gate.Task.WaitAsync(Ct);
            db.OidcRateLimitBuckets.Add(Bucket(Policies[0]));
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
        Assert.Single(await read.OidcRateLimitBuckets.ToListAsync(Ct));
    }

    private static OidcRateLimitBucketEntity Bucket(string policy, string digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", int count = 1) => new()
    {
        Policy = policy, PartitionDigest = digest, PermitCount = count,
        WindowExpiresAt = Instant.AddTicks(1234560)
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
                    path = Path.Combine(Path.GetTempPath(), $"rate-limit-schema-{Guid.NewGuid():N}.db");
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
            return assembly.CreateMigration(assembly.Migrations.Single(x => x.Key.EndsWith("_AddOidcRateLimitBuckets", StringComparison.Ordinal)).Value, db.Database.ProviderName!);
        }
        public async Task<bool> TableExistsAsync(IdentityDbContext db) => (await RowsAsync(db, provider == "SQLite"
            ? "SELECT name FROM sqlite_master WHERE type='table' AND name='oidc_rate_limit_buckets'"
            : "SELECT tablename FROM pg_tables WHERE schemaname=current_schema() AND tablename='oidc_rate_limit_buckets'")).Count == 1;
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
                ? "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE tbl_name <> 'oidc_rate_limit_buckets' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '__EF%' ORDER BY name"
                : "SELECT table_name,column_name,data_type,is_nullable,character_maximum_length,column_default FROM information_schema.columns WHERE table_schema=current_schema() AND table_name <> 'oidc_rate_limit_buckets' AND table_name NOT LIKE '__EF%' ORDER BY table_name,ordinal_position");
            if (provider == "PostgreSQL") rows.AddRange(await RowsAsync(db, "SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname=current_schema() AND tablename <> 'oidc_rate_limit_buckets' AND tablename NOT LIKE '__EF%' ORDER BY indexname"));
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
