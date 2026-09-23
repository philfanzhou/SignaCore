using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Hosting;
using ServiceMantle.Installation;
using SignaCore.Database;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Acceptance of the legacy-database upgrade contract on real historical schemas: a sample
/// database is pinned at a fixed past point of the migration lineage with raw, era-accurate
/// product rows, then booted by the current build. The upgrade must complete in place, keep every
/// product row (including the unmapped <c>audit_logs</c> history), reach a completed installation
/// through the protected import, and never reopen anonymous setup — before the upgrade, after a
/// failed import, and after a safe retry.
/// <para>
/// The pre-change launcher settings the import consumes are injected the same way the existing
/// first-run tests inject them. The refusal path for databases still holding unmigrated legacy
/// <c>system_settings</c> rows is pinned by <see cref="SystemSettingsRetirementTests"/> and is not
/// re-tested here.
/// </para>
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class LegacyDatabaseUpgradeAcceptanceTests : IAsyncLifetime
{
    private const string RootSecret = "legacy-upgrade-acceptance-root-secret";
    private const string PublicBaseUrl = "https://identity.example.test";
    private const string SetupEntryPath = "/management/v1/setup";

    /// <summary>The first point of the system_settings era: the deepest in-place upgrade chain.</summary>
    private const string SystemSettingsEraStart = "20260815054216_AddSystemSettingsAndInstallationState";

    /// <summary>The last point before the audit unmap: the upgrade applies exactly the #358 surface.</summary>
    private const string LastPointBeforeAuditUnmap = "20260921130547_RetireSystemSettings";

    private string _workingDirectory = string.Empty;
    private string _databasePath = string.Empty;
    private string _connectionString = string.Empty;
    private WebApplicationFactory<Program>? _factory;

    public ValueTask InitializeAsync()
    {
        _workingDirectory = Path.Combine(Path.GetTempPath(), $"signacore-upgrade-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_workingDirectory);
        _databasePath = Path.Combine(_workingDirectory, "signacore.db");
        _connectionString = new SqliteConnectionStringBuilder { DataSource = _databasePath }.ConnectionString;
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        _factory?.Dispose();

        for (var attempt = 0; attempt < 5; attempt++)
        {
            TestSqlitePools.ClearAll();
            try
            {
                if (Directory.Exists(_workingDirectory))
                {
                    Directory.Delete(_workingDirectory, recursive: true);
                }

                return;
            }
            catch (IOException) when (attempt < 4)
            {
                await Task.Delay(200);
            }
        }
    }

    [Theory]
    [InlineData(SystemSettingsEraStart)]
    [InlineData(LastPointBeforeAuditUnmap)]
    public async Task HistoricalSample_UpgradesInPlace_PreservesEveryProductRow_AndNeverReopensSetup(
        string pinnedMigration)
    {
        await StageHistoricalSampleAsync(pinnedMigration);

        using var http = await StartHostAsync(LegacyLauncherSettings(issuer: PublicBaseUrl));

        var status = await http.GetAsync(SetupEntryPath, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, status.StatusCode);
        Assert.Equal(
            "completed",
            (await status.Content.ReadFromJsonAsync<JsonElement>(
                cancellationToken: TestContext.Current.CancellationToken))
                .GetProperty("status").GetString());

        await using var db = OpenDatabase();

        // The upgrade completed in place: every migration of the current build is applied, the
        // guarded system_settings table is gone, and the unmapped legacy audit history survives.
        var expectedMigrations = db.Database.GetService<IMigrationsAssembly>().Migrations.Count;
        var appliedMigrations = await db.Database.SqlQuery<int>(
            $"""SELECT COUNT(*) AS "Value" FROM __EFMigrationsHistory""")
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(expectedMigrations, appliedMigrations);
        Assert.False(await SharedSettingTestDatabase.LegacyTableExistsAsync(
            db, TestContext.Current.CancellationToken));
        Assert.Equal(2, await CountLegacyAuditRowsAsync(db));

        // Every staged product row survives the upgrade, table by table.
        Assert.Equal(1, await db.Accounts.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(
            1, await db.PasswordCredentials.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(
            1, await db.AppRegistrations.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(
            2, await db.LoginHistories.CountAsync(cancellationToken: TestContext.Current.CancellationToken));

        // The completed installation came from the protected import: aggregate version 1, no
        // setup code ever issued, no new administrator created over the deployment's own account.
        var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(
            db, TestContext.Current.CancellationToken);
        Assert.NotNull(aggregate);
        Assert.True(aggregate!.Version >= 1);
        Assert.Equal(
            "legacy_admin",
            SharedSettingTestDatabase.ParseValues(aggregate)["admin.username"]);
        var installation = await db.ServiceInstallations.SingleAsync(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(InstallationStatus.Completed, installation.Status);
        Assert.Null(installation.SetupCodeDigest);
        Assert.Equal(1, await db.Accounts.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A failed import at the historical sample leaves the database upgrade-complete but with zero
    /// partial import state, and a restart with the deployment's input fixed completes the import
    /// safely over the preserved product rows.
    /// </summary>
    [Fact]
    public async Task InvalidImportAtTheHistoricalSample_LeavesNoPartialState_AndARestartWithFixedInputImportsSafely()
    {
        await StageHistoricalSampleAsync(SystemSettingsEraStart);

        var exception = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var http = await StartHostAsync(LegacyLauncherSettings(issuer: "https://somewhere.else.test"));
            await http.GetAsync(SetupEntryPath, TestContext.Current.CancellationToken);
        });

        // The failure names keys or classification codes, never the submitted values.
        var flattened = Flatten(exception);
        Assert.DoesNotContain("somewhere.else.test", flattened, StringComparison.Ordinal);
        Assert.DoesNotContain("legacy_admin", flattened, StringComparison.Ordinal);

        await using (var db = OpenDatabase())
        {
            // Zero partial import state: no aggregate and no import audit. The schema upgrade did
            // complete, and crossing the AddServiceInstallations migration seeded the fail-closed
            // adoption row (a Completed row for pre-existing business data) — the failed import
            // leaves exactly that row, unchanged: same Completed status, no setup code, no
            // completion rewrite. Anonymous setup never reopens through any of it.
            Assert.Null(await SharedSettingTestDatabase.LoadAggregateAsync(
                db, TestContext.Current.CancellationToken));
            var adopted = await db.ServiceInstallations.AsNoTracking().SingleAsync(
                cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal(InstallationStatus.Completed, adopted.Status);
            Assert.Null(adopted.SetupCodeDigest);
            Assert.Equal(1, adopted.Version);
            Assert.Equal(
                0, (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                        db, TestContext.Current.CancellationToken))
                    .Count(row => row.Action == "installation.legacy_import.completed"));
            await AssertProductRowsPreservedAsync(db);
        }

        _factory?.Dispose();
        _factory = null;

        using (var http = await StartHostAsync(LegacyLauncherSettings(issuer: PublicBaseUrl)))
        {
            Assert.Equal(
                "completed",
                (await (await http.GetAsync(SetupEntryPath, TestContext.Current.CancellationToken)).Content
                    .ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken))
                    .GetProperty("status").GetString());
        }

        await using (var db = OpenDatabase())
        {
            var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(
                db, TestContext.Current.CancellationToken);
            Assert.NotNull(aggregate);
            Assert.True(aggregate!.Version >= 1);
            Assert.Equal(
                InstallationStatus.Completed,
                (await db.ServiceInstallations.SingleAsync(
                    cancellationToken: TestContext.Current.CancellationToken)).Status);
            await AssertProductRowsPreservedAsync(db);
        }
    }

    /// <summary>
    /// Pins the database at a historical lineage point through the real migrator and stages
    /// era-accurate product rows with raw SQL: exactly the columns the initial-create schema of
    /// these tables defines, so the sample is what a deployment frozen at that build would own.
    /// </summary>
    private async Task StageHistoricalSampleAsync(string pinnedMigration)
    {
        await using var db = OpenDatabase();
        var migrator = db.Database.GetService<IMigrator>();
        await migrator.MigrateAsync(pinnedMigration, TestContext.Current.CancellationToken);

        var accountId = Guid.NewGuid();
        var now = (DateTimeOffset.UtcNow.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10;

        await db.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO accounts (id, is_active, created_at, total_login_count)
            VALUES ({accountId}, 1, {now}, 0)
            """,
            TestContext.Current.CancellationToken);
        await db.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO password_credentials (id, account_id, username, username_normalized, password_hash, created_at)
            VALUES ({Guid.NewGuid()}, {accountId}, 'legacy_admin', 'LEGACY_ADMIN',
                'not-a-real-hash-but-a-staged-value', {now})
            """,
            TestContext.Current.CancellationToken);
        await db.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO app_registrations (id, app_id, app_id_normalized, app_secret_hash, app_name, is_active, created_at)
            VALUES ({Guid.NewGuid()}, 'legacy_app', 'LEGACY_APP', 'not-a-real-hash-but-a-staged-value', 'Legacy App', 1, {now})
            """,
            TestContext.Current.CancellationToken);
        await db.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO login_histories (id, account_id, username, auth_method, event_type, created_at)
            VALUES
                ({Guid.NewGuid()}, {accountId}, 'legacy_admin', 'password', 'login_succeeded', {now}),
                ({Guid.NewGuid()}, {accountId}, 'legacy_admin', 'password', 'login_failed', {now})
            """,
            TestContext.Current.CancellationToken);
        await db.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO audit_logs (id, action, target_type, target_id, created_at)
            VALUES
                ({Guid.NewGuid()}, 'account.login', 'account', {accountId.ToString()}, {now}),
                ({Guid.NewGuid()}, 'app_registration.created', 'app_registration', 'legacy_app', {now})
            """,
            TestContext.Current.CancellationToken);

        db.ChangeTracker.Clear();
    }

    private static IDictionary<string, string?> LegacyLauncherSettings(string issuer) =>
        new Dictionary<string, string?>
        {
            // What the pre-change launcher used to inject; the import reads it once and stores it.
            [SystemSettingKeys.PublicBaseUrl] = PublicBaseUrl,
            [SystemSettingKeys.JwtIssuer] = issuer,
            [SystemSettingKeys.LegacyAdminBootstrapUsername] = "legacy_admin"
        };

    private async Task<HttpClient> StartHostAsync(IDictionary<string, string?> launcherSettings)
    {
        var bootstrapFilePath = await InstallationTestSupport.PrepareUninstalledBootstrapAsync(
            _workingDirectory,
            new DatabaseOptions { Provider = "SQLite", ConnectionString = _connectionString },
            RootSecret);

        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("environment", Environments.Production);
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath);
                foreach (var (key, value) in launcherSettings)
                {
                    builder.UseSetting(key, value);
                }
            });

        return _factory.CreateClient();
    }

    private static async Task AssertProductRowsPreservedAsync(IdentityDbContext db)
    {
        Assert.Equal(1, await db.Accounts.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(1, await db.PasswordCredentials.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(1, await db.AppRegistrations.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(2, await db.LoginHistories.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(2, await CountLegacyAuditRowsAsync(db));
    }

    private static async Task<int> CountLegacyAuditRowsAsync(IdentityDbContext db) =>
        await db.Database.SqlQuery<int>(
            $"""SELECT COUNT(*) AS "Value" FROM audit_logs""")
            .SingleAsync(TestContext.Current.CancellationToken);

    private static string Flatten(Exception exception)
    {
        var messages = new List<string>();
        for (var current = exception; current is not null; current = current.InnerException)
        {
            messages.Add(current.Message);
        }

        return string.Join(" | ", messages);
    }

    private IdentityDbContext OpenDatabase()
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = _connectionString
        });
        return new IdentityDbContext(optionsBuilder.Options);
    }
}
