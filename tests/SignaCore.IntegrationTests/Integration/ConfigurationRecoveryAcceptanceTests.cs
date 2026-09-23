using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ServiceMantle.Configuration;
using ServiceMantle.Installation;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Acceptance of the configuration-failure recovery contract: an import carrying type-invalid
/// input is refused closed and retries safely once fixed; a stale management update conflicts with
/// zero partial state and succeeds at the current version, with audits only for the commits that
/// happened; a wrong root key refuses activation while every stored row — the aggregate included —
/// stays byte-identical, and the correct key recovers the consistent snapshot; a corrupted
/// sensitive envelope is refused without reopening setup, and repairing the row restores the
/// service.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class ConfigurationRecoveryAcceptanceTests : IAsyncLifetime
{
    private const string Root = "/management/v1";
    private const string CookieName = "__Host-ServiceMantle.Management";
    private const string RootSecret = "configuration-recovery-root-secret";
    private const string AdminUsername = "config_admin";
    private const string AdminPassword = "ConfigAdmin123";
    private const string PublicBaseUrl = "https://identity.example.test";

    private string _workingDirectory = string.Empty;
    private string _databasePath = string.Empty;
    private string _connectionString = string.Empty;
    private string _bootstrapFilePath = string.Empty;
    private WebApplicationFactory<Program>? _factory;
    private readonly List<WebApplicationFactory<Program>> _factories = [];

    public ValueTask InitializeAsync()
    {
        _workingDirectory = Path.Combine(Path.GetTempPath(), $"signacore-config-recovery-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_workingDirectory);
        _databasePath = Path.Combine(_workingDirectory, "signacore.db");
        _connectionString = new SqliteConnectionStringBuilder { DataSource = _databasePath }.ConnectionString;
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var factory in _factories)
        {
            factory.Dispose();
        }

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

    /// <summary>
    /// A pre-change deployment whose launcher carried a type-invalid value for a numeric setting
    /// is refused by the import's validation — key name and classification code only — with zero
    /// partial state, and the next start with the deployment's input fixed completes the import.
    /// </summary>
    [Fact]
    public async Task TypeInvalidImportInput_IsRefusedClosed_AndARestartWithFixedInputImports()
    {
        await SeedPreChangeDeploymentAsync();

        var invalid = new Dictionary<string, string?>
        {
            [SystemSettingKeys.PublicBaseUrl] = PublicBaseUrl,
            [SystemSettingKeys.JwtIssuer] = PublicBaseUrl,
            [SystemSettingKeys.LegacyAdminBootstrapUsername] = "legacy_admin",
            // A numeric catalog key carrying non-numeric text: the composite validation refuses
            // the whole candidate.
            [SystemSettingKeys.ConsulPort] = "not-a-port"
        };
        var exception = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var http = await StartImportHostAsync(invalid);
            await http.GetAsync("/health/live", TestContext.Current.CancellationToken);
        });
        _factory?.Dispose();
        _factory = null;

        // The refusal carries the normalized key name and the closed classification code, never
        // the submitted value.
        var flattened = Flatten(exception);
        Assert.Contains("consul.port (setting.invalid_number)", flattened, StringComparison.Ordinal);
        Assert.DoesNotContain("not-a-port", flattened, StringComparison.Ordinal);

        await using (var db = OpenDatabase())
        {
            Assert.Null(await SharedSettingTestDatabase.LoadAggregateAsync(
                db, TestContext.Current.CancellationToken));
            Assert.Equal(
                0, await db.ServiceInstallations.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
            Assert.Equal(
                1, await db.PasswordCredentials.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        }

        invalid[SystemSettingKeys.ConsulPort] = "18500";
        using (var http = await StartImportHostAsync(invalid))
        {
            var status = await http.GetAsync(Root + "/setup", TestContext.Current.CancellationToken);
            Assert.Equal(
                "completed",
                (await status.Content.ReadFromJsonAsync<JsonElement>(
                    cancellationToken: TestContext.Current.CancellationToken))
                    .GetProperty("status").GetString());
        }

        await using (var db = OpenDatabase())
        {
            var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(
                db, TestContext.Current.CancellationToken);
            Assert.NotNull(aggregate);
            Assert.True(aggregate!.Version >= 1);
        }
    }

    /// <summary>
    /// A stale expected version conflicts with zero partial state and zero audit; the retry at the
    /// current version commits, and the shared audits cover exactly the commits that happened —
    /// never the conflict.
    /// </summary>
    [Fact]
    public async Task StaleExpectedVersion_ConflictsWithZeroPartialState_AndRetriesAtTheCurrentVersion()
    {
        await PrepareCompletedInstallationAsync();
        using var first = CreateInstance();
        using var firstAdmin = await CreateAdminClientAsync(first);
        var staleVersion = await ReadConfigurationVersionAsync(firstAdmin);

        // Another instance commits first, the way a concurrent deployment would.
        using var second = CreateInstance();
        using var secondAdmin = await CreateAdminClientAsync(second);
        var committed = await secondAdmin.PostAsJsonAsync(
            Root + "/settings",
            new
            {
                expectedVersion = staleVersion,
                changes = new[] { new { key = "sms.max_sends_per_hour", value = "5" } }
            },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, committed.StatusCode);

        var auditsAfterCommit = 0;
        await using (var db = OpenDatabase())
        {
            auditsAfterCommit = (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                db, TestContext.Current.CancellationToken)).Count;
        }

        // The stale submission conflicts, and nothing changes: same version, no new audits.
        var conflicted = await firstAdmin.PostAsJsonAsync(
            Root + "/settings",
            new
            {
                expectedVersion = staleVersion,
                changes = new[] { new { key = "sms.max_sends_per_hour", value = "987654321" } }
            },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Conflict, conflicted.StatusCode);
        Assert.DoesNotContain(
            "987654321",
            await conflicted.Content.ReadAsStringAsync(TestContext.Current.CancellationToken),
            StringComparison.Ordinal);

        await using (var db = OpenDatabase())
        {
            Assert.Equal(staleVersion + 1,
                (await SharedSettingTestDatabase.LoadAggregateAsync(
                    db, TestContext.Current.CancellationToken))!.Version);
            Assert.Equal(auditsAfterCommit,
                (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                    db, TestContext.Current.CancellationToken)).Count);
        }

        // The retry at the current version commits and is the only new audit writer.
        var retried = await firstAdmin.PostAsJsonAsync(
            Root + "/settings",
            new
            {
                expectedVersion = staleVersion + 1,
                changes = new[] { new { key = "sms.max_sends_per_hour", value = "6" } }
            },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, retried.StatusCode);

        await using (var db = OpenDatabase())
        {
            Assert.Equal(staleVersion + 2,
                (await SharedSettingTestDatabase.LoadAggregateAsync(
                    db, TestContext.Current.CancellationToken))!.Version);
            Assert.Equal(auditsAfterCommit + 1,
                (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                    db, TestContext.Current.CancellationToken)).Count);
            Assert.Equal("6", SharedSettingTestDatabase.ParseValues(
                (await SharedSettingTestDatabase.LoadAggregateAsync(
                    db, TestContext.Current.CancellationToken))!)["sms.max_sends_per_hour"]);
        }
    }

    /// <summary>
    /// A wrong root key refuses activation — the sensitive settings it cannot decrypt are named by
    /// key, never by value — while every stored row stays byte-identical (the aggregate included),
    /// and the correct key restarts into the same consistent snapshot.
    /// </summary>
    [Fact]
    public async Task WrongRootKey_RefusesActivation_KeepsEveryRowByteIdentical_AndTheCorrectKeyRecovers()
    {
        await PrepareCompletedInstallationAsync();
        using (var owner = CreateInstance())
        {
            Assert.Equal(HttpStatusCode.OK, (await owner.CreateClient()
                .GetAsync("/health/ready", TestContext.Current.CancellationToken)).StatusCode);
        }

        SharedSettingTestDatabase.AggregateRow aggregateBefore;
        string auditsBefore;
        string keysBefore;
        await using (var db = OpenDatabase())
        {
            aggregateBefore = (await SharedSettingTestDatabase.LoadAggregateAsync(
                db, TestContext.Current.CancellationToken))!;
            auditsBefore = JsonSerializer.Serialize(await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                db, TestContext.Current.CancellationToken));
            keysBefore = JsonSerializer.Serialize(await db.SecurityKeys.AsNoTracking()
                .OrderBy(key => key.KeyId)
                .Select(key => new { key.KeyId, key.EncryptedPrivateKeyParams, key.EncryptionSalt })
                .ToListAsync(cancellationToken: TestContext.Current.CancellationToken));
        }

        var exception = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var wrongKey = CreateInstance(rootSecret: "a-completely-wrong-root-secret");
            await wrongKey.CreateClient().GetAsync("/health/live", TestContext.Current.CancellationToken);
        });

        var flattened = Flatten(exception);
        Assert.Contains("could not be decrypted", flattened, StringComparison.Ordinal);
        Assert.DoesNotContain(RootSecret, flattened, StringComparison.Ordinal);
        Assert.DoesNotContain("a-completely-wrong-root-secret", flattened, StringComparison.Ordinal);

        await using (var db = OpenDatabase())
        {
            // The last valid version is retained untouched: no rewrite, no partial activation.
            Assert.Equal(aggregateBefore.Version,
                (await SharedSettingTestDatabase.LoadAggregateAsync(
                    db, TestContext.Current.CancellationToken))!.Version);
            Assert.Equal(aggregateBefore.ValuesJson,
                (await SharedSettingTestDatabase.LoadAggregateAsync(
                    db, TestContext.Current.CancellationToken))!.ValuesJson);
            Assert.Equal(auditsBefore, JsonSerializer.Serialize(
                await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                    db, TestContext.Current.CancellationToken)));
            Assert.Equal(keysBefore, JsonSerializer.Serialize(await db.SecurityKeys.AsNoTracking()
                .OrderBy(key => key.KeyId)
                .Select(key => new { key.KeyId, key.EncryptedPrivateKeyParams, key.EncryptionSalt })
                .ToListAsync(cancellationToken: TestContext.Current.CancellationToken)));
            Assert.Equal(
                InstallationStatus.Completed,
                (await db.ServiceInstallations.SingleAsync(
                    cancellationToken: TestContext.Current.CancellationToken)).Status);
        }

        // The correct key recovers the consistent snapshot, at the retained version.
        using (var recovered = CreateInstance())
        using (var ready = await recovered.CreateClient()
            .GetAsync("/health/ready", TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
        }

        await using (var db = OpenDatabase())
        {
            Assert.Equal(aggregateBefore.Version,
                (await SharedSettingTestDatabase.LoadAggregateAsync(
                    db, TestContext.Current.CancellationToken))!.Version);
        }
    }

    /// <summary>
    /// A corrupted sensitive envelope refuses activation without reopening setup and without
    /// rewriting the damaged row; restoring the row recovers the service at the same version.
    /// </summary>
    [Fact]
    public async Task CorruptedSensitiveEnvelope_RefusesActivation_WithoutRewrite_AndRepairRestores()
    {
        await PrepareCompletedInstallationAsync();
        using (var instance = CreateInstance())
        {
            using var admin = await CreateAdminClientAsync(instance);
            var committed = await admin.PostAsJsonAsync(
                Root + "/settings",
                new
                {
                    expectedVersion = await ReadConfigurationVersionAsync(admin),
                    changes = new[] { new { key = "sms.otp_hmac_key", value = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=" } }
                },
                TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, committed.StatusCode);
        }

        string intactValues;
        await using (var db = OpenDatabase())
        {
            var aggregate = (await SharedSettingTestDatabase.LoadAggregateAsync(
                db, TestContext.Current.CancellationToken))!;
            intactValues = aggregate.ValuesJson;
            await db.Database.ExecuteSqlAsync(
                $"""
                UPDATE service_settings SET values_json = {aggregate.ValuesJson.Replace("sm:v1:", "xx:v1:", StringComparison.Ordinal)}
                """,
                TestContext.Current.CancellationToken);
        }

        var exception = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var corrupted = CreateInstance();
            await corrupted.CreateClient().GetAsync("/health/live", TestContext.Current.CancellationToken);
        });

        // The refusal names the damaged keys and never a value; the damaged row is retained
        // byte-identically — no rewrite, no partial activation, and the installation stays
        // completed so anonymous setup never reopens.
        var flattened = Flatten(exception);
        Assert.Contains("could not be decrypted", flattened, StringComparison.Ordinal);
        Assert.DoesNotContain("xx:v1:", flattened, StringComparison.Ordinal);
        await using (var db = OpenDatabase())
        {
            Assert.Equal(intactValues.Replace("sm:v1:", "xx:v1:", StringComparison.Ordinal),
                (await SharedSettingTestDatabase.LoadAggregateAsync(
                    db, TestContext.Current.CancellationToken))!.ValuesJson);
            Assert.Equal(
                InstallationStatus.Completed,
                (await db.ServiceInstallations.SingleAsync(
                    cancellationToken: TestContext.Current.CancellationToken)).Status);
        }

        // The repair: restore the intact row and the service returns at the same version.
        await using (var db = OpenDatabase())
        {
            await db.Database.ExecuteSqlAsync(
                $"""UPDATE service_settings SET values_json = {intactValues}""",
                TestContext.Current.CancellationToken);
        }

        using (var recovered = CreateInstance())
        using (var ready = await recovered.CreateClient()
            .GetAsync("/health/ready", TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
        }
    }

    private async Task PrepareCompletedInstallationAsync()
    {
        _bootstrapFilePath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
            _workingDirectory,
            new DatabaseOptions { Provider = "SQLite", ConnectionString = _connectionString },
            RootSecret,
            AdminUsername,
            AdminPassword);
    }

    private WebApplicationFactory<Program> CreateInstance(string? rootSecret = null)
    {
        var bootstrapFilePath = _bootstrapFilePath;
        if (rootSecret is not null)
        {
            // The wrong-secret bootstrap lives in its own directory so the original bootstrap file
            // — the one the correct-key recovery needs — is never replaced.
            bootstrapFilePath = InstallationTestSupport.PrepareUninstalledBootstrapAsync(
                Path.Combine(_workingDirectory, "wrong-root"),
                new DatabaseOptions { Provider = "SQLite", ConnectionString = _connectionString },
                rootSecret).GetAwaiter().GetResult();
        }

        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath));
        _factories.Add(factory);
        factory.CreateClient();
        return factory;
    }

    private async Task<HttpClient> StartImportHostAsync(IDictionary<string, string?> launcherSettings)
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
        _factories.Add(_factory);

        return _factory.CreateClient();
    }

    private static async Task<HttpClient> CreateAdminClientAsync(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        var request = new HttpRequestMessage(HttpMethod.Post, Root + "/session/login")
        {
            Content = new StringContent(
                JsonSerializer.Serialize(new { username = AdminUsername, password = AdminPassword }),
                Encoding.UTF8,
                "application/json")
        };
        request.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(response.Headers.NonValidated.TryGetValues("Set-Cookie", out var cookies));
        var cookie = cookies
            .Single(value => value.StartsWith($"{CookieName}=", StringComparison.Ordinal))
            .Split(';')[0];
        client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", cookie);
        return client;
    }

    private static async Task<long> ReadConfigurationVersionAsync(HttpClient admin)
    {
        using var response = await admin.GetAsync(Root + "/settings", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken))
            .GetProperty("version").GetInt64();
    }

    private async Task SeedPreChangeDeploymentAsync()
    {
        await using var db = OpenDatabase();
        await db.Database.MigrateAsync(TestContext.Current.CancellationToken);

        var accountId = Guid.NewGuid();
        db.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        db.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = "legacy_admin",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("LegacyAdmin123"),
            CreatedAt = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync(TestContext.Current.CancellationToken);
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

    private static string Flatten(Exception exception)
    {
        var messages = new List<string>();
        for (var current = exception; current is not null; current = current.InnerException)
        {
            messages.Add(current.Message);
        }

        return string.Join(" | ", messages);
    }
}
