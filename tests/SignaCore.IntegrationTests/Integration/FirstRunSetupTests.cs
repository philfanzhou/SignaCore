using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ServiceMantle;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Keys;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// End-to-end behavior of a brand-new, uninitialized database: the PendingSetup host built on the
/// shared ServiceMantle setup entry, the one-time code, and the atomic completion transaction.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class FirstRunSetupTests : IAsyncLifetime
{
    private const string RootSecret = "first-run-setup-root-secret";
    private const string AdminUsername = "setup_admin";
    private const string AdminPassword = "SetupAdmin123";
    private const string PublicBaseUrl = "https://identity.example.test";
    private const string SetupEntryPath = "/management/v1/setup";
    private const string UnsafeRequestHeader = "X-ServiceMantle-Request";
    private const string WrongCode = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    private string _workingDirectory = string.Empty;
    private string _databasePath = string.Empty;
    private string _connectionString = string.Empty;
    private WebApplicationFactory<Program>? _factory;

    public ValueTask InitializeAsync()
    {
        _workingDirectory = Path.Combine(Path.GetTempPath(), $"signacore-setup-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_workingDirectory);
        _databasePath = Path.Combine(_workingDirectory, "signacore.db");
        _connectionString = new SqliteConnectionStringBuilder { DataSource = _databasePath }.ConnectionString;
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        _factory?.Dispose();

        // The PendingSetup host stops itself after a successful completion, and its restart
        // watcher releases its SQLite scope asynchronously; a single pool clear can therefore race
        // a still-open connection. Retry the cleanup briefly instead of failing the test on the
        // working directory's deletion.
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

    [Fact]
    public async Task EmptyDatabase_ReportsPendingThroughTheSharedEntry()
    {
        using var http = await StartHostAsync();

        var response = await http.GetAsync(SetupEntryPath, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("pending", body.GetProperty("status").GetString());
    }

    [Fact]
    public async Task EmptyDatabase_CreatesAPendingInstallationWithAHashedSetupCode()
    {
        using var _ = await StartHostAsync();

        await using var db = OpenDatabase();
        var installation = await db.ServiceInstallations.SingleAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(InstallationStatus.PendingSetup, installation.Status);
        Assert.NotNull(installation.SetupCodeDigest);
        // The shared store persists only the versioned digest, never the plaintext.
        Assert.StartsWith("sha256-v1:", installation.SetupCodeDigest, StringComparison.Ordinal);
        Assert.NotNull(installation.SetupCodeExpiresAtUtc);
        Assert.Null(installation.CompletedAtUtc);
    }

    /// <summary>
    /// While the installation is pending the identity surface does not exist. A read matches only
    /// the phase-admitted SPA fallback, whose handler declines API-shaped paths with a plain 404. A
    /// write matches no endpoint at all — routing answers it with its synthetic method-mismatch
    /// endpoint — and the shared phase gate answers that endpoint with the fixed
    /// <c>503 service.phase.unavailable</c>, exactly as the Bootstrap Configuration Mode host
    /// already behaves.
    /// </summary>
    [Theory]
    [InlineData("/api/auth/token")]
    [InlineData("/oauth2/token")]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    [InlineData("/.well-known/jwks.json")]
    [InlineData("/metrics")]
    public async Task NormalApiReads_WhilePending_AreNotFoundAndWrites_ArePhaseUnavailable(string path)
    {
        using var http = await StartHostAsync();

        var read = await http.GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, read.StatusCode);

        var write = await http.PostAsync(path, JsonContent.Create(new { grantType = "password" }),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, write.StatusCode);
        Assert.Equal(
            "{\"errorCode\":\"service.phase.unavailable\"}",
            await write.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// Liveness has to be true so a launcher can wait for the setup page; readiness has to be false
    /// so a load balancer never routes authentication traffic here.
    /// </summary>
    [Fact]
    public async Task HealthEndpoints_WhilePending_ReportLiveButNotReady()
    {
        using var http = await StartHostAsync();

        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync("/health/live", TestContext.Current.CancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await http.GetAsync("/health/ready", TestContext.Current.CancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await http.GetAsync("/health", TestContext.Current.CancellationToken)).StatusCode);
    }

    /// <summary>
    /// The fixed cross-site request header is part of the shared entry contract: without it the
    /// submission is refused before the executor runs, which the still-valid code afterwards
    /// proves — a consumed code could never complete the installation a second time.
    /// </summary>
    [Fact]
    public async Task Submission_WithoutTheUnsafeRequestHeader_NeverRunsTheExecutor()
    {
        using var http = await StartHostAsync();
        var code = await RotateSetupCodeAsync();

        var headerless = await PostSetupAsync(http, code, includeUnsafeRequestHeader: false);

        Assert.Equal(HttpStatusCode.BadRequest, headerless.StatusCode);

        var accepted = await PostSetupAsync(http, code);
        Assert.Equal(HttpStatusCode.NoContent, accepted.StatusCode);
    }

    [Fact]
    public async Task Setup_WithAWrongCode_IsRefusedAndChangesNothing()
    {
        using var http = await StartHostAsync();

        var response = await PostSetupAsync(http, WrongCode);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain(AdminPassword, body, StringComparison.Ordinal);

        await using var db = OpenDatabase();
        Assert.Equal(InstallationStatus.PendingSetup, (await db.ServiceInstallations.SingleAsync(
            cancellationToken: TestContext.Current.CancellationToken)).Status);
        Assert.False(await db.Accounts.AnyAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.False(await db.SystemSettings.AnyAsync(cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Setup_WithAnExpiredCode_IsRefused()
    {
        using var http = await StartHostAsync();
        var code = await RotateSetupCodeAsync(expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1));

        var response = await PostSetupAsync(http, code);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// A rotated code invalidates the previous one; only the newest code can complete the
    /// installation.
    /// </summary>
    [Fact]
    public async Task Setup_WithASupersededCode_IsRefusedAndTheNewCodeWins()
    {
        using var http = await StartHostAsync();
        var superseded = await RotateSetupCodeAsync();
        var current = await RotateSetupCodeAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, (await PostSetupAsync(http, superseded)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await PostSetupAsync(http, current)).StatusCode);
    }

    public static TheoryData<string> InvalidInputShapes()
    {
        return
        [
            "missing-password",
            "missing-publicBaseUrl",
            "extra-field",
            "wrong-type-allowNonHttpsIssuer",
            "wrong-type-username",
        ];
    }

    /// <summary>
    /// Every structural input problem is the one fixed validation rejection, changes nothing, and
    /// leaves the code consumable.
    /// </summary>
    [Theory]
    [MemberData(nameof(InvalidInputShapes))]
    public async Task Setup_WithAStructurallyInvalidInput_IsRefusedAndTheCodeStaysUsable(string shape)
    {
        using var http = await StartHostAsync();
        var code = await RotateSetupCodeAsync();

        var response = await PostSetupAsync(http, code, inputShape: shape);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertInstallationStillPendingAsync();

        Assert.Equal(HttpStatusCode.NoContent, (await PostSetupAsync(http, code)).StatusCode);
    }

    public static TheoryData<string> InvalidInputValues()
    {
        return
        [
            "weak-password",
            "plain-http-publicBaseUrl",
            "empty-jwtAudience",
            "overlong-username",
            "taken-username",
        ];
    }

    /// <summary>
    /// Every semantic input problem is the one fixed validation rejection (the shared 400 carries
    /// no field-level reason), rolls the transaction back, and leaves the code consumable.
    /// </summary>
    [Theory]
    [MemberData(nameof(InvalidInputValues))]
    public async Task Setup_WithASemanticallyInvalidInput_IsRefusedAndTheCodeStaysUsable(string value)
    {
        using var http = await StartHostAsync();
        var code = await RotateSetupCodeAsync();
        var existingAccounts = 0;
        var existingCredentials = 0;
        if (value == "taken-username")
        {
            await SeedExistingAdministratorAsync();
            existingAccounts = 1;
            existingCredentials = 1;
        }

        var response = await PostSetupAsync(http, code, inputValue: value);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertNothingNewWasWrittenAsync(existingAccounts, existingCredentials);

        Assert.Equal(HttpStatusCode.NoContent, (await PostSetupAsync(http, code)).StatusCode);
    }

    [Fact]
    public async Task Setup_WithExplicitHttpOptIn_AcceptsHttpWithoutClassifyingTheHost()
    {
        using var http = await StartHostAsync();
        var code = await RotateSetupCodeAsync();

        var response = await PostSetupAsync(
            http,
            code,
            publicBaseUrl: "http://identity.example.test",
            allowNonHttpsIssuer: true);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        await using var db = OpenDatabase();
        var settings = await db.SystemSettings.ToDictionaryAsync(setting => setting.Key, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("true", settings[SystemSettingKeys.SecurityAllowNonHttpsIssuer].Value);
    }

    [Fact]
    public async Task Setup_StoresTheOperatorSelectedAudience()
    {
        using var http = await StartHostAsync();
        var code = await RotateSetupCodeAsync();

        var response = await PostSetupAsync(http, code, jwtAudience: "urn:example:services");

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        await using var db = OpenDatabase();
        Assert.Equal(
            "urn:example:services",
            (await db.SystemSettings.SingleAsync(
                setting => setting.Key == SystemSettingKeys.JwtAudience,
                cancellationToken: TestContext.Current.CancellationToken)).Value);
    }

    [Fact]
    public async Task Setup_WithAValidCode_CompletesAtomically()
    {
        using var http = await StartHostAsync();
        var code = await RotateSetupCodeAsync();

        var response = await PostSetupAsync(http, code);
        var responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(0, responseBody.Length);
        // No candidate code, password, or root secret is echoed by any completion answer.
        Assert.DoesNotContain(code, responseBody, StringComparison.Ordinal);
        Assert.DoesNotContain(AdminPassword, responseBody, StringComparison.Ordinal);
        Assert.DoesNotContain(RootSecret, responseBody, StringComparison.Ordinal);

        await using var db = OpenDatabase();
        var installation = await db.ServiceInstallations.SingleAsync(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(InstallationStatus.Completed, installation.Status);
        Assert.NotNull(installation.CompletedAtUtc);
        // The one-time code is invalidated in the same transaction that completes installation.
        Assert.Null(installation.SetupCodeDigest);
        Assert.Null(installation.SetupCodeExpiresAtUtc);
        // The completion published configuration version 1.
        Assert.Equal(1, await db.SystemSettings.MaxAsync(
            setting => (int?)setting.Version, cancellationToken: TestContext.Current.CancellationToken));

        var credential = await db.PasswordCredentials.SingleAsync(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(AdminUsername, credential.Username);
        Assert.True(BCrypt.Net.BCrypt.Verify(AdminPassword, credential.PasswordHash));

        var settings = await db.SystemSettings.ToDictionaryAsync(setting => setting.Key, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(PublicBaseUrl, settings[SystemSettingKeys.PublicBaseUrl].Value);
        Assert.Equal(PublicBaseUrl, settings[SystemSettingKeys.JwtIssuer].Value);
        Assert.Equal(AdminUsername, settings[SystemSettingKeys.AdminUsername].Value);

        var audit = await db.AuditLogs.SingleAsync(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("installation.setup.completed", audit.Action);
        // The audit row is the closed projection of the shared installation event: it links to the
        // account this same transaction created and to the installation target.
        Assert.Equal("Installation", audit.TargetType);
        Assert.Equal("signacore", audit.TargetId);
        Assert.Equal(credential.AccountId, audit.ActorId);
        Assert.Equal(AdminUsername, audit.ActorName);
        Assert.Contains("ConfigurationVersion=1", audit.Description, StringComparison.Ordinal);
        Assert.Null(audit.BeforeSnapshot);
        Assert.Null(audit.AfterSnapshot);
        var viaRepository = await new AuditLogRepository(db).QueryAsync(
            "installation.setup.completed",
            "Installation",
            "signacore",
            credential.AccountId,
            pageSize: 10,
            skip: 0,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Single(viaRepository);
    }

    /// <summary>
    /// The administrator password exists only as its hash, and secret settings only as encrypted
    /// envelopes. Neither may be recoverable by reading the tables, and neither may surface in the
    /// audit projection.
    /// </summary>
    [Fact]
    public async Task Setup_NeverStoresPlaintextCredentialsOrSecretSettings()
    {
        using var http = await StartHostAsync();
        await PostSetupAsync(http, await RotateSetupCodeAsync());

        await using var db = OpenDatabase();

        Assert.DoesNotContain(
            AdminPassword,
            (await db.PasswordCredentials.SingleAsync(cancellationToken: TestContext.Current.CancellationToken)).PasswordHash,
            StringComparison.Ordinal);

        var audit = await db.AuditLogs.SingleAsync(cancellationToken: TestContext.Current.CancellationToken);
        Assert.DoesNotContain(AdminPassword, audit.Description ?? string.Empty, StringComparison.Ordinal);
        Assert.Null(audit.BeforeSnapshot);
        Assert.Null(audit.AfterSnapshot);

        var secrets = await db.SystemSettings.Where(setting => setting.IsSecret).ToListAsync(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.NotEmpty(secrets);
        var protector = new AesGcmConfigurationProtector(new BootstrapMasterKeyProvider(RootSecret));
        foreach (var secret in secrets)
        {
            // Stored form is an opaque envelope; only the configured root key recovers the value.
            Assert.NotEqual(protector.Unprotect(secret.Key, secret.Value), secret.Value);
        }
    }

    /// <summary>
    /// A successful setup stops its own host so a supervisor restarts it into the normal host, so a
    /// second attempt necessarily lands on the restarted process — which must refuse it without
    /// parsing the request.
    /// </summary>
    [Fact]
    public async Task Setup_AfterCompletion_IsRefusedByTheRestartedHost()
    {
        using (var setupHost = await StartHostAsync())
        {
            Assert.Equal(HttpStatusCode.NoContent, (await PostSetupAsync(setupHost, await RotateSetupCodeAsync())).StatusCode);
        }

        _factory?.Dispose();
        _factory = null;

        using var restarted = await StartHostAsync();

        var status = await restarted.GetAsync(SetupEntryPath, TestContext.Current.CancellationToken);
        Assert.Equal("completed", (await status.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken))
            .GetProperty("status").GetString());

        // The replay answer does not depend on the request body at all.
        var second = await restarted.SendAsync(new HttpRequestMessage(HttpMethod.Post, SetupEntryPath)
        {
            Headers = { { UnsafeRequestHeader, "1" } },
            Content = JsonContent.Create(new { anything = "garbage" }),
        }, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);

        await using var db = OpenDatabase();
        Assert.Equal(1, await db.PasswordCredentials.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        // The completion published configuration version 1: every stored settings row carries it.
        Assert.Equal(1, await db.SystemSettings.MaxAsync(
            setting => (int?)setting.Version, cancellationToken: TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// Concurrent completions must serialize on the singleton row: exactly one wins, and the losers
    /// change nothing. The winner stops the host once its response completes, so a loser may be cut
    /// off rather than answered.
    /// </summary>
    [Fact]
    public async Task ConcurrentSetupRequests_ProduceExactlyOneInstallation()
    {
        using var http = await StartHostAsync();
        var code = await RotateSetupCodeAsync();

        var outcomes = await Task.WhenAll(Enumerable.Range(0, 4).Select(async _ =>
        {
            try
            {
                return (await PostSetupAsync(http, code)).StatusCode;
            }
            catch (Exception)
            {
                return HttpStatusCode.ServiceUnavailable;
            }
        }));

        Assert.Equal(1, outcomes.Count(status => status == HttpStatusCode.NoContent));

        await using var db = OpenDatabase();
        Assert.Equal(1, await db.PasswordCredentials.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(1, await db.Accounts.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A database that already owns business data but has no installation state is an upgrade of a
    /// pre-change deployment. It must take the protected legacy import path, never Setup Mode.
    /// </summary>
    [Fact]
    public async Task ExistingDatabaseWithoutInstallationState_NeverExposesAnonymousSetup()
    {
        await SeedPreChangeDeploymentAsync();

        using var http = await StartHostAsync(new Dictionary<string, string?>
        {
            // What the pre-change launcher used to inject; the import reads it once and stores it.
            [SystemSettingKeys.PublicBaseUrl] = PublicBaseUrl,
            [SystemSettingKeys.JwtIssuer] = PublicBaseUrl,
            [SystemSettingKeys.LegacyAdminBootstrapUsername] = "legacy_admin"
        });

        var status = await http.GetAsync(SetupEntryPath, TestContext.Current.CancellationToken);
        Assert.Equal("completed", (await status.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken))
            .GetProperty("status").GetString());

        await using var db = OpenDatabase();
        var installation = await db.ServiceInstallations.SingleAsync(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(InstallationStatus.Completed, installation.Status);
        Assert.Null(installation.SetupCodeDigest);

        // Import creates no administrator: the deployment already has its own accounts.
        Assert.Equal(1, await db.PasswordCredentials.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal("legacy_admin", (await db.SystemSettings.SingleAsync(setting => setting.Key == SystemSettingKeys.AdminUsername,
            cancellationToken: TestContext.Current.CancellationToken)).Value);
    }

    /// <summary>
    /// A completed installation whose settings were deleted must fail closed, not reopen setup —
    /// otherwise deleting rows would hand the service to the next anonymous visitor.
    /// </summary>
    [Fact]
    public async Task CompletedInstallationWithMissingSettings_FailsClosedInsteadOfReopeningSetup()
    {
        using (var http = await StartHostAsync())
        {
            await PostSetupAsync(http, await RotateSetupCodeAsync());
        }

        _factory?.Dispose();
        _factory = null;

        await using (var db = OpenDatabase())
        {
            await db.SystemSettings
                .Where(setting => setting.Key == SystemSettingKeys.JwtAudience)
                .ExecuteDeleteAsync(cancellationToken: TestContext.Current.CancellationToken);
        }

        var exception = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var http = await StartHostAsync();
            await http.GetAsync("/health/live", TestContext.Current.CancellationToken);
        });

        Assert.Contains(SystemSettingKeys.JwtAudience, Flatten(exception), StringComparison.Ordinal);

        await using var verifyDb = OpenDatabase();
        Assert.Equal(InstallationStatus.Completed, (await verifyDb.ServiceInstallations.SingleAsync(
            cancellationToken: TestContext.Current.CancellationToken)).Status);
    }

    /// <summary>
    /// A wrong root key must fail startup, not quietly regenerate signing keys. Silent regeneration
    /// would invalidate every issued token while looking like a healthy start.
    /// </summary>
    [Fact]
    public async Task WrongRootKey_FailsClosedAndLeavesStoredSigningKeysUntouched()
    {
        using (var setupHost = await StartHostAsync())
        {
            Assert.Equal(HttpStatusCode.NoContent, (await PostSetupAsync(setupHost, await RotateSetupCodeAsync())).StatusCode);
        }

        _factory?.Dispose();
        _factory = null;

        // One normal start so the installation actually owns signing keys.
        using (var normalHost = await StartHostAsync())
        {
            Assert.Equal(HttpStatusCode.OK, (await normalHost.GetAsync("/health/ready", TestContext.Current.CancellationToken)).StatusCode);
        }

        _factory?.Dispose();
        _factory = null;

        List<(string KeyId, string Encrypted, string Salt)> before;
        await using (var db = OpenDatabase())
        {
            before = await db.SecurityKeys
                .OrderBy(key => key.KeyId)
                .Select(key => new ValueTuple<string, string, string>(
                    key.KeyId, key.EncryptedPrivateKeyParams, key.EncryptionSalt))
                .ToListAsync(cancellationToken: TestContext.Current.CancellationToken);
        }

        Assert.NotEmpty(before);

        var exception = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var http = await StartHostAsync(rootSecret: "a-completely-different-root-secret");
            await http.GetAsync("/health/live", TestContext.Current.CancellationToken);
        });

        // The failure names the settings it could not decrypt, and never the secret itself.
        Assert.Contains("could not be decrypted", Flatten(exception), StringComparison.Ordinal);
        Assert.DoesNotContain(RootSecret, Flatten(exception), StringComparison.Ordinal);

        await using var verifyDb = OpenDatabase();
        var after = await verifyDb.SecurityKeys
            .OrderBy(key => key.KeyId)
            .Select(key => new ValueTuple<string, string, string>(
                key.KeyId, key.EncryptedPrivateKeyParams, key.EncryptionSalt))
            .ToListAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(before, after);
    }

    private async Task AssertInstallationStillPendingAsync()
    {
        await using var db = OpenDatabase();
        var installation = await db.ServiceInstallations.SingleAsync(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(InstallationStatus.PendingSetup, installation.Status);
        Assert.NotNull(installation.SetupCodeDigest);
    }

    private async Task AssertNothingNewWasWrittenAsync(int existingAccounts = 0, int existingCredentials = 0)
    {
        await using var db = OpenDatabase();
        Assert.Equal(existingAccounts, await db.Accounts.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(existingCredentials, await db.PasswordCredentials.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.False(await db.SystemSettings.AnyAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.False(await db.AuditLogs.AnyAsync(cancellationToken: TestContext.Current.CancellationToken));
        await AssertInstallationStillPendingAsync();
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

    private async Task<HttpClient> StartHostAsync(
        IDictionary<string, string?>? extraSettings = null,
        bool allowRedirects = true,
        string rootSecret = RootSecret)
    {
        var bootstrapFilePath = await InstallationTestSupport.PrepareUninstalledBootstrapAsync(
            _workingDirectory,
            new DatabaseOptions { Provider = "SQLite", ConnectionString = _connectionString },
            rootSecret);

        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                // The design's rules that matter here — HTTPS-only public base URL, no Development
                // fallbacks — only apply outside Development, and WebApplicationFactory defaults to
                // Development.
                builder.UseSetting("environment", Environments.Production);
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath);
                foreach (var (key, value) in extraSettings ?? new Dictionary<string, string?>())
                {
                    builder.UseSetting(key, value);
                }
            });

        return _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = allowRedirects
        });
    }

    private async Task<HttpResponseMessage> PostSetupAsync(
        HttpClient http,
        string setupCode,
        bool allowNonHttpsIssuer = false,
        string password = AdminPassword,
        string publicBaseUrl = PublicBaseUrl,
        string jwtAudience = "SignaCore.Services",
        string? inputShape = null,
        string? inputValue = null,
        bool includeUnsafeRequestHeader = true)
    {
        object input = (inputShape, inputValue) switch
        {
            ("missing-password", _) => new
            {
                publicBaseUrl,
                allowNonHttpsIssuer,
                jwtAudience,
                username = AdminUsername,
            },
            ("missing-publicBaseUrl", _) => new
            {
                allowNonHttpsIssuer,
                jwtAudience,
                username = AdminUsername,
                password,
            },
            ("extra-field", _) => new
            {
                publicBaseUrl,
                allowNonHttpsIssuer,
                jwtAudience,
                username = AdminUsername,
                password,
                confirmPassword = password,
            },
            ("wrong-type-allowNonHttpsIssuer", _) => new
            {
                publicBaseUrl,
                allowNonHttpsIssuer = "true",
                jwtAudience,
                username = AdminUsername,
                password,
            },
            ("wrong-type-username", _) => new
            {
                publicBaseUrl,
                allowNonHttpsIssuer,
                jwtAudience,
                username = 42,
                password,
            },
            (_, "weak-password") => ValidInput(publicBaseUrl, allowNonHttpsIssuer, jwtAudience, AdminUsername, "short"),
            (_, "plain-http-publicBaseUrl") => ValidInput("http://identity.example.test", allowNonHttpsIssuer, jwtAudience, AdminUsername, password),
            (_, "empty-jwtAudience") => ValidInput(publicBaseUrl, allowNonHttpsIssuer, "", AdminUsername, password),
            (_, "overlong-username") => ValidInput(publicBaseUrl, allowNonHttpsIssuer, jwtAudience, new string('u', 101), password),
            (_, "taken-username") => ValidInput(publicBaseUrl, allowNonHttpsIssuer, jwtAudience, "existing_admin", password),
            _ => ValidInput(publicBaseUrl, allowNonHttpsIssuer, jwtAudience, AdminUsername, password),
        };

        var request = new HttpRequestMessage(HttpMethod.Post, SetupEntryPath)
        {
            Content = JsonContent.Create(new { code = setupCode, input }),
        };
        if (includeUnsafeRequestHeader)
        {
            request.Headers.Add(UnsafeRequestHeader, "1");
        }

        return await http.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static object ValidInput(
        string publicBaseUrl,
        bool allowNonHttpsIssuer,
        string jwtAudience,
        string username,
        string password) => new
    {
        publicBaseUrl,
        allowNonHttpsIssuer,
        jwtAudience,
        username,
        password,
    };

    /// <summary>
    /// The plaintext code is printed to stdout once and never stored, so a test cannot read it
    /// back. Rotating uses the shared store the same way the operator command does, and returns the
    /// newly issued plaintext.
    /// </summary>
    private async Task<string> RotateSetupCodeAsync(DateTimeOffset? expiresAt = null)
    {
        await using var db = OpenDatabase();
        var setupCodeStore = new EfCoreServiceSetupCodeStore<IdentityDbContext>(
            db,
            lifetime: SetupCodeLifetime.Create(TimeSpan.FromHours(1)));
        var issued = await setupCodeStore.RotateAsync(
            InstallationStores.ServiceId, TestContext.Current.CancellationToken);
        Assert.True(issued.IsIssued, $"Rotation failed: {issued.ErrorCode}");

        if (expiresAt is not null)
        {
            var installation = await db.ServiceInstallations.SingleAsync();
            installation.SetupCodeExpiresAtUtc = expiresAt.Value.UtcDateTime;
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        return issued.SetupCode!.Reveal();
    }

    private async Task SeedExistingAdministratorAsync()
    {
        await using var db = OpenDatabase();
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
            Username = "existing_admin",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("ExistingAdmin123"),
            CreatedAt = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    private async Task SeedPreChangeDeploymentAsync()
    {
        await using var db = OpenDatabase();
        await db.Database.MigrateAsync();

        // Migrations applied to an empty database create no installation row (the backfill has
        // nothing to adopt); adding business data afterwards reproduces a pre-change deployment.
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
        await db.SaveChangesAsync();
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
