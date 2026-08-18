using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// End-to-end behavior of a brand-new, uninitialized database: Setup Mode, the one-time code, and
/// the atomic completion transaction.
/// </summary>
public sealed class FirstRunSetupTests : IAsyncLifetime
{
    private const string RootSecret = "first-run-setup-root-secret";
    private const string AdminUsername = "setup_admin";
    private const string AdminPassword = "SetupAdmin123";
    private const string PublicBaseUrl = "https://identity.example.test";

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

    public ValueTask DisposeAsync()
    {
        _factory?.Dispose();
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_workingDirectory))
        {
            Directory.Delete(_workingDirectory, recursive: true);
        }

        return ValueTask.CompletedTask;
    }

    [Fact]
    public async Task EmptyDatabase_EntersSetupMode()
    {
        using var http = await StartSetupModeHostAsync();

        var response = await http.GetAsync("/api/setup/status");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("pending", body.GetProperty("status").GetString());
    }

    [Fact]
    public async Task EmptyDatabase_CreatesAPendingInstallationWithAHashedSetupCode()
    {
        using var _ = await StartSetupModeHostAsync();

        await using var db = OpenDatabase();
        var state = await db.InstallationStates.SingleAsync();

        Assert.Equal(InstallationStatus.Pending, state.Status);
        Assert.False(string.IsNullOrWhiteSpace(state.SetupCodeHash));
        Assert.NotNull(state.SetupCodeExpiresAt);
        Assert.Null(state.CompletedAt);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/admin")]
    public async Task BrowserNavigation_WhilePending_RedirectsToSetup(string path)
    {
        using var http = await StartSetupModeHostAsync(allowRedirects: false);
        http.DefaultRequestHeaders.Add("Accept", "text/html");

        var response = await http.GetAsync(path);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal("/setup", response.Headers.Location?.ToString());
    }

    [Theory]
    [InlineData("/api/auth/token")]
    [InlineData("/oauth2/token")]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    [InlineData("/.well-known/jwks.json")]
    [InlineData("/api/admin/session/login")]
    public async Task NormalApis_WhilePending_ReturnInstallationRequired(string path)
    {
        using var http = await StartSetupModeHostAsync();

        var response = await http.GetAsync(path);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("installation_required", body.GetProperty("error").GetString());
    }

    /// <summary>
    /// The verbs the endpoints actually declare, which is what a real client sends. A GET reaches
    /// the gate only because it matches no action; a POST resolves the endpoint and would drag its
    /// <c>[Authorize]</c> metadata into a Setup Mode that registers no policies.
    /// </summary>
    [Theory]
    [InlineData("/api/auth/token")]
    [InlineData("/oauth2/token")]
    [InlineData("/api/admin/session/login")]
    public async Task NormalApis_WhilePending_ReturnInstallationRequiredForTheirOwnVerb(string path)
    {
        using var http = await StartSetupModeHostAsync();

        var response = await http.PostAsJsonAsync(path, new { grantType = "password" });

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("installation_required", body.GetProperty("error").GetString());
    }

    /// <summary>
    /// Liveness has to be true so a launcher can wait for the setup page; readiness has to be false
    /// so a load balancer never routes authentication traffic here.
    /// </summary>
    [Fact]
    public async Task HealthEndpoints_WhilePending_ReportLiveButNotReady()
    {
        using var http = await StartSetupModeHostAsync();

        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync("/health/live")).StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await http.GetAsync("/health/ready")).StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await http.GetAsync("/health")).StatusCode);
    }

    [Fact]
    public async Task Setup_WithAWrongCode_IsRefusedAndChangesNothing()
    {
        using var http = await StartSetupModeHostAsync();

        var response = await PostSetupAsync(http, setupCode: "AAAAA-BBBBB-CCCCC-DDDDD");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        await using var db = OpenDatabase();
        Assert.Equal(InstallationStatus.Pending, (await db.InstallationStates.SingleAsync()).Status);
        Assert.False(await db.Accounts.AnyAsync());
        Assert.False(await db.SystemSettings.AnyAsync());
    }

    [Fact]
    public async Task Setup_WithAnExpiredCode_IsRefused()
    {
        using var http = await StartSetupModeHostAsync();
        var code = await RotateSetupCodeAsync(expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1));

        var response = await PostSetupAsync(http, code);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Setup_WithAWeakPassword_IsRefusedBeforeAnythingIsWritten()
    {
        using var http = await StartSetupModeHostAsync();
        var code = await RotateSetupCodeAsync();

        var response = await PostSetupAsync(http, code, password: "short");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        await using var db = OpenDatabase();
        Assert.False(await db.Accounts.AnyAsync());
    }

    [Fact]
    public async Task Setup_WithAPlainHttpPublicBaseUrl_IsRefusedOutsideDevelopment()
    {
        using var http = await StartSetupModeHostAsync();
        var code = await RotateSetupCodeAsync();

        var response = await PostSetupAsync(http, code, publicBaseUrl: "http://identity.example.test");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Setup_WithExplicitHttpOptIn_AcceptsHttpWithoutClassifyingTheHost()
    {
        using var http = await StartSetupModeHostAsync();
        var code = await RotateSetupCodeAsync();

        var response = await PostSetupAsync(
            http,
            code,
            publicBaseUrl: "http://identity.example.test",
            allowNonHttpsIssuer: true);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        await using var db = OpenDatabase();
        var settings = await db.SystemSettings.ToDictionaryAsync(setting => setting.Key);
        Assert.Equal("true", settings[SystemSettingKeys.SecurityAllowNonHttpsIssuer].Value);
    }

    [Fact]
    public async Task Setup_StoresTheOperatorSelectedAudience()
    {
        using var http = await StartSetupModeHostAsync();
        var code = await RotateSetupCodeAsync();

        var response = await PostSetupAsync(http, code, jwtAudience: "urn:example:services");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await using var db = OpenDatabase();
        Assert.Equal(
            "urn:example:services",
            (await db.SystemSettings.SingleAsync(
                setting => setting.Key == SystemSettingKeys.JwtAudience)).Value);
    }

    [Fact]
    public async Task Setup_WithAValidCode_CompletesAtomically()
    {
        using var http = await StartSetupModeHostAsync();
        var code = await RotateSetupCodeAsync();

        var response = await PostSetupAsync(http, code);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        await using var db = OpenDatabase();
        var state = await db.InstallationStates.SingleAsync();
        Assert.Equal(InstallationStatus.Completed, state.Status);
        Assert.Equal(1, state.ConfigurationVersion);
        Assert.NotNull(state.CompletedAt);
        // The one-time code is invalidated in the same transaction that completes installation.
        Assert.Null(state.SetupCodeHash);
        Assert.Null(state.SetupCodeExpiresAt);

        var credential = await db.PasswordCredentials.SingleAsync();
        Assert.Equal(AdminUsername, credential.Username);
        Assert.True(BCrypt.Net.BCrypt.Verify(AdminPassword, credential.PasswordHash));

        var settings = await db.SystemSettings.ToDictionaryAsync(setting => setting.Key);
        Assert.Equal(PublicBaseUrl, settings[SystemSettingKeys.PublicBaseUrl].Value);
        Assert.Equal(PublicBaseUrl, settings[SystemSettingKeys.JwtIssuer].Value);
        Assert.Equal(AdminUsername, settings[SystemSettingKeys.AdminUsername].Value);

        var audit = await db.AuditLogs.SingleAsync();
        Assert.Equal("installation.setup.completed", audit.Action);
    }

    /// <summary>
    /// The administrator password exists only as its hash, and secret settings only as encrypted
    /// envelopes. Neither may be recoverable by reading the tables.
    /// </summary>
    [Fact]
    public async Task Setup_NeverStoresPlaintextCredentialsOrSecretSettings()
    {
        using var http = await StartSetupModeHostAsync();
        await PostSetupAsync(http, await RotateSetupCodeAsync());

        await using var db = OpenDatabase();

        Assert.DoesNotContain(
            AdminPassword,
            (await db.PasswordCredentials.SingleAsync()).PasswordHash,
            StringComparison.Ordinal);

        var audit = await db.AuditLogs.SingleAsync();
        Assert.DoesNotContain(AdminPassword, audit.Description ?? string.Empty, StringComparison.Ordinal);
        Assert.Null(audit.BeforeSnapshot);
        Assert.Null(audit.AfterSnapshot);

        var secrets = await db.SystemSettings.Where(setting => setting.IsSecret).ToListAsync();
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
    /// second attempt necessarily lands on the restarted process — which must refuse it.
    /// </summary>
    [Fact]
    public async Task Setup_AfterCompletion_IsRefusedByTheRestartedHost()
    {
        using (var setupHost = await StartSetupModeHostAsync())
        {
            Assert.Equal(HttpStatusCode.OK, (await PostSetupAsync(setupHost, await RotateSetupCodeAsync())).StatusCode);
        }

        _factory?.Dispose();
        _factory = null;

        using var restarted = await StartHostAsync();
        var second = await PostSetupAsync(restarted, "TESTA-TESTB-TESTC-TESTD");

        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);

        await using var db = OpenDatabase();
        Assert.Equal(1, await db.PasswordCredentials.CountAsync());
        Assert.Equal(1, (await db.InstallationStates.SingleAsync()).ConfigurationVersion);
    }

    /// <summary>
    /// Concurrent completions must serialize on the singleton row: exactly one wins, and the losers
    /// change nothing.
    /// </summary>
    [Fact]
    public async Task ConcurrentSetupRequests_ProduceExactlyOneInstallation()
    {
        using var http = await StartSetupModeHostAsync();
        var code = await RotateSetupCodeAsync();

        // The winner stops the host once its response completes, so a loser may be cut off rather
        // than answered. What must hold is that at most one request succeeded and the database saw
        // exactly one installation.
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

        Assert.Equal(1, outcomes.Count(status => status == HttpStatusCode.OK));

        await using var db = OpenDatabase();
        Assert.Equal(1, await db.PasswordCredentials.CountAsync());
        Assert.Equal(1, await db.Accounts.CountAsync());
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

        var status = await http.GetAsync("/api/setup/status");
        Assert.Equal("completed", (await status.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("status").GetString());

        await using var db = OpenDatabase();
        var state = await db.InstallationStates.SingleAsync();
        Assert.Equal(InstallationStatus.Completed, state.Status);
        Assert.Null(state.SetupCodeHash);

        // Import creates no administrator: the deployment already has its own accounts.
        Assert.Equal(1, await db.PasswordCredentials.CountAsync());
        Assert.Equal("legacy_admin", (await db.SystemSettings.SingleAsync(
            setting => setting.Key == SystemSettingKeys.AdminUsername)).Value);
    }

    /// <summary>
    /// A completed installation whose settings were deleted must fail closed, not reopen setup —
    /// otherwise deleting rows would hand the service to the next anonymous visitor.
    /// </summary>
    [Fact]
    public async Task CompletedInstallationWithMissingSettings_FailsClosedInsteadOfReopeningSetup()
    {
        using (var http = await StartSetupModeHostAsync())
        {
            await PostSetupAsync(http, await RotateSetupCodeAsync());
        }

        _factory?.Dispose();
        _factory = null;

        await using (var db = OpenDatabase())
        {
            await db.SystemSettings
                .Where(setting => setting.Key == SystemSettingKeys.JwtAudience)
                .ExecuteDeleteAsync();
        }

        var exception = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var http = await StartHostAsync();
            await http.GetAsync("/health/live");
        });

        Assert.Contains(SystemSettingKeys.JwtAudience, Flatten(exception), StringComparison.Ordinal);

        await using var verifyDb = OpenDatabase();
        Assert.Equal(InstallationStatus.Completed, (await verifyDb.InstallationStates.SingleAsync()).Status);
    }

    /// <summary>
    /// A wrong root key must fail startup, not quietly regenerate signing keys. Silent regeneration
    /// would invalidate every issued token while looking like a healthy start.
    /// </summary>
    [Fact]
    public async Task WrongRootKey_FailsClosedAndLeavesStoredSigningKeysUntouched()
    {
        using (var setupHost = await StartSetupModeHostAsync())
        {
            Assert.Equal(HttpStatusCode.OK, (await PostSetupAsync(setupHost, await RotateSetupCodeAsync())).StatusCode);
        }

        _factory?.Dispose();
        _factory = null;

        // One normal start so the installation actually owns signing keys.
        using (var normalHost = await StartHostAsync())
        {
            Assert.Equal(HttpStatusCode.OK, (await normalHost.GetAsync("/health/ready")).StatusCode);
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
                .ToListAsync();
        }

        Assert.NotEmpty(before);

        var exception = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            using var http = await StartHostAsync(rootSecret: "a-completely-different-root-secret");
            await http.GetAsync("/health/live");
        });

        // The failure names the settings it could not decrypt, and never the secret itself.
        Assert.Contains("could not be decrypted", Flatten(exception), StringComparison.Ordinal);
        Assert.DoesNotContain(RootSecret, Flatten(exception), StringComparison.Ordinal);

        await using var verifyDb = OpenDatabase();
        var after = await verifyDb.SecurityKeys
            .OrderBy(key => key.KeyId)
            .Select(key => new ValueTuple<string, string, string>(
                key.KeyId, key.EncryptedPrivateKeyParams, key.EncryptionSalt))
            .ToListAsync();

        Assert.Equal(before, after);
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

    private Task<HttpClient> StartSetupModeHostAsync(bool allowRedirects = true) =>
        StartHostAsync(allowRedirects: allowRedirects);

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
        string password = AdminPassword,
        string publicBaseUrl = PublicBaseUrl,
        bool allowNonHttpsIssuer = false,
        string jwtAudience = "SignaCore.Services")
    {
        return await http.PostAsJsonAsync("/api/setup/complete", new
        {
            publicBaseUrl,
            allowNonHttpsIssuer,
            jwtAudience,
            username = AdminUsername,
            password,
            confirmPassword = password,
            setupCode
        });
    }

    /// <summary>
    /// The plaintext code is printed to stdout once and never stored, so a test cannot read it back.
    /// Rotating writes a known code the same way the operator command does.
    /// </summary>
    private async Task<string> RotateSetupCodeAsync(DateTimeOffset? expiresAt = null)
    {
        const string code = "TESTA-TESTB-TESTC-TESTD";

        await using var db = OpenDatabase();
        var state = await db.InstallationStates.SingleAsync();
        state.SetupCodeHash = SignaCore.Host.Installation.SetupCode.Hash(code);
        state.SetupCodeExpiresAt = expiresAt ?? DateTimeOffset.UtcNow.AddHours(1);
        await db.SaveChangesAsync();

        return code;
    }

    private async Task SeedPreChangeDeploymentAsync()
    {
        await using var db = OpenDatabase();
        await db.Database.MigrateAsync();

        // Migrations create installation_state; a pre-change database has the table but no row.
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
