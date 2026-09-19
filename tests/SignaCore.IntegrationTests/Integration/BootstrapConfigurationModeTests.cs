using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ServiceMantle.Bootstrap;
using ServiceMantle.AspNetCore.Health;
using ServiceMantle.AspNetCore.Logging;
using ServiceMantle.Health;
using ServiceMantle.Installation;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host.Bootstrap;
using Xunit;
using SignaCore.Tests.Integration;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// Bootstrap Configuration Mode over the shared pipeline: the shared anonymous creation entry,
/// the shared installation status entry, the credential-gated read-only probe, and the phase gate
/// that keeps everything else unreachable.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class BootstrapConfigurationModeTests : IAsyncLifetime
{
    private const string SpaTemplate = "<html><head><title>Console</title></head><body>Console</body></html>";
    private const string StatusPath = "/management/v1/status";
    private const string CreatePath = "/management/v1/bootstrap";
    private const string TestPath = "/api/bootstrap/test";

    private string _directory = string.Empty;
    private string _webRoot = string.Empty;
    private string _bootstrapPath = string.Empty;
    private string _credentialRecordPath = string.Empty;
    private WebApplicationFactory<Program>? _factory;

    public ValueTask InitializeAsync()
    {
        _directory = Path.Combine(CreateTemporaryRoot(), $"signacore-bootstrap-mode-{Guid.NewGuid():N}");
        _webRoot = Path.Combine(_directory, "wwwroot");
        Directory.CreateDirectory(_webRoot);
        File.WriteAllText(Path.Combine(_webRoot, "index.html"), SpaTemplate);
        File.WriteAllText(Path.Combine(_webRoot, "app.css"), "body{}");
        _bootstrapPath = Path.Combine(_directory, "signacore.bootstrap.json");
        _credentialRecordPath = Path.Combine(_directory, "signacore.bootstrap-credential.json");
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// The shared SQLite target rules reject a path whose ancestors are symbolic links, and the
    /// macOS temporary root is one (/var → /private/var), so tests resolve it first.
    /// </summary>
    private static string CreateTemporaryRoot()
    {
        var root = Path.GetTempPath();
        if (OperatingSystem.IsMacOS() && root.StartsWith("/var/", StringComparison.Ordinal))
        {
            root = "/private" + root;
        }

        return root;
    }

    public ValueTask DisposeAsync()
    {
        _factory?.Dispose();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        return ValueTask.CompletedTask;
    }

    private HttpClient StartHost(
        Action<IServiceCollection>? configureTestServices = null,
        bool createWebRoot = true)
    {
        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("environment", "Production");
                builder.UseSetting("Bootstrap:FilePath", _bootstrapPath);
                builder.UseSetting("Endpoints:Http", "0");
                if (createWebRoot)
                {
                    builder.UseWebRoot(_webRoot);
                }

                builder.ConfigureTestServices(services =>
                {
                    configureTestServices?.Invoke(services);
                });
            });

        return _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    /// <summary>
    /// Reissues the credential through the same record the host's startup reissue wrote, which is
    /// exactly the recovery path an operator has after an unconsumed startup credential.
    /// </summary>
    private async Task<string> ReissueCredentialAsync()
    {
        var store = BootstrapCredentialProvisioner.CreateStore(_bootstrapPath);
        var provision = await store.ReissueAsync(
            BootstrapCredentialLifetime.Default,
            TestContext.Current.CancellationToken);
        Assert.True(provision.IsProvisioned);
        return provision.Credential!.Reveal();
    }

    private static HttpRequestMessage CreateRequest(string path, object body, string credential)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(body),
        };
        request.Headers.Add("X-ServiceMantle-Request", "1");
        request.Headers.Add("X-ServiceMantle-Bootstrap-Credential", credential);
        return request;
    }

    private static object SqliteTarget(string filePath) => new
    {
        provider = "SQLite",
        connectionString = $"Data Source={filePath}"
    };

    [Fact]
    public async Task MissingFile_StaysLiveAndGatesTheNormalSurface()
    {
        using var http = StartHost();
        _ = await ReissueCredentialAsync();

        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync("/health/live", TestContext.Current.CancellationToken)).StatusCode);
        var ready = await http.GetAsync("/health/ready", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
        var legacy = await http.GetAsync("/health", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, legacy.StatusCode);

        // The anonymous status entry reports the bootstrap phase with no restart required yet.
        var status = await http.GetAsync(StatusPath, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, status.StatusCode);
        using var document = JsonDocument.Parse(
            await status.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal("bootstrap_configuration", document.RootElement.GetProperty("phase").GetString());
        Assert.Equal("not_started", document.RootElement.GetProperty("migrationStatus").GetString());
        Assert.Equal("unreachable", document.RootElement.GetProperty("databaseStatus").GetString());
        Assert.False(document.RootElement.GetProperty("bootstrapConfigured").GetBoolean());
        Assert.False(document.RootElement.GetProperty("restartRequired").GetBoolean());

        // The normal API surface is mapped by nothing here: routing answers 404 before any
        // identity capability could exist.
        foreach (var path in new[] { "/api/oauth2/token", "/.well-known/openid-configuration", "/metrics", "/api/bootstrap/save" })
        {
            var blocked = await http.GetAsync(path, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.NotFound, blocked.StatusCode);
        }

        // The Bootstrap page and its static assets are reachable.
        http.DefaultRequestHeaders.Accept.ParseAdd("text/html");
        var page = await http.GetAsync("/bootstrap", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Equal("text/html", page.Content.Headers.ContentType?.MediaType);
        var asset = await http.GetAsync("/app.css", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, asset.StatusCode);
    }

    [Fact]
    public async Task WrongCredentialAndInvalidTarget_DoNotCreateTheFile()
    {
        using var http = StartHost();
        var target = SqliteTarget(Path.Combine(_directory, "identity.db"));

        var missingCredential = await http.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, CreatePath)
            {
                Content = JsonContent.Create(new { database = target }),
                Headers = { { "X-ServiceMantle-Request", "1" } },
            },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, missingCredential.StatusCode);

        var wrongCredential = await http.SendAsync(
            CreateRequest(CreatePath, new { database = target }, "not-the-credential"),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongCredential.StatusCode);
        Assert.Equal(
            """{"errorCode":"management.bootstrap.credential_invalid"}""",
            await wrongCredential.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        // From here every request carries a well-formed credential, so each one consumes it even
        // when the target is then refused: that is the documented consume-first window, and the
        // operator recovery is a reissue.
        var unknownProvider = await http.SendAsync(
            CreateRequest(
                CreatePath,
                new { database = new { provider = "MongoDb", connectionString = "Host=x" } },
                await ReissueCredentialAsync()),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, unknownProvider.StatusCode);

        var unreachable = await http.SendAsync(
            CreateRequest(
                CreatePath,
                new { database = SqliteTarget(Path.Combine(_directory, "missing-parent", "identity.db")) },
                await ReissueCredentialAsync()),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, unreachable.StatusCode);

        Assert.False(File.Exists(_bootstrapPath));
    }

    [Fact]
    public async Task Probe_ReturnsClassificationWithoutConsumingTheCredential()
    {
        using var http = StartHost();
        var credential = await ReissueCredentialAsync();
        var databasePath = Path.Combine(_directory, "identity.db");

        var probe = await http.SendAsync(
            CreateRequest(TestPath, new { database = SqliteTarget(databasePath) }, credential),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, probe.StatusCode);
        using var document = JsonDocument.Parse(
            await probe.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal("empty", document.RootElement.GetProperty("target").GetString());
        Assert.True(document.RootElement.GetProperty("canConnect").GetBoolean());
        Assert.Equal("not_applicable", document.RootElement.GetProperty("masterKey").GetString());

        // The credential still authorizes a creation afterwards: the probe never consumed it.
        var create = await http.SendAsync(
            CreateRequest(CreatePath, new { database = SqliteTarget(databasePath) }, credential),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        Assert.True(File.Exists(_bootstrapPath));
    }

    [Fact]
    public async Task Probe_WithInvalidCredential_DoesNotOpenTheDatabase()
    {
        using var http = StartHost();
        _ = await ReissueCredentialAsync();

        // The target would classify as unreachable (its parent directory does not exist). A 401
        // instead proves the request was refused before any database was opened.
        var probe = await http.SendAsync(
            CreateRequest(
                TestPath,
                new { database = SqliteTarget(Path.Combine(_directory, "missing-parent", "identity.db")) },
                "not-the-credential"),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, probe.StatusCode);
        Assert.Equal(
            """{"errorCode":"management.bootstrap.credential_invalid"}""",
            await probe.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Create_NewInstallation_GeneratesTheKeyReportsRestartAndStops()
    {
        using var http = StartHost();
        var credential = await ReissueCredentialAsync();
        var databasePath = Path.Combine(_directory, "identity.db");

        var create = await http.SendAsync(
            CreateRequest(CreatePath, new { database = SqliteTarget(databasePath) }, credential),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        using var document = JsonDocument.Parse(
            await create.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.True(document.RootElement.GetProperty("restartRequired").GetBoolean());

        Assert.True(File.Exists(_bootstrapPath));
        await AssertFileIsCanonicalAsync(generatedKey: true);

        // The published file plus the process-local latch project through the status entry for as
        // long as the stopping host still answers; once it stops, that itself is the outcome.
        var observedRestartOrStop = false;
        for (var attempt = 0; attempt < 50 && !observedRestartOrStop; attempt++)
        {
            try
            {
                var status = await http.GetAsync(StatusPath, TestContext.Current.CancellationToken);
                if (status.StatusCode == HttpStatusCode.OK)
                {
                    using var state = JsonDocument.Parse(
                        await status.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
                    Assert.Equal("bootstrap_configuration", state.RootElement.GetProperty("phase").GetString());
                    if (state.RootElement.GetProperty("restartRequired").GetBoolean())
                    {
                        observedRestartOrStop = true;
                    }
                }
                else
                {
                    observedRestartOrStop = true;
                }
            }
            catch (Exception exception) when (
                exception is HttpRequestException or ObjectDisposedException or InvalidOperationException)
            {
                observedRestartOrStop = true;
            }

            if (!observedRestartOrStop)
            {
                await Task.Delay(50, TestContext.Current.CancellationToken);
            }
        }

        Assert.True(observedRestartOrStop);
        await AssertHostStopsAsync(http);
    }

    [Fact]
    public async Task Create_ExistingInstallation_UsesTheProvidedKey()
    {
        using var http = StartHost();
        var credential = await ReissueCredentialAsync();
        var databasePath = Path.Combine(_directory, "identity.db");

        var create = await http.SendAsync(
            CreateRequest(
                CreatePath,
                new { database = SqliteTarget(databasePath), masterKey = "provided-existing-root-key" },
                credential),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        Assert.True(File.Exists(_bootstrapPath));
        await AssertFileIsCanonicalAsync(generatedKey: false, providedKey: "provided-existing-root-key");
        await AssertHostStopsAsync(http);
    }

    [Fact]
    public async Task Create_FailuresDoNotStopTheHost()
    {
        using var http = StartHost();
        var credential = await ReissueCredentialAsync();

        var wrongCredential = await http.SendAsync(
            CreateRequest(CreatePath, new { database = SqliteTarget(Path.Combine(_directory, "identity.db")) }, "not-the-credential"),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongCredential.StatusCode);

        var unreachable = await http.SendAsync(
            CreateRequest(
                CreatePath,
                new { database = SqliteTarget(Path.Combine(_directory, "missing-parent", "identity.db")) },
                credential),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, unreachable.StatusCode);

        Assert.False(File.Exists(_bootstrapPath));
        var status = await http.GetAsync(StatusPath, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, status.StatusCode);
    }

    [Fact]
    public async Task Create_CancelledAfterPublishStillStopsTheProcess()
    {
        using var http = StartHost();
        var credential = await ReissueCredentialAsync();
        var databasePath = Path.Combine(_directory, "identity.db");

        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.Current.CancellationToken);
        var pending = http.SendAsync(
            CreateRequest(CreatePath, new { database = SqliteTarget(databasePath) }, credential),
            cancellation.Token);

        // Abort as soon as the file is published: the published file must still stop the process.
        for (var attempt = 0; attempt < 500 && !File.Exists(_bootstrapPath); attempt++)
        {
            await Task.Delay(10, TestContext.Current.CancellationToken);
        }

        Assert.True(File.Exists(_bootstrapPath));
        cancellation.Cancel();
        try
        {
            _ = await pending;
        }
        catch (Exception exception) when (exception is OperationCanceledException or TaskCanceledException)
        {
            // The abort raced the completed response; either outcome is acceptable.
        }

        await AssertHostStopsAsync(http);
    }

    [Fact]
    public async Task ConcurrentCreates_OnlyOneWinsTheCredential()
    {
        using var http = StartHost();
        var credential = await ReissueCredentialAsync();
        var databasePath = Path.Combine(_directory, "identity.db");

        var first = http.SendAsync(
            CreateRequest(CreatePath, new { database = SqliteTarget(databasePath) }, credential),
            TestContext.Current.CancellationToken);
        var second = http.SendAsync(
            CreateRequest(CreatePath, new { database = SqliteTarget(databasePath) }, credential),
            TestContext.Current.CancellationToken);
        var responses = await Task.WhenAll(first, second);

        // Exactly one concurrent consumer wins the credential; the loser gets the fixed rejection
        // no matter which response slot it landed in.
        Assert.Contains(responses, response => response.StatusCode == HttpStatusCode.Created);
        Assert.Contains(responses, response => response.StatusCode == HttpStatusCode.Unauthorized);
        var rejected = responses.Single(response => response.StatusCode == HttpStatusCode.Unauthorized);
        Assert.Equal(
            """{"errorCode":"management.bootstrap.credential_invalid"}""",
            await rejected.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.True(File.Exists(_bootstrapPath));
        await AssertFileIsCanonicalAsync(generatedKey: true);
        await AssertHostStopsAsync(http);
    }

    [Fact]
    public async Task AfterThePhaseAdvances_TheModeSurfaceIsUnavailable()
    {
        using var http = StartHost(
            services => services.Replace(ServiceDescriptor.Singleton<IServiceHealthSnapshotSource>(
                new AdvancedPhaseSnapshotSource())));
        var credential = await ReissueCredentialAsync();

        http.DefaultRequestHeaders.Accept.ParseAdd("text/html");
        var page = await http.GetAsync("/bootstrap", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, page.StatusCode);
        Assert.Equal(
            """{"errorCode":"service.phase.unavailable"}""",
            await page.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        var probe = await http.SendAsync(
            CreateRequest(TestPath, new { database = SqliteTarget(Path.Combine(_directory, "identity.db")) }, credential),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, probe.StatusCode);

        var create = await http.SendAsync(
            CreateRequest(CreatePath, new { database = SqliteTarget(Path.Combine(_directory, "identity.db")) }, credential),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, create.StatusCode);
        Assert.False(File.Exists(_bootstrapPath));
    }

    [Fact]
    public async Task ValidatorFailures_AreFixed400AndInternalFailuresAre503()
    {
        // The local rules: a PostgreSQL version below SignaCore's floor fails the local shape check.
        using var http = StartHost();
        var credential = await ReissueCredentialAsync();
        var oldVersion = await http.SendAsync(
            CreateRequest(
                CreatePath,
                new { database = new { provider = "PostgreSQL", serverVersion = "14", connectionString = "Host=db;Database=x" } },
                credential),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, oldVersion.StatusCode);
        Assert.False(File.Exists(_bootstrapPath));

        // An internal validator failure is the shared 503, not a caller rejection.
        using var throwingHost = StartHost(services => services.Replace(ServiceDescriptor.Singleton(
            typeof(IBootstrapCandidateValidator),
            new ThrowingValidator())));
        var throwingCredential = await ReissueCredentialAsync();
        var internalFailure = await throwingHost.SendAsync(
            CreateRequest(
                CreatePath,
                new { database = SqliteTarget(Path.Combine(_directory, "identity.db")) },
                throwingCredential),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, internalFailure.StatusCode);
        Assert.Equal(
            """{"errorCode":"management.bootstrap.unavailable"}""",
            await internalFailure.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.False(File.Exists(_bootstrapPath));
    }

    [Fact]
    public async Task Create_NewInstallationOverProtectedData_IsRefused()
    {
        var protectedPath = await CreateProtectedSqliteTargetAsync();
        using var http = StartHost();
        var credential = await ReissueCredentialAsync();

        // A server-generated key can never read existing protected data: the new-installation-
        // pointed-at-a-used-database refusal, as a fixed 400 without a file.
        var create = await http.SendAsync(
            CreateRequest(CreatePath, new { database = SqliteTarget(protectedPath) }, credential),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, create.StatusCode);
        Assert.False(File.Exists(_bootstrapPath));
    }

    [Fact]
    public async Task ResponsesStdoutAndDiagnostics_DoNotCarrySecrets()
    {
        using var http = StartHost();
        var credential = await ReissueCredentialAsync();
        var databasePath = Path.Combine(_directory, "identity.db");
        // Resolved before the creation stops the host, when the container is still alive.
        var projector = _factory!.Services.GetRequiredService<RequestHeaderDiagnosticProjector>();

        var originalOutput = Console.Out;
        var captured = new StringWriter();
        Console.SetOut(captured);
        try
        {
            var create = await http.SendAsync(
                CreateRequest(CreatePath, new { database = SqliteTarget(databasePath) }, credential),
                TestContext.Current.CancellationToken);
            var body = await create.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            var generatedKey = ReadMasterKeyFromFile();

            Assert.DoesNotContain(credential, body, StringComparison.Ordinal);
            Assert.DoesNotContain(generatedKey, body, StringComparison.Ordinal);
            var output = captured.ToString();
            Assert.DoesNotContain(credential, output, StringComparison.Ordinal);
            Assert.DoesNotContain(generatedKey, output, StringComparison.Ordinal);
        }
        finally
        {
            Console.SetOut(originalOutput);
        }

        // The credential header is on the shared denied list, so its value never survives a
        // structured diagnostic projection.
        var headers = new HeaderDictionary
        {
            ["X-ServiceMantle-Bootstrap-Credential"] = credential,
            ["X-Some-Ordinary-Header"] = "ordinary-value",
        };
        var projected = projector.Project(headers);
        Assert.Equal("[REDACTED]", projected["X-ServiceMantle-Bootstrap-Credential"]?.ToString());
        Assert.Equal("ordinary-value", projected["X-Some-Ordinary-Header"]?.ToString());
    }

    private async Task AssertFileIsCanonicalAsync(bool generatedKey, string? providedKey = null)
    {
        using var document = JsonDocument.Parse(await File.ReadAllTextAsync(_bootstrapPath, TestContext.Current.CancellationToken));
        Assert.Equal(4, document.RootElement.EnumerateObject().Count());
        Assert.Equal(1, document.RootElement.GetProperty("FormatVersion").GetInt32());
        Assert.Equal("signacore", document.RootElement.GetProperty("ServiceId").GetString());
        var key = document.RootElement.GetProperty("MasterKey").GetString();
        Assert.False(string.IsNullOrWhiteSpace(key));
        Assert.Equal(generatedKey, string.IsNullOrEmpty(providedKey));
        if (providedKey is not null)
        {
            Assert.Equal(providedKey, key);
        }
    }

    private string ReadMasterKeyFromFile()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(_bootstrapPath));
        return document.RootElement.GetProperty("MasterKey").GetString()!;
    }

    private static async Task AssertHostStopsAsync(HttpClient http)
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            try
            {
                using var status = await http.GetAsync(StatusPath, TestContext.Current.CancellationToken);
            }
            catch (Exception exception) when (
                exception is HttpRequestException or ObjectDisposedException or InvalidOperationException)
            {
                return;
            }

            await Task.Delay(50, TestContext.Current.CancellationToken);
        }

        Assert.Fail("The bootstrap-mode host did not stop after the file was published.");
    }

    /// <summary>
    /// A SQLite database holding one protected setting no candidate key can read, so key
    /// compatibility is Incompatible rather than NoProtectedData.
    /// </summary>
    private async Task<string> CreateProtectedSqliteTargetAsync()
    {
        var databasePath = Path.Combine(_directory, $"protected-{Guid.NewGuid():N}.db");
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = $"Data Source={databasePath}"
        });
        await using var context = new IdentityDbContext(optionsBuilder.Options);
        await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
        context.SystemSettings.Add(new SystemSettingEntity
        {
            Key = "smtp.password",
            Value = "definitely-not-a-readable-envelope",
            ValueType = "string",
            IsSecret = true,
            Version = 1,
            UpdatedAt = DateTimeOffset.UtcNow,
            UpdatedBy = "seed"
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        await context.DisposeAsync();
        TestSqlitePools.ClearAll();
        foreach (var sidecar in new[] { "-journal", "-wal", "-shm" })
        {
            var sidecarPath = databasePath + sidecar;
            if (File.Exists(sidecarPath))
            {
                File.Delete(sidecarPath);
            }
        }

        return databasePath;
    }

    private sealed class AdvancedPhaseSnapshotSource : IServiceHealthSnapshotSource
    {
        public ValueTask<ServiceHealthSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new ServiceHealthSnapshot(
                ServiceStartupPhase.PendingSetup,
                ServiceMigrationReadinessState.Succeeded,
                ServiceDatabaseReadinessState.Reachable));
    }

    private sealed class ThrowingValidator : IBootstrapCandidateValidator
    {
        public ValueTask<BootstrapValidationResult> ValidateAsync(
            BootstrapConfiguration candidate,
            CancellationToken cancellationToken) =>
            throw new IOException("simulated internal failure");
    }
}
