using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ServiceMantle.Audit;
using ServiceMantle.Bootstrap;
using ServiceMantle.Management;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Management;
using SignaCore.Host.Models;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Authenticated replacement of the bootstrap database target through the shared update entry
/// <c>PUT /management/v1/bootstrap</c>: a confirmed change keeps the current master key, rewrites
/// the file atomically in the canonical schema, writes the <c>bootstrap_updated</c> audit row for
/// the logged-in operator, and stops the process after the response completed. Every refusal —
/// confirmation, reachability, key rules, and the Development fallback — leaves the file, the
/// audit trail, and the process untouched.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class AdminBootstrapReplacementTests : IAsyncLifetime
{
    private const string UpdatePath = "/management/v1/bootstrap";
    private const string UnsafeRequestHeader = "X-ServiceMantle-Request";
    private const string ConfirmHeader = "X-SignaCore-Confirm-Database-Change";
    private const string RootSecret = "replacement-root-secret-for-tests-only";
    private const string AdminUsername = "replacement_admin";
    private const string AdminPassword = "ReplacementAdmin123!";

    private string _directory = string.Empty;
    private string _databasePath = string.Empty;
    private string _bootstrapPath = string.Empty;
    private string _databaseConnectionString = string.Empty;
    private Guid _adminAccountId;

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    public async ValueTask InitializeAsync()
    {
        _directory = Path.Combine(CreateTemporaryRoot(), $"signacore-bootstrap-replace-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_directory);
        _databasePath = Path.Combine(_directory, "identity.db");
        _databaseConnectionString =
            new SqliteConnectionStringBuilder { DataSource = _databasePath }.ConnectionString;
        var database = new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = _databaseConnectionString
        };

        _bootstrapPath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
            _directory,
            database,
            RootSecret,
            AdminUsername,
            AdminPassword);
        _adminAccountId = await ReadAdminAccountIdAsync();
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
        TestSqlitePools.ClearAll();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        return ValueTask.CompletedTask;
    }

    private async Task<Guid> ReadAdminAccountIdAsync()
    {
        await using var db = OpenDatabase();
        var credential = await db.PasswordCredentials.AsNoTracking()
            .SingleAsync(item => item.Username == AdminUsername, Token);
        return credential.AccountId;
    }

    private IdentityDbContext OpenDatabase()
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = _databaseConnectionString
        });
        return new IdentityDbContext(optionsBuilder.Options);
    }

    private WebApplicationFactory<Program> StartHost(Action<IServiceCollection>? testServices = null) =>
        new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                // The tests run in Development, where the legacy admin cookie remains usable over
                // plain HTTP. The bootstrap file exists, so the Development fallback never engages.
                builder.UseEnvironment("Development");
                builder.UseSetting(SignaCoreBootstrapStore.FilePathConfigurationKey, _bootstrapPath);
                if (testServices is not null)
                {
                    builder.ConfigureTestServices(testServices);
                }
            });

    /// <summary>
    /// The management cookie is Secure in every environment, so the client addresses the in-memory
    /// TestServer over https to let the cookie container replay it.
    /// </summary>
    private static async Task<HttpClient> CreateAdminClientAsync(
        WebApplicationFactory<Program> factory,
        string username = AdminUsername,
        string password = AdminPassword)
    {
        var http = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
        using var login = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
        {
            Content = JsonContent.Create(new { username, password })
        };
        login.Headers.TryAddWithoutValidation(UnsafeRequestHeader, "1");
        var loginResponse = await http.SendAsync(login, Token);
        Assert.True(loginResponse.IsSuccessStatusCode, $"admin login failed: {loginResponse.StatusCode}");
        return http;
    }

    private static Task<HttpResponseMessage> PutAsync(
        HttpClient client,
        string json,
        bool confirmed = true,
        bool withUnsafeHeader = true,
        CancellationToken? cancellationToken = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Put, UpdatePath)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        if (withUnsafeHeader)
        {
            request.Headers.TryAddWithoutValidation(UnsafeRequestHeader, "1");
        }

        if (confirmed)
        {
            request.Headers.TryAddWithoutValidation(ConfirmHeader, "1");
        }

        return client.SendAsync(request, cancellationToken ?? Token);
    }

    private string ReplacementJson(string? connectionString = null, string? masterKey = null)
    {
        var connection = connectionString ??
            new SqliteConnectionStringBuilder
            {
                DataSource = Path.Combine(_directory, "replacement.db")
            }.ConnectionString;
        var json = "{\"database\":{\"provider\":\"SQLite\",\"serverVersion\":null,\"connectionString\":" +
            JsonSerializer.Serialize(connection) + "}";
        if (masterKey is not null)
        {
            json += ",\"masterKey\":" + JsonSerializer.Serialize(masterKey);
        }

        return json + "}";
    }

    private async Task<string> ReadBootstrapAsync() =>
        await File.ReadAllTextAsync(_bootstrapPath, Token);

    private async Task<List<AuditLogEntity>> ReadAuditRowsAsync()
    {
        await using var db = OpenDatabase();
        return await db.AuditLogs.AsNoTracking()
            .Where(row => row.Action == "bootstrap_updated")
            .ToListAsync(Token);
    }

    private static async Task<bool> WaitForStopAsync(CancellationToken stopping)
    {
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(Token);
        cancellation.CancelAfter(TimeSpan.FromSeconds(15));
        try
        {
            await Task.WhenAny(
                Task.Delay(Timeout.Infinite, stopping),
                Task.Delay(Timeout.Infinite, cancellation.Token));
        }
        catch (OperationCanceledException)
        {
        }

        return stopping.IsCancellationRequested;
    }

    private static async Task AssertCallerCancelledAsync(Func<Task<HttpResponseMessage>> pending)
    {
        var failure = await Assert.ThrowsAnyAsync<Exception>(pending);
        Assert.True(
            failure is OperationCanceledException ||
            failure is HttpRequestException { InnerException: OperationCanceledException },
            $"expected caller cancellation, observed {failure.GetType().Name}: {failure.Message}");
    }

    /// <summary>
    /// Captures the host's stopping token while the factory's service provider is still alive: a
    /// stopped host disposes it, and resolving after the stop would throw.
    /// </summary>
    private static CancellationToken CaptureStoppingToken(WebApplicationFactory<Program> factory) =>
        factory.Services.GetRequiredService<IHostApplicationLifetime>().ApplicationStopping;

    [Fact]
    public async Task ConfirmedUpdate_KeepsTheKeyRewritesTheFileAuditsAndStops()
    {
        using var factory = StartHost();
        var stopping = CaptureStoppingToken(factory);
        using var admin = await CreateAdminClientAsync(factory);
        var replacementPath = Path.Combine(_directory, "replacement.db");

        using var response = await PutAsync(
            admin,
            ReplacementJson(new SqliteConnectionStringBuilder { DataSource = replacementPath }.ConnectionString));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(Token);
        Assert.Equal("""{"restartRequired":true}""", body);
        Assert.DoesNotContain(RootSecret, body, StringComparison.Ordinal);
        Assert.DoesNotContain(replacementPath, body, StringComparison.Ordinal);

        // The shared store replaced the file atomically: canonical schema, the same master key, the
        // new target, and no temporary leftovers.
        using var document = JsonDocument.Parse(await ReadBootstrapAsync());
        Assert.Equal(1, document.RootElement.GetProperty("FormatVersion").GetInt32());
        Assert.Equal("signacore", document.RootElement.GetProperty("ServiceId").GetString());
        Assert.Contains(replacementPath,
            document.RootElement.GetProperty("Database").GetProperty("ConnectionString").GetString(),
            StringComparison.Ordinal);
        // An omitted key means "keep the current one": the key did not rotate.
        Assert.Equal(RootSecret, document.RootElement.GetProperty("MasterKey").GetString());
        Assert.Empty(Directory.EnumerateFiles(_directory, "*.tmp"));

        // The audit row names the operator of the management session, the provider, and the
        // redacted endpoint only.
        var audit = await WaitForAuditRowAsync();
        Assert.Single(audit);
        Assert.Equal(_bootstrapPath, audit[0].TargetId);
        Assert.Equal(_adminAccountId, audit[0].ActorId);
        Assert.Equal(AdminUsername, audit[0].ActorName);
        Assert.Contains("SQLite", audit[0].Description, StringComparison.Ordinal);
        Assert.DoesNotContain(RootSecret, audit[0].Description, StringComparison.Ordinal);
        Assert.DoesNotContain(replacementPath, audit[0].Description, StringComparison.Ordinal);

        Assert.True(await WaitForStopAsync(stopping));
    }

    [Fact]
    public async Task SavingTheLiveTargetAgain_IsRefusedByTheSharedCandidateChecks()
    {
        // The running SQLite database keeps a hot WAL, and the shared candidate validation
        // deliberately refuses a target with present journal sidecars, so an identical candidate
        // on this host answers the shared fixed 400 instead of reaching the manager. The guard's
        // 200 path audits without comparing content, so the identical-candidate 200 row of the
        // semantic model is reachable only for targets the shared checks accept.
        using var factory = StartHost();
        var stopping = CaptureStoppingToken(factory);
        using var admin = await CreateAdminClientAsync(factory);
        var before = await ReadBootstrapAsync();

        using var response = await PutAsync(admin, ReplacementJson(_databaseConnectionString));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(Token);
        Assert.Contains("management.request.invalid", body, StringComparison.Ordinal);
        Assert.Equal(before, await ReadBootstrapAsync(), StringComparer.Ordinal);
        Assert.Empty(await ReadAuditRowsAsync());
        Assert.False(stopping.IsCancellationRequested);
    }

    [Fact]
    public async Task AKeyThatTheTargetDataAlreadyUses_IsAcceptedAndAdopted()
    {
        const string targetKey = "the-key-the-target-data-already-uses";
        var protectedPath = await CreateProtectedTargetAsync("compatible.db", targetKey);
        using var factory = StartHost();
        var stopping = CaptureStoppingToken(factory);
        using var admin = await CreateAdminClientAsync(factory);

        using var response = await PutAsync(
            admin,
            ReplacementJson(new SqliteConnectionStringBuilder { DataSource = protectedPath }.ConnectionString, targetKey));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await ReadBootstrapAsync());
        Assert.Equal(targetKey, document.RootElement.GetProperty("MasterKey").GetString());
        Assert.Single(await WaitForAuditRowAsync());
        Assert.True(await WaitForStopAsync(stopping));
    }

    [Fact]
    public async Task UnconfirmedUpdate_IsRefusedBeforeTheHandlerAndChangesNothing()
    {
        var validator = CountingValidator.Counting(RootSecret);
        using var factory = StartHost(services =>
        {
            services.RemoveAll<IBootstrapCandidateValidator>();
            services.AddSingleton<IBootstrapCandidateValidator>(validator);
        });
        var stopping = CaptureStoppingToken(factory);
        using var admin = await CreateAdminClientAsync(factory);
        var before = await ReadBootstrapAsync();

        using var response = await PutAsync(admin, ReplacementJson(), confirmed: false);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(Token);
        Assert.Contains("signacore.bootstrap.confirmation_required", body, StringComparison.Ordinal);
        Assert.Equal(before, await ReadBootstrapAsync(), StringComparer.Ordinal);
        Assert.Empty(await ReadAuditRowsAsync());
        // The SignaCore error code is the guard's own: the shared handler — and with it the
        // manager — was never reached.
        Assert.Equal(0, validator.Calls);
        Assert.False(stopping.IsCancellationRequested);
    }

    [Fact]
    public async Task MissingTargetWithAReplacementKey_IsRefusedAndPreparesNothing()
    {
        using var factory = StartHost();
        var stopping = CaptureStoppingToken(factory);
        using var admin = await CreateAdminClientAsync(factory);
        var freshPath = Path.Combine(_directory, "fresh-replacement.db");
        var before = await ReadBootstrapAsync();

        using var response = await PutAsync(
            admin,
            ReplacementJson(new SqliteConnectionStringBuilder { DataSource = freshPath }.ConnectionString, "a-different-key"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(before, await ReadBootstrapAsync(), StringComparer.Ordinal);
        Assert.Empty(await ReadAuditRowsAsync());
        // The refusal decided before anything was created: no prepared empty target is left behind.
        Assert.False(File.Exists(freshPath));
        Assert.False(stopping.IsCancellationRequested);
    }

    [Fact]
    public async Task AnIncompatibleKeyForProtectedData_IsRefused()
    {
        var protectedPath = await CreateProtectedTargetAsync("incompatible.db", "the-target-key");
        using var factory = StartHost();
        var stopping = CaptureStoppingToken(factory);
        using var admin = await CreateAdminClientAsync(factory);
        var before = await ReadBootstrapAsync();

        // A key that is neither the running one nor able to read the target's data.
        using var response = await PutAsync(
            admin,
            ReplacementJson(new SqliteConnectionStringBuilder { DataSource = protectedPath }.ConnectionString, "a-wrong-key"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(before, await ReadBootstrapAsync(), StringComparer.Ordinal);
        Assert.Empty(await ReadAuditRowsAsync());
        Assert.False(stopping.IsCancellationRequested);
    }

    [Fact]
    public async Task AnExplicitlyBlankMasterKey_IsRejectedByTheSharedParser()
    {
        using var factory = StartHost();
        using var admin = await CreateAdminClientAsync(factory);
        var before = await ReadBootstrapAsync();

        using var response = await PutAsync(
            admin,
            $$"""{"database":{"provider":"SQLite","serverVersion":null,"connectionString":"Data Source={{Path.Combine(_directory, "blank-key.db")}}"},"masterKey":""}""");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(Token);
        Assert.Contains("management.request.invalid", body, StringComparison.Ordinal);
        Assert.Equal(before, await ReadBootstrapAsync(), StringComparer.Ordinal);
        Assert.Empty(await ReadAuditRowsAsync());
        Assert.False(File.Exists(Path.Combine(_directory, "blank-key.db")));
    }

    [Fact]
    public async Task AnUnreachableTarget_IsRefusedAndChangesNothing()
    {
        using var factory = StartHost();
        using var admin = await CreateAdminClientAsync(factory);
        var before = await ReadBootstrapAsync();

        var json = """{"database":{"provider":"PostgreSQL","serverVersion":"15","connectionString":"Host=host.invalid.test;Database=x;Username=u;Password=p;Timeout=1"}}""";
        using var response = await PutAsync(admin, json);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(
            before,
            await ReadBootstrapAsync(),
            StringComparer.Ordinal);
        Assert.Empty(await ReadAuditRowsAsync());
    }

    [Fact]
    public async Task WithoutTheManagementCookie_TheUpdateIs401()
    {
        using var factory = StartHost();
        var stopping = CaptureStoppingToken(factory);
        using var anonymous = factory.CreateClient();

        using var response = await PutAsync(anonymous, ReplacementJson(), confirmed: false);

        // Authorization precedes the confirmation rule: no cookie is rejected as unauthenticated,
        // not as unconfirmed.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(await ReadAuditRowsAsync());
        Assert.False(stopping.IsCancellationRequested);
    }

    [Fact]
    public async Task AReadOnlyOperator_Is403EvenWhenConfirmed()
    {
        using var factory = StartHost(services =>
        {
            services.RemoveAll<IManagementIdentityProvider>();
            services.AddScoped<IManagementIdentityProvider, ReadOnlyOperatorProvider>();
        });
        var stopping = CaptureStoppingToken(factory);
        using var reader = await CreateAdminClientAsync(factory);

        using var response = await PutAsync(reader, ReplacementJson(), confirmed: false);

        // The session exists but holds no administration permission: forbidden, and still ahead of
        // the confirmation rule.
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(await ReadAuditRowsAsync());
        Assert.False(stopping.IsCancellationRequested);
    }

    [Fact]
    public async Task TheOldControllerRouteIsGone()
    {
        using var factory = StartHost();
        using var admin = await CreateAdminClientAsync(factory);

        using var legacy = await admin.PutAsJsonAsync("/api/admin/bootstrap", new { confirm = true }, Token);

        Assert.True(
            legacy.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.MethodNotAllowed,
            $"the legacy route answered {legacy.StatusCode}");
    }

    [Fact]
    public async Task CallerCancellation_BeforeTheWrite_ChangesNothing()
    {
        var validator = CountingValidator.HoldInsideValidation();
        using var factory = StartHost(services =>
        {
            services.RemoveAll<IBootstrapCandidateValidator>();
            services.AddSingleton<IBootstrapCandidateValidator>(validator);
        });
        var stopping = CaptureStoppingToken(factory);
        using var admin = await CreateAdminClientAsync(factory);

        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(Token);
        var pending = PutAsync(
            admin,
            ReplacementJson(new SqliteConnectionStringBuilder
            {
                DataSource = Path.Combine(_directory, "cancelled.db")
            }.ConnectionString),
            cancellationToken: cancellation.Token);
        await validator.Entered.Task.WaitAsync(Token);
        await cancellation.CancelAsync();
        await AssertCallerCancelledAsync(() => pending);

        await Task.Delay(TimeSpan.FromSeconds(1), Token);
        Assert.DoesNotContain("cancelled.db", await ReadBootstrapAsync(), StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(_directory, "cancelled.db")));
        Assert.Empty(await ReadAuditRowsAsync());
        Assert.False(stopping.IsCancellationRequested);
    }

    [Fact]
    public async Task CallerCancellation_AfterThePublish_AuditsAndStops()
    {
        using var factory = StartHost(services =>
        {
            services.RemoveAll<IBootstrapCandidateValidator>();
            services.AddSingleton<IBootstrapCandidateValidator>(provider =>
                CountingValidator.CancelAfterValidation(
                    provider.GetRequiredService<IHttpContextAccessor>()));
        });
        var stopping = CaptureStoppingToken(factory);
        using var admin = await CreateAdminClientAsync(factory);

        // The published file survives the lost response, and the aborted request still audits and
        // stops through the guard's file comparison. The client observes its cancellation, or — as
        // the in-memory transport surfaces it — an unusable response that never carries the
        // committed restartRequired result.
        try
        {
            using var response = await PutAsync(
                admin,
                ReplacementJson(new SqliteConnectionStringBuilder
                {
                    DataSource = Path.Combine(_directory, "published.db")
                }.ConnectionString));
            var text = await response.Content.ReadAsStringAsync(Token);
            Assert.NotEqual("""{"restartRequired":true}""", text);
        }
        catch (Exception failure)
        {
            Assert.True(
                failure is OperationCanceledException ||
                failure is HttpRequestException { InnerException: OperationCanceledException },
                $"expected caller cancellation, observed {failure.GetType().Name}: {failure.Message}");
        }

        Assert.Contains("published.db", await ReadBootstrapAsync(), StringComparison.Ordinal);
        Assert.Single(await WaitForAuditRowAsync());
        Assert.True(await WaitForStopAsync(stopping));
    }

    [Fact]
    public async Task AFailingAuditSave_StillStopsAndLogsOneFixedLine()
    {
        var capture = new LogCapture();
        using var factory = StartHost(services =>
        {
            services.RemoveAll<IAuditService>();
            services.AddScoped<IAuditService, ThrowingAuditService>();
            services.RemoveAll<ILoggerFactory>();
            services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
                logging.AddProvider(capture)));
        });
        var stopping = CaptureStoppingToken(factory);
        using var admin = await CreateAdminClientAsync(factory);

        using var response = await PutAsync(
            admin,
            ReplacementJson(new SqliteConnectionStringBuilder
            {
                DataSource = Path.Combine(_directory, "audit-failure.db")
            }.ConnectionString));

        // The bootstrap change itself is not affected by the audit failure: the response is 200 and
        // the instance stops so the restart completes.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await WaitForStopAsync(stopping));

        // No audit row exists and exactly the fixed log line explains why. The line carries no
        // connection string and no key.
        Assert.Empty(await ReadAuditRowsAsync());
        var logged = string.Join('\n', capture.Messages);
        Assert.Contains("bootstrap_updated audit row could not be written", logged, StringComparison.Ordinal);
        Assert.DoesNotContain(RootSecret, logged, StringComparison.Ordinal);
        Assert.DoesNotContain(_databaseConnectionString, logged, StringComparison.Ordinal);
    }

    private async Task<List<AuditLogEntity>> WaitForAuditRowAsync()
    {
        using var waiter = CancellationTokenSource.CreateLinkedTokenSource(Token);
        waiter.CancelAfter(TimeSpan.FromSeconds(15));
        while (true)
        {
            var rows = await ReadAuditRowsAsync();
            if (rows.Count > 0)
            {
                return rows;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(100), waiter.Token);
        }
    }

    /// <summary>
    /// Creates a target holding one shared sensitive envelope really protected with
    /// <paramref name="key"/>, so key compatibility is decided by actual decryption rather than by
    /// a sentinel string.
    /// </summary>
    private async Task<string> CreateProtectedTargetAsync(string fileName, string key)
    {
        var databasePath = Path.Combine(_directory, fileName);
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = $"Data Source={databasePath}"
        });
        await using var context = new IdentityDbContext(optionsBuilder.Options);
        await context.Database.MigrateAsync(Token);
        var rootKey = Convert.ToBase64String(
            new BootstrapMasterKeyProvider(key).GetMasterKey());
        var envelope = new ServiceMantle.Configuration.SensitiveValueProtector(
                SignaCore.Host.Installation.InstallationStores.ServiceId,
                "sms.otp_hmac_key")
            .Protect("the-protected-value", rootKey);
        var valuesJson = "{\"sms.otp_hmac_key\":\"" + envelope + "\"}";
        await context.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO service_settings (service_id, values_json, version, updated_at_utc, updated_by, restart_required)
            VALUES ('signacore', {valuesJson}, 1, {DateTime.UtcNow}, 'seed', 0)
            """,
            Token);
        await context.DisposeAsync();
        TestSqlitePools.ClearAll();
        foreach (var sidecar in new[] { "-journal", "-wal", "-shm" })
        {
            var path = databasePath + sidecar;
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }

        return databasePath;
    }

    /// <summary>
    /// A test double for the SignaCore candidate validator. Counting its calls observes whether
    /// the shared manager was reached at all; <see cref="HoldInsideValidation"/> parks a request
    /// inside validation until the caller cancels; <see cref="CancelAfterValidation"/> swaps the
    /// observed <c>RequestAborted</c> for an already-cancelled token once validation succeeds, so
    /// the shared handler observes the abort after the manager published the file.
    /// </summary>
    private sealed class CountingValidator : IBootstrapCandidateValidator
    {
        private readonly SignaCoreBootstrapCandidateValidator inner;
        private readonly TaskCompletionSource? releaseGate;
        private readonly IHttpContextAccessor? accessor;
        private readonly bool cancelAfterValidation;
        private int calls;

        private CountingValidator(
            string currentMasterKey,
            TaskCompletionSource? releaseGate,
            bool cancelAfterValidation,
            IHttpContextAccessor? accessor)
        {
            inner = new SignaCoreBootstrapCandidateValidator(
                SignaCoreBootstrapStore.CreateProviderRegistry(),
                currentMasterKey);
            this.releaseGate = releaseGate;
            this.cancelAfterValidation = cancelAfterValidation;
            this.accessor = accessor;
        }

        internal static CountingValidator Counting(string currentMasterKey) =>
            new(currentMasterKey, null, false, null);

        internal static CountingValidator HoldInsideValidation()
        {
            var validator = new CountingValidator(
                RootSecret,
                new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously),
                false,
                null);
            return validator;
        }

        internal static CountingValidator CancelAfterValidation(IHttpContextAccessor accessor) =>
            new(RootSecret, null, true, accessor);

        /// <summary>Signals that the request reached validation; set only by the holding variant.</summary>
        internal TaskCompletionSource Entered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal int Calls => Volatile.Read(ref calls);

        public async ValueTask<BootstrapValidationResult> ValidateAsync(
            BootstrapConfiguration candidate,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref calls);
            if (releaseGate is not null)
            {
                Entered.TrySetResult();
                await releaseGate.Task.WaitAsync(cancellationToken);
            }

            var result = await inner.ValidateAsync(candidate, cancellationToken);
            if (cancelAfterValidation && result.IsValid && accessor?.HttpContext is { } context)
            {
                using var cancelled = new CancellationTokenSource();
                cancelled.Cancel();
                context.RequestAborted = cancelled.Token;
            }

            return result;
        }
    }

    private sealed class ReadOnlyOperatorProvider : IManagementIdentityProvider
    {
        public ValueTask<ManagementIdentityResult> GetIdentityAsync(
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(ManagementIdentityResult.Authenticated(
                ManagementIdentity.Create(
                    WellKnownManagementAuditOperatorSources.InteractiveAdmin,
                    Guid.NewGuid().ToString(),
                    [ManagementPermission.Read],
                    "Read Only")));
    }

    private sealed class ThrowingAuditService : IAuditService
    {
        public Task RecordLoginAsync(
            Guid? accountId,
            string username,
            string authMethod,
            string eventType,
            string? clientIp,
            string? userAgent,
            string? failureReason = null,
            string? appId = null,
            string? correlationId = null,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task RecordActionAsync(
            string action,
            string targetType,
            string targetId,
            Guid? actorId,
            string? actorName,
            string? description,
            string? clientIp = null,
            string? correlationId = null,
            object? before = null,
            object? after = null,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("simulated audit save failure");
    }

    private sealed class LogCapture : ILoggerProvider
    {
        private readonly List<string> messages = [];

        internal IReadOnlyList<string> Messages
        {
            get
            {
                lock (messages)
                {
                    return [.. messages];
                }
            }
        }

        public ILogger CreateLogger(string categoryName) => new Recorder(this);

        public void Dispose()
        {
        }

        private sealed class Recorder(LogCapture owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                lock (owner.messages)
                {
                    owner.messages.Add(
                        $"{formatter(state, exception)} {exception?.ToString() ?? string.Empty}");
                }
            }
        }
    }
}

/// <summary>
/// A host that loaded its database from the Development fallback instead of the bootstrap file
/// refuses every update with the fixed <c>signacore.bootstrap.not_file_backed</c> result, without
/// reaching the shared handler and without stopping.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class DevelopmentFallbackBootstrapUpdateTests : IAsyncLifetime
{
    private const string UnsafeRequestHeader = "X-ServiceMantle-Request";
    private const string ConfirmHeader = "X-SignaCore-Confirm-Database-Change";
    private const string AdminUsername = "fallback_admin";
    private const string AdminPassword = "FallbackAdmin123!";

    private string _directory = string.Empty;
    private string _databaseConnectionString = string.Empty;

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    public async ValueTask InitializeAsync()
    {
        var root = Path.GetTempPath();
        if (OperatingSystem.IsMacOS() && root.StartsWith("/var/", StringComparison.Ordinal))
        {
            root = "/private" + root;
        }

        _directory = Path.Combine(root, $"signacore-bootstrap-fallback-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_directory);
        var databasePath = Path.Combine(_directory, "identity.db");
        _databaseConnectionString =
            new SqliteConnectionStringBuilder { DataSource = databasePath }.ConnectionString;

        // The fallback derives its root secret deterministically from the provider and the
        // connection string, so the prepared installation is decryptable under it.
        var derivedSecret = $"development-root-secret::SQLite::{_databaseConnectionString}";
        await InstallationTestSupport.PrepareCompletedInstallationAsync(
            _directory,
            new DatabaseOptions
            {
                Provider = "SQLite",
                ConnectionString = _databaseConnectionString
            },
            derivedSecret,
            AdminUsername,
            AdminPassword);
    }

    public ValueTask DisposeAsync()
    {
        TestSqlitePools.ClearAll();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        return ValueTask.CompletedTask;
    }

    [Fact]
    public async Task AFallbackHost_RefusesTheUpdateAsNotFileBacked()
    {
        using var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Development");
                builder.UseSetting("Database:Provider", "SQLite");
                builder.UseSetting("Database:ConnectionString", _databaseConnectionString);
            });
        using var http = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
        using var login = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
        {
            Content = System.Net.Http.Json.JsonContent.Create(new { username = AdminUsername, password = AdminPassword })
        };
        login.Headers.TryAddWithoutValidation(UnsafeRequestHeader, "1");
        var loginResponse = await http.SendAsync(login, Token);
        Assert.True(loginResponse.IsSuccessStatusCode, $"login failed: {loginResponse.StatusCode}");

        var json = "{\"database\":{\"provider\":\"SQLite\",\"serverVersion\":null,\"connectionString\":" +
            System.Text.Json.JsonSerializer.Serialize(_databaseConnectionString) + "}}";
        using var request = new HttpRequestMessage(HttpMethod.Put, "/management/v1/bootstrap")
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        request.Headers.TryAddWithoutValidation(UnsafeRequestHeader, "1");
        request.Headers.TryAddWithoutValidation(ConfirmHeader, "1");

        using var response = await http.SendAsync(request, Token);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(Token);
        Assert.Contains("signacore.bootstrap.not_file_backed", body, StringComparison.Ordinal);
        Assert.False(factory.Services.GetRequiredService<IHostApplicationLifetime>()
            .ApplicationStopping.IsCancellationRequested);
    }
}
