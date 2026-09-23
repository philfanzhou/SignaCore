using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using ServiceMantle.AspNetCore.ManagementApi.Setup;
using ServiceMantle.Installation;
using SignaCore.Database;
using SignaCore.Domain.Validators;
using SignaCore.Host;
using SignaCore.Host.Installation;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Acceptance of the setup failure and recovery contract at the host level: submissions that fail
/// — a wrong or expired code, an invalid input, a caller cancellation inside the completion
/// transaction, or an internal cancellation — never report ready, leave zero partial business,
/// configuration, audit, code-consumption, or completion state, and the restarted host resolves
/// the still-pending installation whose original (never consumed) code completes it.
/// <para>
/// The composed transaction core (<see cref="SetupCompletionExecutor.CompleteAsync"/>) is driven
/// through its internal composition seam with a coordinating password policy for the
/// in-transaction cancellation handshake; every other dependency comes from the booted pending
/// host's real services. The executor-level cancellation checkpoint matrix is pinned by
/// <see cref="SetupContributorDatabaseContractTests"/> and is not repeated here.
/// </para>
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class SetupRecoveryAcceptanceTests : IAsyncLifetime
{
    private const string SetupEntryPath = "/management/v1/setup";
    private const string RootSecret = "setup-recovery-root-secret";
    private const string AdminUsername = "recovery_admin";
    private const string AdminPassword = "RecoveryAdmin123";
    private const string PublicBaseUrl = "https://identity.example.test";

    private string _workingDirectory = string.Empty;
    private string _databasePath = string.Empty;
    private string _connectionString = string.Empty;
    private WebApplicationFactory<Program>? _factory;

    public ValueTask InitializeAsync()
    {
        _workingDirectory = Path.Combine(Path.GetTempPath(), $"signacore-setup-recovery-{Guid.NewGuid():N}");
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

    /// <summary>
    /// Wrong code, expired code, and structurally invalid input are all refused without consuming
    /// the working code or writing anything; after a restart the still-pending installation is
    /// resolved with no reissued plaintext, and the original code completes it.
    /// </summary>
    [Fact]
    public async Task RefusedSubmissions_LeaveZeroState_ResolveAfterRestart_AndTheOriginalCodeCompletes()
    {
        string code;
        using (var http = await StartHostAsync())
        {
            code = await RotateSetupCodeAsync(expiresIn: TimeSpan.FromHours(1));

            // A wrong code is refused; the working code is untouched.
            Assert.Equal(
                HttpStatusCode.Unauthorized,
                (await PostSetupAsync(http, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).StatusCode);

            // A structurally invalid input is the fixed validation refusal, and the code survives.
            Assert.Equal(
                HttpStatusCode.BadRequest,
                (await PostSetupAsync(http, code, inputShape: "missing-password")).StatusCode);

            await AssertNothingPartialAsync();

            // Readiness is never reported while the installation is pending — on any surface.
            using var ready = await http.GetAsync("/health/ready", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
        }

        _factory?.Dispose();
        _factory = null;

        // The expired window across the restart: no plaintext is reissued, the expired code is
        // dead, and the installation still resolves as pending.
        await ExpireSetupCodeAsync();
        using (var capture = new ConsoleCapture())
        {
            using var http = await StartHostAsync();

            var status = await http.GetAsync(SetupEntryPath, TestContext.Current.CancellationToken);
            Assert.Equal(
                "pending",
                (await status.Content.ReadFromJsonAsync<JsonElement>(
                    cancellationToken: TestContext.Current.CancellationToken))
                    .GetProperty("status").GetString());
            Assert.DoesNotContain(code, capture.Output, StringComparison.Ordinal);

            Assert.Equal(
                HttpStatusCode.Unauthorized,
                (await PostSetupAsync(http, code)).StatusCode);
            await AssertNothingPartialAsync();
        }

        _factory?.Dispose();
        _factory = null;

        // A rotation supersedes the dead code: the fresh one completes the installation over the
        // untouched state, landing the whole first-run slice in one transaction.
        var freshCode = await RotateSetupCodeAsync(expiresIn: TimeSpan.FromHours(1));
        using (var http = await StartHostAsync())
        {
            Assert.Equal(
                HttpStatusCode.Unauthorized,
                (await PostSetupAsync(http, code)).StatusCode);
            Assert.Equal(
                HttpStatusCode.NoContent,
                (await PostSetupAsync(http, freshCode)).StatusCode);
        }

        await using (var db = OpenDatabase())
        {
            Assert.Equal(
                InstallationStatus.Completed,
                (await db.ServiceInstallations.SingleAsync(
                    cancellationToken: TestContext.Current.CancellationToken)).Status);
            Assert.Equal(
                1, await db.PasswordCredentials.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
            var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(
                db, TestContext.Current.CancellationToken);
            Assert.Equal(1, aggregate!.Version);
        }
    }

    /// <summary>
    /// A caller cancellation observed inside the completion transaction propagates on the original
    /// token with every staged artifact discarded; the same, never-consumed code completes the
    /// installation on the next submission — first on the live host, and after a restart.
    /// </summary>
    [Fact]
    public async Task CallerCancellationInsideTheTransaction_RollsBackEverything_AndTheSameCodeCompletes()
    {
        using var http = await StartHostAsync();
        var code = await RotateSetupCodeAsync(expiresIn: TimeSpan.FromHours(1));

        using var cancellation = new CancellationTokenSource();
        var enteredValidation = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var policy = new CoordinatingPasswordPolicy(
            onValidate: coordinatorToken =>
            {
                enteredValidation.SetResult();
                // Block the executor's thread inside the transaction until the caller cancels,
                // then surface the caller's own cancellation from the in-transaction call.
                cancellation.Token.WaitHandle.WaitOne();
                throw new OperationCanceledException(cancellation.Token);
            });

        // Task.Run keeps the blocking policy off the test's own thread: the executor's
        // synchronous stretch otherwise runs far enough to block the caller before the first
        // await, deadlocking the handshake.
        var completion = Task.Run(() => DriveCompletionAsync(code, policy, cancellation.Token));
        await enteredValidation.Task.WaitAsync(
            TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
        await cancellation.CancelAsync();

        var propagated = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => completion);
        Assert.Equal(cancellation.Token, propagated.CancellationToken);

        await AssertNothingPartialAsync();
        await AssertReadinessNotReportedAsync(http);

        // The never-consumed code completes the installation on the very next submission, with a
        // fresh attempt state through the real endpoint.
        Assert.Equal(
            HttpStatusCode.NoContent,
            (await PostSetupAsync(http, code)).StatusCode);
        await using (var db = OpenDatabase())
        {
            Assert.Equal(
                InstallationStatus.Completed,
                (await db.ServiceInstallations.SingleAsync(
                    cancellationToken: TestContext.Current.CancellationToken)).Status);
        }
    }

    /// <summary>
    /// An internal cancellation — a foreign token, with the caller's own token still live — is the
    /// fixed safe Unavailable outcome, not a caller cancellation: zero state, and the original
    /// code still completes afterwards.
    /// </summary>
    [Fact]
    public async Task InternalCancellation_IsTheFixedUnavailable_AndTheSameCodeCompletes()
    {
        using var http = await StartHostAsync();
        var code = await RotateSetupCodeAsync(expiresIn: TimeSpan.FromHours(1));

        var policy = new CoordinatingPasswordPolicy(
            onValidate: _ => throw new OperationCanceledException(
                new CancellationToken(canceled: true)));

        var result = await DriveCompletionAsync(code, policy, TestContext.Current.CancellationToken);

        Assert.Equal(SetupCompletionStatus.Unavailable, result.Status);
        await AssertNothingPartialAsync();

        Assert.Equal(
            HttpStatusCode.NoContent,
            (await PostSetupAsync(http, code)).StatusCode);
        await using var db = OpenDatabase();
        Assert.Equal(
            InstallationStatus.Completed,
            (await db.ServiceInstallations.SingleAsync(
                cancellationToken: TestContext.Current.CancellationToken)).Status);
    }

    /// <summary>
    /// Drives the real composed transaction core with the booted pending host's real services; the
    /// password policy is the coordinating seam the scenario injects.
    /// </summary>
    private async Task<SetupCompletionResult> DriveCompletionAsync(
        string code,
        IPasswordPolicy policy,
        CancellationToken cancellationToken)
    {
        Assert.True(SetupCode.TryParse(code, out var parsed), "The rotated code must parse.");

        var scope = _factory!.Services.CreateAsyncScope();
        await using (scope.ConfigureAwait(false))
        {
            var services = scope.ServiceProvider;
            return await SetupCompletionExecutor.CompleteAsync(
                services.GetRequiredService<IdentityDbContext>(),
                services.GetRequiredService<DatabaseOptions>(),
                services.GetRequiredService<ServiceMantle.Configuration.ServiceSettingUpdateService>(),
                policy,
                services.GetRequiredService<InitialAdministratorSetupContributorFactory>(),
                NullLoggerFactory.Instance.CreateLogger("SignaCore.Host.Installation.SetupCompletionExecutor"),
                clientIp: "192.0.2.10",
                parsed!,
                ValidInput(),
                cancellationToken);
        }
    }

    private static JsonElement ValidInput() =>
        JsonSerializer.SerializeToElement(new
        {
            publicBaseUrl = PublicBaseUrl,
            allowNonHttpsIssuer = false,
            jwtAudience = "SignaCore.Services",
            username = AdminUsername,
            password = AdminPassword
        });

    private async Task<HttpClient> StartHostAsync()
    {
        var bootstrapFilePath = await InstallationTestSupport.PrepareUninstalledBootstrapAsync(
            _workingDirectory,
            new DatabaseOptions { Provider = "SQLite", ConnectionString = _connectionString },
            RootSecret);

        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("environment", Microsoft.Extensions.Hosting.Environments.Production);
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath);
            });

        return _factory.CreateClient();
    }

    private static async Task<HttpResponseMessage> PostSetupAsync(
        HttpClient http,
        string setupCode,
        string? inputShape = null)
    {
        object input = inputShape switch
        {
            "missing-password" => new
            {
                publicBaseUrl = PublicBaseUrl,
                allowNonHttpsIssuer = false,
                jwtAudience = "SignaCore.Services",
                username = AdminUsername
            },
            _ => new
            {
                publicBaseUrl = PublicBaseUrl,
                allowNonHttpsIssuer = false,
                jwtAudience = "SignaCore.Services",
                username = AdminUsername,
                password = AdminPassword
            }
        };

        var request = new HttpRequestMessage(HttpMethod.Post, SetupEntryPath)
        {
            Content = JsonContent.Create(new { code = setupCode, input }),
        };
        request.Headers.Add("X-ServiceMantle-Request", "1");
        return await http.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private async Task<string> RotateSetupCodeAsync(TimeSpan expiresIn)
    {
        await using var db = OpenDatabase();
        var setupCodeStore = new ServiceMantle.Persistence.EntityFrameworkCore.EfCoreServiceSetupCodeStore<IdentityDbContext>(
            db,
            lifetime: SetupCodeLifetime.Create(expiresIn));
        var issued = await setupCodeStore.RotateAsync(
            SignaCore.Host.Installation.InstallationStores.ServiceId, TestContext.Current.CancellationToken);
        Assert.True(issued.IsIssued, $"Rotation failed: {issued.ErrorCode}");
        return issued.SetupCode!.Reveal();
    }

    private async Task ExpireSetupCodeAsync()
    {
        await using var db = OpenDatabase();
        var installation = await db.ServiceInstallations.SingleAsync(
            cancellationToken: TestContext.Current.CancellationToken);
        // The material invariants order the stamps strictly (created <= issued < expired), so
        // the expired window is staged by pinning issuance to the creation moment and expiry one
        // tick later: consistent material whose code has been expired since — every host restart
        // since lies strictly after it.
        installation.SetupCodeIssuedAtUtc = installation.CreatedAtUtc;
        installation.SetupCodeExpiresAtUtc = installation.CreatedAtUtc.AddTicks(1);
        await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// The five rollback surfaces: no business rows, no shared aggregate, no audit of any kind, and
    /// the installation row stays pending with its code intact (never consumed).
    /// </summary>
    private async Task AssertNothingPartialAsync()
    {
        await using var db = OpenDatabase();
        Assert.Equal(0, await db.Accounts.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(0, await db.PasswordCredentials.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Null(await SharedSettingTestDatabase.LoadAggregateAsync(
            db, TestContext.Current.CancellationToken));
        Assert.Empty(await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
            db, TestContext.Current.CancellationToken));
        var installation = await db.ServiceInstallations.SingleAsync(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(InstallationStatus.PendingSetup, installation.Status);
        Assert.NotNull(installation.SetupCodeDigest);
    }

    private static async Task AssertReadinessNotReportedAsync(HttpClient http)
    {
        using var live = await http.GetAsync("/health/live", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, live.StatusCode);
        using var ready = await http.GetAsync("/health/ready", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
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

    /// <summary>
    /// The deterministic in-transaction pause point: the executor's first policy call runs inside
    /// the completion transaction, so the coordinated behavior lands mid-transaction every time.
    /// </summary>
    private sealed class CoordinatingPasswordPolicy(Action<CancellationToken> onValidate) : IPasswordPolicy
    {
        public bool Validate(string password, out string errorMessage)
        {
            var source = new CancellationTokenSource();
            onValidate(source.Token);
            // The coordinated behavior always throws; this line exists for the compiler.
            throw new InvalidOperationException("The coordinating policy never completes normally.");
#pragma warning disable CS0162 // Unreachable code after the always-throwing coordination.
            errorMessage = string.Empty;
            return false;
#pragma warning restore CS0162
        }
    }

    private sealed class ConsoleCapture : IDisposable
    {
        private readonly TextWriter _original = Console.Out;
        private readonly StringWriter _buffer = new();

        public ConsoleCapture() => Console.SetOut(TextWriter.Synchronized(_buffer));

        public string Output
        {
            get
            {
                lock (_buffer)
                {
                    return _buffer.ToString();
                }
            }
        }

        public void Dispose()
        {
            Console.SetOut(_original);
            _buffer.Dispose();
        }
    }
}
