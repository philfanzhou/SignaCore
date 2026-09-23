using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle.Configuration;
using ServiceMantle.Health;
using SignaCore.Database;
using SignaCore.Host;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Acceptance of the multi-instance contract over one shared database on the default SQLite
/// path: two hosts converge on a single migration and a single setup completion without a
/// duplicate initialization, both instances observe the same installation and configuration
/// version, the management cookie crosses instances under the shared service id, and an
/// instance that is not yet installed — or whose business readiness fails — never reports
/// ready while liveness keeps reporting the process alive.
/// <para>
/// Competition windows are deterministic barriers, never sleeps: the setup race is frozen by an
/// externally held SQLite write transaction that both completion attempts contend on. The
/// PostgreSQL contract face of the migration gate stays with
/// <see cref="ServiceMantleMigrationGateTests"/> under
/// <c>RUN_SIGNACORE_DATABASE_CONTRACTS=true</c>.
/// </para>
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class MultiInstanceAcceptanceTests : IAsyncLifetime
{
    private const string Root = "/management/v1";
    private const string SetupEntryPath = "/management/v1/setup";
    private const string CookieName = "__Host-ServiceMantle.Management";
    private const string RootSecret = "multi-instance-acceptance-root-secret";
    private const string AdminUsername = "multi_admin";
    private const string AdminPassword = "MultiAdmin123";
    private const string PublicBaseUrl = "https://identity.example.test";

    private string _workingDirectory = string.Empty;
    private string _databasePath = string.Empty;
    private string _connectionString = string.Empty;
    private string _bootstrapFilePath = string.Empty;
    private readonly List<WebApplicationFactory<Program>> _factories = [];

    public ValueTask InitializeAsync()
    {
        _workingDirectory = Path.Combine(Path.GetTempPath(), $"signacore-multi-{Guid.NewGuid():N}");
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
    /// Two hosts booting over one fresh database: the first migration wins once and the second
    /// host observes the schema as current, the setup code is issued exactly once (the second
    /// boot reprints nothing), both instances stay not-ready while the installation is pending,
    /// and after the single completion two fresh normal instances observe the identical
    /// installation and configuration version and share the management cookie.
    /// </summary>
    [Fact]
    public async Task TwoHosts_OverOneFreshDatabase_ConvergeOnASingleInstallation()
    {
        _bootstrapFilePath = await InstallationTestSupport.PrepareUninstalledBootstrapAsync(
            _workingDirectory,
            new DatabaseOptions { Provider = "SQLite", ConnectionString = _connectionString },
            RootSecret);

        string code;
        string secondBootConsole;
        using (var capture = new ConsoleCapture())
        {
            using var first = CreateInstance();

            code = ExtractSetupCode(capture.Output);
            Assert.Equal(1, CountOccurrences(capture.Output, code));

            using var second = CreateInstance();
            secondBootConsole = capture.Output;

            // The second instance over the same pending database never issues another plaintext
            // code, and the pending installation stays single.
            Assert.Equal(1, CountOccurrences(secondBootConsole, code));
            await using var db = OpenDatabase();
            Assert.Equal(
                1, await db.ServiceInstallations.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
            Assert.True(await db.Database.SqlQuery<int>(
                $"""SELECT COUNT(DISTINCT "MigrationId") AS "Value" FROM __EFMigrationsHistory""")
                .SingleAsync(TestContext.Current.CancellationToken) > 0);

            // While the installation is pending, neither instance reports ready on any phase
            // endpoint, and both stay live so a launcher can reach them.
            using var secondClient = second.CreateClient();
            foreach (var path in new[] { "/health", "/health/live", "/health/ready" })
            {
                using var firstResponse = await first.CreateClient()
                    .GetAsync(path, TestContext.Current.CancellationToken);
                using var secondResponse = await secondClient.GetAsync(path, TestContext.Current.CancellationToken);
                Assert.Equal(path == "/health/live" ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable,
                    firstResponse.StatusCode);
                Assert.Equal(path == "/health/live" ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable,
                    secondResponse.StatusCode);
            }

            // The single completion uses the once-issued plaintext code.
            Assert.Equal(
                HttpStatusCode.NoContent,
                (await PostSetupAsync(first.CreateClient(), code)).StatusCode);
        }

        foreach (var factory in _factories)
        {
            factory.Dispose();
        }

        _factories.Clear();

        // Two fresh normal instances over the completed database observe the identical state.
        using var normalA = CreateInstance();
        using var normalB = CreateInstance();

        foreach (var factory in new[] { normalA, normalB })
        {
            using var client = factory.CreateClient();
            using var status = await client.GetAsync(SetupEntryPath, TestContext.Current.CancellationToken);
            Assert.Equal(
                "completed",
                (await status.Content.ReadFromJsonAsync<JsonElement>(
                    cancellationToken: TestContext.Current.CancellationToken))
                    .GetProperty("status").GetString());
            using var ready = await client.GetAsync("/health/ready", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
        }

        // The configuration authority is the shared aggregate: both instances activated the same
        // version with the same key corpus, and the installation is single and Completed.
        var accessorA = normalA.Services.GetRequiredService<IServiceSettingCurrentSnapshotAccessor>();
        var accessorB = normalB.Services.GetRequiredService<IServiceSettingCurrentSnapshotAccessor>();
        Assert.True(accessorA.TryGetCurrent(out var snapshotA));
        Assert.True(accessorB.TryGetCurrent(out var snapshotB));
        Assert.Equal(1, snapshotA!.Version);
        Assert.Equal(snapshotA.Version, snapshotB!.Version);
        Assert.Equal(snapshotA.Values.Keys.Order(StringComparer.Ordinal), snapshotB.Values.Keys.Order(StringComparer.Ordinal));

        await using (var db = OpenDatabase())
        {
            var installation = await db.ServiceInstallations.SingleAsync(
                cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal(ServiceMantle.Installation.InstallationStatus.Completed, installation.Status);
            Assert.Equal(1, await db.PasswordCredentials.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        }

        // The management cookie crosses instances under the shared service id.
        var cookie = await LoginAsync(normalA);
        var sessionRequest = new HttpRequestMessage(HttpMethod.Get, Root + "/session");
        sessionRequest.Headers.TryAddWithoutValidation("Cookie", cookie);
        using var sessionOnB = await normalB.CreateClient()
            .SendAsync(sessionRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, sessionOnB.StatusCode);
    }

    /// <summary>
    /// A deterministic setup race: an externally held write transaction freezes the completion
    /// window while two instances submit the same code. Exactly one completion wins, the loser
    /// gets a definitive rejection, and the database keeps one administrator, one Completed row,
    /// one aggregate version, and one installation event.
    /// </summary>
    [Fact]
    public async Task TwoConcurrentCompletions_WithAFrozenWindow_HaveExactlyOneWinner()
    {
        _bootstrapFilePath = await InstallationTestSupport.PrepareUninstalledBootstrapAsync(
            _workingDirectory,
            new DatabaseOptions { Provider = "SQLite", ConnectionString = _connectionString },
            RootSecret);

        var first = CreateInstance();

        // Reissue deterministically through the shared store the operator command uses, so the
        // competing submissions carry the same code regardless of banner timing.
        var code = RotateSetupCode();

        var second = CreateInstance();

        // The barrier: hold a write transaction on the installation row so both submissions are
        // in flight when the window opens.
        await using var freeze = new SqliteConnection(_connectionString);
        await freeze.OpenAsync(TestContext.Current.CancellationToken);
        await ExecuteAsync(freeze, "BEGIN IMMEDIATE", TestContext.Current.CancellationToken);
        await ExecuteAsync(
            freeze,
            "UPDATE service_installations SET version = version WHERE service_id = 'signacore'",
            TestContext.Current.CancellationToken);

        var submissionA = PostSetupAsync(first.CreateClient(), code);
        var submissionB = PostSetupAsync(second.CreateClient(), code);
        await ExecuteAsync(freeze, "COMMIT", TestContext.Current.CancellationToken);

        var responses = await Task.WhenAll(submissionA, submissionB);
        var winners = responses.Count(response => response.StatusCode == HttpStatusCode.NoContent);
        Assert.Equal(1, winners);
        foreach (var response in responses.Where(response => response.StatusCode != HttpStatusCode.NoContent))
        {
            Assert.Contains(
                response.StatusCode,
                new[] { HttpStatusCode.Conflict, HttpStatusCode.ServiceUnavailable });
        }

        await using var db = OpenDatabase();
        var installation = await db.ServiceInstallations.SingleAsync(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(ServiceMantle.Installation.InstallationStatus.Completed, installation.Status);
        Assert.Equal(1, await db.PasswordCredentials.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
        Assert.Single((await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                db, TestContext.Current.CancellationToken))
            .Where(row => row.Action == "installation.completed"));
        var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(
            db, TestContext.Current.CancellationToken);
        Assert.NotNull(aggregate);
        Assert.Equal(1, aggregate!.Version);
    }

    /// <summary>
    /// A business readiness failure on one instance keeps that instance's liveness at 200 while
    /// every readiness surface reports 503 with the contributor's stable error code — the
    /// completed sibling instance keeps reporting ready.
    /// </summary>
    [Fact]
    public async Task ABusinessReadinessFailureOnOneInstance_NeverReportsReady()
    {
        _bootstrapFilePath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
            _workingDirectory,
            new DatabaseOptions { Provider = "SQLite", ConnectionString = _connectionString },
            RootSecret,
            AdminUsername,
            AdminPassword);

        using var healthy = CreateInstance();
        using var failing = CreateInstance(services =>
            services.AddSingleton<IServiceReadinessContributor>(new FailingReadinessContributor()));

        using var healthyReady = await healthy.CreateClient()
            .GetAsync("/health/ready", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, healthyReady.StatusCode);

        using var failingClient = failing.CreateClient();
        using var failingLive = await failingClient.GetAsync("/health/live", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, failingLive.StatusCode);

        foreach (var path in new[] { "/health", "/health/ready" })
        {
            using var response = await failingClient.GetAsync(path, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            using var body = JsonDocument.Parse(
                await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            Assert.Equal(
                FailingReadinessContributor.ErrorCode,
                body.RootElement.GetProperty("errorCode").GetString());
        }
    }

    private sealed class FailingReadinessContributor : IServiceReadinessContributor
    {
        internal const string ErrorCode = "acceptance.business_unavailable";

        // A distinct position in the shared readiness sequence: the signing-key gate owns 100.
        public int Order => 200;

        public ValueTask<ServiceReadinessContributorResult> EvaluateAsync(
            ServiceHealthSnapshot snapshot,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(snapshot);
            return ValueTask.FromResult(ServiceReadinessContributorResult.NotReady(ErrorCode));
        }
    }

    private WebApplicationFactory<Program> CreateInstance(
        Action<IServiceCollection>? configureTestServices = null)
    {
        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("Bootstrap:FilePath", _bootstrapFilePath);
                if (configureTestServices is not null)
                {
                    builder.ConfigureTestServices(configureTestServices);
                }
            });
        _factories.Add(factory);
        factory.CreateClient();
        return factory;
    }

    private string RotateSetupCode()
    {
        using var db = OpenDatabase();
        var setupCodeStore = new ServiceMantle.Persistence.EntityFrameworkCore.EfCoreServiceSetupCodeStore<IdentityDbContext>(
            db,
            lifetime: ServiceMantle.Installation.SetupCodeLifetime.Create(TimeSpan.FromHours(1)));
        var issued = setupCodeStore.RotateAsync(
            SignaCore.Host.Installation.InstallationStores.ServiceId, TestContext.Current.CancellationToken)
            .GetAwaiter().GetResult();
        Assert.True(issued.IsIssued, $"Rotation failed: {issued.ErrorCode}");
        return issued.SetupCode!.Reveal();
    }

    private static async Task<HttpResponseMessage> PostSetupAsync(HttpClient http, string setupCode)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, SetupEntryPath)
        {
            Content = JsonContent.Create(new
            {
                code = setupCode,
                input = new
                {
                    publicBaseUrl = PublicBaseUrl,
                    allowNonHttpsIssuer = false,
                    jwtAudience = "SignaCore.Services",
                    username = AdminUsername,
                    password = AdminPassword
                }
            }),
        };
        request.Headers.Add("X-ServiceMantle-Request", "1");
        return await http.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static async Task<string> LoginAsync(WebApplicationFactory<Program> factory)
    {
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, Root + "/session/login")
        {
            Content = new StringContent(
                JsonSerializer.Serialize(new { username = AdminUsername, password = AdminPassword }),
                Encoding.UTF8,
                "application/json")
        };
        request.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(response.Headers.NonValidated.TryGetValues("Set-Cookie", out var cookieValues));
        return cookieValues
            .Single(value => value.StartsWith($"{CookieName}=", StringComparison.Ordinal))
            .Split(';')[0];
    }

    private static async Task ExecuteAsync(
        SqliteConnection connection,
        string commandText,
        CancellationToken cancellationToken)
    {
        using var command = connection.CreateCommand();
        command.CommandText = commandText;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string ExtractSetupCode(string console)
    {
        var marker = console.IndexOf("enter the one-time setup code:", StringComparison.Ordinal);
        Assert.True(marker >= 0, "The first-run setup banner was not printed on the console.");
        var following = console[(marker + "enter the one-time setup code:".Length)..];
        var codeLine = following
            .Split('\n')
            .Select(line => line.Trim('\r', ' '))
            .FirstOrDefault(line => line.Length > 0);
        Assert.False(string.IsNullOrWhiteSpace(codeLine), "The setup banner carries no code line.");
        return codeLine!;
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        var count = 0;
        var index = 0;
        while ((index = haystack.IndexOf(needle, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += needle.Length;
        }

        return count;
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
