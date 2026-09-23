using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using ServiceMantle.Installation;
using SignaCore.Database;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Acceptance of the fresh-install chain end to end, from a database target that does not exist
/// yet: the one-time setup code is issued on the console exactly once, a restart never reprints
/// it, the recovery window (a pending row whose code never persisted) issues a replacement, and
/// the completion transaction lands the initial administrator, the configuration aggregate, the
/// installation event, and the Completed state together. Plaintext secrets are refused on every
/// surface: the HTTP response, the console the host prints on, and the persisted rows.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class FreshInstallAcceptanceTests : IAsyncLifetime
{
    private const string RootSecret = "fresh-install-acceptance-root-secret";
    private const string AdminUsername = "fresh_admin";
    private const string AdminPassword = "FreshAdmin123";
    private const string PublicBaseUrl = "https://identity.example.test";
    private const string SetupEntryPath = "/management/v1/setup";

    private string _workingDirectory = string.Empty;
    private string _databasePath = string.Empty;
    private string _connectionString = string.Empty;
    private WebApplicationFactory<Program>? _factory;

    public ValueTask InitializeAsync()
    {
        _workingDirectory = Path.Combine(Path.GetTempPath(), $"signacore-fresh-{Guid.NewGuid():N}");
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
    /// The full chain on one database: cold start prints the code once, the printed code
    /// completes the installation, and the completion lands every artifact together — then a
    /// restart reports the completed installation without ever reprinting a code.
    /// </summary>
    [Fact]
    public async Task ColdStart_PrintsTheCodeOnce_CompletesAtomically_AndNeverReprintsOnRestart()
    {
        Assert.False(File.Exists(_databasePath), "The acceptance chain starts from a nonexistent target.");

        string code;
        string firstBootConsole;
        using (var capture = new ConsoleCapture())
        {
            using var http = await StartHostAsync();
            firstBootConsole = capture.Output;

            code = ExtractSetupCode(firstBootConsole);
                        // The plaintext appears on the console exactly once: the issuance banner only.
            Assert.Equal(1, CountOccurrences(firstBootConsole, code));

            await using var db = OpenDatabase();
            var installation = await db.ServiceInstallations.SingleAsync(
                cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal(InstallationStatus.PendingSetup, installation.Status);
            Assert.StartsWith("sha256-v1:", installation.SetupCodeDigest, StringComparison.Ordinal);
            Assert.NotEqual(code, installation.SetupCodeDigest);
            Assert.True(await db.Database.SqlQuery<int>(
                $"""SELECT COUNT(*) AS "Value" FROM __EFMigrationsHistory""")
                .SingleAsync(TestContext.Current.CancellationToken) > 0);

            // The completion runs with the console-issued plaintext and carries no secret back.
            var response = await PostSetupAsync(http, code);
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            var responseBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.DoesNotContain(code, responseBody, StringComparison.Ordinal);
            Assert.DoesNotContain(AdminPassword, responseBody, StringComparison.Ordinal);
        }

        await using (var db = OpenDatabase())
        {
            // One transaction, every artifact: initial administrator, configuration version 1,
            // the single installation event, and the Completed row whose code is consumed.
            var credential = await db.PasswordCredentials
                .SingleAsync(cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal(AdminUsername, credential.Username);
            Assert.Equal(1, await db.Accounts.CountAsync(cancellationToken: TestContext.Current.CancellationToken));
            Assert.DoesNotContain(AdminPassword, credential.PasswordHash, StringComparison.Ordinal);

            var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(
                db, TestContext.Current.CancellationToken);
            Assert.NotNull(aggregate);
            Assert.Equal(1, aggregate!.Version);
            Assert.Equal(
                AdminUsername,
                SharedSettingTestDatabase.ParseValues(aggregate)["admin.username"]);

            Assert.Single((await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                    db, TestContext.Current.CancellationToken))
                .Where(row => row.Action == "installation.completed"));

            var installation = await db.ServiceInstallations.SingleAsync(
                cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal(InstallationStatus.Completed, installation.Status);
            Assert.NotNull(installation.CompletedAtUtc);
            Assert.Null(installation.SetupCodeDigest);
        }

        _factory?.Dispose();
        _factory = null;

        using (var capture = new ConsoleCapture())
        {
            using var http = await StartHostAsync();

            var status = await http.GetAsync(SetupEntryPath, TestContext.Current.CancellationToken);
            Assert.Equal(
                "completed",
                (await status.Content.ReadFromJsonAsync<JsonElement>(
                    cancellationToken: TestContext.Current.CancellationToken))
                    .GetProperty("status").GetString());

            // The restart never reissues or reprints the consumed code, and the completion
            // secrets stay off the whole console of the completed host.
            var secondBootConsole = capture.Output;
            Assert.DoesNotContain(code, secondBootConsole, StringComparison.Ordinal);
            Assert.DoesNotContain(AdminPassword, secondBootConsole, StringComparison.Ordinal);
            Assert.DoesNotContain(RootSecret, secondBootConsole, StringComparison.Ordinal);
        }

        // The plaintext of the first boot reached no persisted row: it is gone with the consumed
        // code fields, and no aggregate value carries the password.
        await using (var db = OpenDatabase())
        {
            var installation = await db.ServiceInstallations.SingleAsync(
                cancellationToken: TestContext.Current.CancellationToken);
            Assert.Null(installation.SetupCodeDigest);
            var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(
                db, TestContext.Current.CancellationToken);
            Assert.DoesNotContain(
                AdminPassword,
                JsonSerializer.Serialize(SharedSettingTestDatabase.ParseValues(aggregate!)),
                StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// A restart after issuance keeps the installation pending, reprints nothing, and the code
    /// from the first boot still completes the installation.
    /// </summary>
    [Fact]
    public async Task RestartAfterIssuance_ReprintsNothing_AndTheFirstBootCodeStillCompletes()
    {
        string firstCode;
        using (var capture = new ConsoleCapture())
        {
            using var http = await StartHostAsync();
            firstCode = ExtractSetupCode(capture.Output);
            Assert.Equal(1, CountOccurrences(capture.Output, firstCode));
        }

        _factory?.Dispose();
        _factory = null;

        using (var capture = new ConsoleCapture())
        {
            using var http = await StartHostAsync();

            Assert.DoesNotContain(firstCode, capture.Output, StringComparison.Ordinal);

            await using var db = OpenDatabase();
            var installation = await db.ServiceInstallations.SingleAsync(
                cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal(InstallationStatus.PendingSetup, installation.Status);

            Assert.Equal(HttpStatusCode.NoContent, (await PostSetupAsync(http, firstCode)).StatusCode);
        }

        await using var verifyDb = OpenDatabase();
        Assert.Equal(
            InstallationStatus.Completed,
            (await verifyDb.ServiceInstallations.SingleAsync(
                cancellationToken: TestContext.Current.CancellationToken)).Status);
    }

    /// <summary>
    /// The recovery window: a pending row whose code never persisted (the crash between creating
    /// the row and saving its code) gets a replacement code on the next boot. The lost code is
    /// dead, and the replacement completes the installation.
    /// </summary>
    [Fact]
    public async Task RecoveryWindow_APendingRowWithoutACode_IssuesAReplacementOnBoot()
    {
        string lostCode;
        using (var capture = new ConsoleCapture())
        {
            using var http = await StartHostAsync();
            lostCode = ExtractSetupCode(capture.Output);
        }

        _factory?.Dispose();
        _factory = null;

        // Simulate the crash inside the recovery window: the pending row survives, its code does
        // not (no digest, no expiry, no generation).
        await using (var db = OpenDatabase())
        {
            await db.Database.ExecuteSqlAsync(
                $"""
                UPDATE service_installations
                SET setup_code_digest = NULL,
                    setup_code_expires_at_utc = NULL,
                    setup_code_issued_at_utc = NULL,
                    setup_code_generation = 0
                """,
                TestContext.Current.CancellationToken);
        }

        using (var capture = new ConsoleCapture())
        {
            using var http = await StartHostAsync();

            var replacement = ExtractSetupCode(capture.Output);
            Assert.Equal(1, CountOccurrences(capture.Output, replacement));
            Assert.NotEqual(lostCode, replacement);

            // The code from before the crash is dead.
            Assert.Equal(
                HttpStatusCode.Unauthorized,
                (await PostSetupAsync(http, lostCode)).StatusCode);
            await using var db = OpenDatabase();
            Assert.Equal(
                InstallationStatus.PendingSetup,
                (await db.ServiceInstallations.SingleAsync(
                    cancellationToken: TestContext.Current.CancellationToken)).Status);

            // The replacement completes the installation.
            Assert.Equal(
                HttpStatusCode.NoContent,
                (await PostSetupAsync(http, replacement)).StatusCode);
        }

        await using var verifyDb = OpenDatabase();
        Assert.Equal(
            InstallationStatus.Completed,
            (await verifyDb.ServiceInstallations.SingleAsync(
                cancellationToken: TestContext.Current.CancellationToken)).Status);
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
        // The shared management-entry guard: every management write carries this header.
        request.Headers.Add("X-ServiceMantle-Request", "1");
        return await http.SendAsync(request, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Boots the pending-setup host with the console redirected, the same way the bootstrap-mode
    /// tests capture stdout. The issuance banner is plain console output, so the capture is the
    /// issuance surface.
    /// </summary>
    private async Task<HttpClient> StartHostAsync()
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
            });

        return _factory.CreateClient();
    }

    /// <summary>
    /// Extracts the one-time code from the first-run banner: the first non-empty line after the
    /// "enter the one-time setup code" marker.
    /// </summary>
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
