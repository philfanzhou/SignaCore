using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using SignaCore.Database;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Models;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Authenticated replacement of the bootstrap database target through the shared bootstrap store:
/// a confirmed change keeps the current master key, rewrites the file atomically in the canonical
/// schema, and never echoes the key or connection string. An unreachable target changes nothing.
/// </summary>
public sealed class AdminBootstrapReplacementTests : IAsyncLifetime
{
    private string _directory = string.Empty;
    private string _databasePath = string.Empty;
    private string _bootstrapPath = string.Empty;
    private WebApplicationFactory<Program>? _factory;

    public async ValueTask InitializeAsync()
    {
        _directory = Path.Combine(Path.GetTempPath(), $"signacore-bootstrap-replace-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_directory);
        _databasePath = Path.Combine(_directory, "identity.db");
        var database = new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = new SqliteConnectionStringBuilder { DataSource = _databasePath }.ConnectionString
        };

        _bootstrapPath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
            _directory,
            database,
            "replacement-root-secret-for-tests-only",
            "replacement_admin",
            "ReplacementAdmin123!");
    }

    private WebApplicationFactory<Program> StartHost() =>
        new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                // The default Development environment keeps the legacy admin cookie usable over
                // plain HTTP in tests; the bootstrap file exists, so the Development fallback never
                // engages.
                builder.UseSetting(SignaCoreBootstrapStore.FilePathConfigurationKey, _bootstrapPath);
            });

    private async Task<HttpClient> CreateAdminClientAsync(WebApplicationFactory<Program> factory)
    {
        var http = factory.CreateClient();
        var login = await http.PostAsJsonAsync("/api/admin/session/login", new
        {
            username = "replacement_admin",
            password = "ReplacementAdmin123!",
            rememberMe = false
        }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(login.IsSuccessStatusCode, $"admin login failed: {login.StatusCode}");
        return http;
    }

    [Fact]
    public async Task ConfirmedChange_KeepsTheKeyAndRewritesTheCanonicalFile()
    {
        using var factory = StartHost();
        using var admin = await CreateAdminClientAsync(factory);

        var replacementPath = Path.Combine(_directory, "replacement.db");
        var response = await admin.PutAsJsonAsync("/api/admin/bootstrap", new
        {
            database = new { provider = "SQLite", filePath = replacementPath },
            confirm = true
        }, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var responseText = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("replacement-root-secret-for-tests-only", responseText, StringComparison.Ordinal);
        Assert.DoesNotContain(replacementPath, responseText, StringComparison.Ordinal);

        // The shared store replaced the file atomically: canonical schema, the same master key, the
        // new target, and no temporary leftovers.
        using var document = JsonDocument.Parse(
            await File.ReadAllTextAsync(_bootstrapPath, TestContext.Current.CancellationToken));
        Assert.Equal(1, document.RootElement.GetProperty("FormatVersion").GetInt32());
        Assert.Equal("signacore", document.RootElement.GetProperty("ServiceId").GetString());
        Assert.Contains(replacementPath,
            document.RootElement.GetProperty("Database").GetProperty("ConnectionString").GetString(),
            StringComparison.Ordinal);
        var key = document.RootElement.GetProperty("MasterKey").GetString();
        Assert.False(string.IsNullOrWhiteSpace(key));
        // A blank submitted key means "keep the current one": the key did not rotate.
        Assert.Equal("replacement-root-secret-for-tests-only", key);
        Assert.Empty(Directory.EnumerateFiles(_directory, "*.tmp"));
    }

    [Fact]
    public async Task UnreachableTarget_ChangesNothing()
    {
        using var factory = StartHost();
        using var admin = await CreateAdminClientAsync(factory);
        var before = await File.ReadAllTextAsync(_bootstrapPath, TestContext.Current.CancellationToken);

        var response = await admin.PutAsJsonAsync("/api/admin/bootstrap", new
        {
            database = new
            {
                provider = "PostgreSQL",
                serverVersion = "15",
                connectionString = "Host=host.invalid.test;Database=x;Username=u;Password=p;Timeout=1"
            },
            confirm = true
        }, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(
            before,
            await File.ReadAllTextAsync(_bootstrapPath, TestContext.Current.CancellationToken),
            StringComparer.Ordinal);
    }

    [Fact]
    public async Task SaveIntoAnExistingFile_IsRefusedAndLeavesItUntouched()
    {
        // The shared store never overwrites an existing target with Create: the bootstrap-mode save
        // and the first-write paths surface that as the fixed WriteFailed outcome.
        var directory = Path.Combine(Path.GetTempPath(), $"signacore-bootstrap-create-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var database = new DatabaseOptions
            {
                Provider = "SQLite",
                ConnectionString = new SqliteConnectionStringBuilder
                {
                    DataSource = Path.Combine(directory, "create.db")
                }.ConnectionString
            };
            var service = new BootstrapConfigurationService(
                SignaCoreBootstrapStore.Create(new ConfigurationBuilder().AddInMemoryCollection(
                    new Dictionary<string, string?>
                    {
                        [SignaCoreBootstrapStore.FilePathConfigurationKey] =
                            Path.Combine(directory, "signacore.bootstrap.json")
                    }).Build()),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<BootstrapConfigurationService>.Instance);

            var first = await service.CreateAsync(new BootstrapSaveRequest
            {
                Database = new BootstrapDatabaseRequest
                {
                    Provider = "SQLite",
                    FilePath = Path.Combine(directory, "create.db")
                },
                InstallMode = "new"
            }, TestContext.Current.CancellationToken);
            Assert.Equal(BootstrapOutcome.Succeeded, first.Outcome);
            var written = await File.ReadAllTextAsync(
                Path.Combine(directory, "signacore.bootstrap.json"), TestContext.Current.CancellationToken);

            var second = await service.CreateAsync(new BootstrapSaveRequest
            {
                Database = new BootstrapDatabaseRequest
                {
                    Provider = "SQLite",
                    FilePath = Path.Combine(directory, "other.db")
                },
                InstallMode = "new"
            }, TestContext.Current.CancellationToken);

            Assert.Equal(BootstrapOutcome.WriteFailed, second.Outcome);
            Assert.Equal(
                written,
                await File.ReadAllTextAsync(
                    Path.Combine(directory, "signacore.bootstrap.json"), TestContext.Current.CancellationToken),
                StringComparer.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    public ValueTask DisposeAsync()
    {
        _factory?.Dispose();
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        return ValueTask.CompletedTask;
    }
}
