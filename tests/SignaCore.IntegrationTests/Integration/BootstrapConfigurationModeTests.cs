using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SignaCore.Host.Bootstrap;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

public sealed class BootstrapConfigurationModeTests : IAsyncLifetime
{
    private string _directory = string.Empty;
    private string _bootstrapPath = string.Empty;
    private string _bootstrapCode = string.Empty;
    private WebApplicationFactory<Program>? _factory;

    public ValueTask InitializeAsync()
    {
        _directory = Path.Combine(Path.GetTempPath(), $"signacore-bootstrap-mode-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_directory);
        _bootstrapPath = Path.Combine(_directory, BootstrapLoader.FileName);
        return ValueTask.CompletedTask;
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

    [Fact]
    public async Task MissingFile_StaysLiveAndGatesTheNormalSurface()
    {
        using var http = StartHost();

        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync("/health/live", TestContext.Current.CancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await http.GetAsync("/health/ready", TestContext.Current.CancellationToken)).StatusCode);

        var blocked = await http.GetAsync("/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, blocked.StatusCode);
        Assert.Equal(
            "bootstrap_configuration_required",
            (await blocked.Content.ReadFromJsonAsync<JsonElement>(
                cancellationToken: TestContext.Current.CancellationToken)).GetProperty("error").GetString());

        http.DefaultRequestHeaders.Accept.ParseAdd("text/html");
        var navigation = await http.GetAsync("/admin", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, navigation.StatusCode);
        Assert.Equal("/bootstrap", navigation.Headers.Location?.ToString());
    }

    [Fact]
    public async Task WrongCodeAndInvalidDatabase_DoNotCreateTheFile()
    {
        using var http = StartHost();
        var database = new
        {
            provider = "SQLite",
            filePath = Path.Combine(_directory, "identity.db")
        };

        var wrongCode = await http.PostAsJsonAsync("/api/bootstrap/save", new
        {
            database,
            installMode = "new",
            bootstrapCode = "wrong-code"
        }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, wrongCode.StatusCode);
        Assert.False(File.Exists(_bootstrapPath));

        var invalidDatabase = await http.PostAsJsonAsync("/api/bootstrap/save", new
        {
            database = new { provider = "SQLite", filePath = ":memory:" },
            installMode = "new",
            bootstrapCode = _bootstrapCode
        }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, invalidDatabase.StatusCode);
        Assert.False(File.Exists(_bootstrapPath));

        var operatorSelectedKey = await http.PostAsJsonAsync("/api/bootstrap/save", new
        {
            database,
            installMode = "new",
            masterKey = "an-operator-selected-key-is-not-allowed",
            bootstrapCode = _bootstrapCode
        }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, operatorSelectedKey.StatusCode);
        Assert.False(File.Exists(_bootstrapPath));
    }

    [Fact]
    public async Task ValidNewInstall_CreatesOnlyTheCanonicalInlineKeySchema()
    {
        using var http = StartHost();

        var response = await http.PostAsJsonAsync("/api/bootstrap/save", new
        {
            database = new
            {
                provider = "SQLite",
                filePath = Path.Combine(_directory, "identity.db")
            },
            installMode = "new",
            bootstrapCode = _bootstrapCode
        }, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(File.Exists(_bootstrapPath));

        using var document = JsonDocument.Parse(await File.ReadAllTextAsync(_bootstrapPath, TestContext.Current.CancellationToken));
        Assert.Equal(2, document.RootElement.EnumerateObject().Count());
        Assert.True(document.RootElement.TryGetProperty("Database", out var database));
        Assert.Equal(3, database.EnumerateObject().Count());
        Assert.False(string.IsNullOrWhiteSpace(
            document.RootElement.GetProperty("MasterKey").GetString()));
        Assert.False(document.RootElement.TryGetProperty("MasterKeyFile", out _));
        Assert.Empty(Directory.EnumerateFiles(_directory, "*.tmp"));

        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(
                UnixFileMode.UserRead | UnixFileMode.UserWrite,
                File.GetUnixFileMode(_bootstrapPath));
            Assert.Equal(
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
                File.GetUnixFileMode(_directory));
        }
    }

    private HttpClient StartHost()
    {
        var authority = BootstrapCodeAuthority.Create(out _bootstrapCode);

        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("environment", Environments.Production);
                builder.UseSetting(BootstrapLoader.FilePathConfigurationKey, _bootstrapPath);
                builder.ConfigureTestServices(services =>
                {
                    services.RemoveAll<BootstrapCodeAuthority>();
                    services.AddSingleton(authority);
                });
            });

        return _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }
}
