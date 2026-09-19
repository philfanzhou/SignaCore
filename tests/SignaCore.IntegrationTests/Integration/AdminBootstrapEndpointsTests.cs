using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using SignaCore.Database;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The retained SignaCore-owned bootstrap surface of the installed host: the authenticated
/// overview <c>GET /api/admin/bootstrap</c> and the target probe
/// <c>POST /api/admin/bootstrap/test</c>. Both carry the fixed management session and the shared
/// unsafe-request guard where required, and neither writes anything.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class AdminBootstrapEndpointsTests : IAsyncLifetime
{
    private const string OverviewPath = "/api/admin/bootstrap";
    private const string TestPath = "/api/admin/bootstrap/test";
    private const string UnsafeRequestHeader = "X-ServiceMantle-Request";
    private const string RootSecret = "endpoints-root-secret-for-tests-only";

    private string _directory = string.Empty;
    private string _bootstrapPath = string.Empty;
    private string _databasePath = string.Empty;
    private string _databaseConnectionString = string.Empty;

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    public async ValueTask InitializeAsync()
    {
        _directory = Path.Combine(Path.GetTempPath(), $"signacore-bootstrap-endpoints-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_directory);
        _databasePath = Path.Combine(_directory, "identity.db");
        _databaseConnectionString =
            new SqliteConnectionStringBuilder { DataSource = _databasePath }.ConnectionString;
        _bootstrapPath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
            _directory,
            new DatabaseOptions
            {
                Provider = "SQLite",
                ConnectionString = _databaseConnectionString
            },
            RootSecret,
            "endpoints_admin",
            "EndpointsAdmin123!");
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

    private WebApplicationFactory<Program> StartHost() =>
        new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
                builder.UseSetting(SignaCoreBootstrapStore.FilePathConfigurationKey, _bootstrapPath));

    private static async Task<HttpClient> CreateAdminClientAsync(WebApplicationFactory<Program> factory)
    {
        var http = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
        using var login = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
        {
            Content = JsonContent.Create(new { username = "endpoints_admin", password = "EndpointsAdmin123!" })
        };
        login.Headers.TryAddWithoutValidation(UnsafeRequestHeader, "1");
        var loginResponse = await http.SendAsync(login, Token);
        Assert.True(loginResponse.IsSuccessStatusCode, $"admin login failed: {loginResponse.StatusCode}");
        return http;
    }

    private static HttpRequestMessage TestRequest(string json, bool withUnsafeHeader = true)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, TestPath)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        if (withUnsafeHeader)
        {
            request.Headers.TryAddWithoutValidation(UnsafeRequestHeader, "1");
        }

        return request;
    }

    [Fact]
    public async Task Overview_ReturnsTheSafeProjectionWithoutTheProviderCatalog()
    {
        using var factory = StartHost();
        using var admin = await CreateAdminClientAsync(factory);

        using var response = await admin.GetAsync(OverviewPath, Token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Token));
        var root = document.RootElement;
        Assert.Equal("SQLite", root.GetProperty("provider").GetString());
        Assert.Equal(_bootstrapPath, root.GetProperty("filePath").GetString());
        Assert.True(root.GetProperty("masterKeyConfigured").GetBoolean());
        Assert.True(root.GetProperty("editable").GetBoolean());
        Assert.NotEmpty(root.GetProperty("scopeNotice").GetString()!);
        // The provider catalog left with the deleted controller, and no key or connection string
        // is ever part of the overview.
        Assert.Throws<KeyNotFoundException>(() => root.GetProperty("supportedProviders"));
        var text = root.GetRawText();
        Assert.DoesNotContain(RootSecret, text, StringComparison.Ordinal);
        Assert.DoesNotContain(_databaseConnectionString, text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Overview_WithoutTheManagementCookie_Is401()
    {
        using var factory = StartHost();
        using var anonymous = factory.CreateClient();

        using var response = await anonymous.GetAsync(OverviewPath, Token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Test_ClassifiesAMissingTargetWithoutCreatingItOrTouchingTheFile()
    {
        using var factory = StartHost();
        using var admin = await CreateAdminClientAsync(factory);
        var before = await File.ReadAllTextAsync(_bootstrapPath, Token);
        var missingPath = Path.Combine(_directory, "missing-target.db");

        var payload = JsonSerializer.Serialize(new
        {
            database = new { provider = "SQLite", filePath = missingPath }
        });
        using var response = await admin.SendAsync(TestRequest(payload), Token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Token));
        var root = document.RootElement;
        Assert.Equal("empty", root.GetProperty("target").GetString());
        Assert.True(root.GetProperty("canConnect").GetBoolean());
        Assert.False(root.GetProperty("hasProtectedData").GetBoolean());
        // A probe never creates the target and never changes the file.
        Assert.False(File.Exists(missingPath));
        Assert.Equal(before, await File.ReadAllTextAsync(_bootstrapPath, Token), StringComparer.Ordinal);
    }

    [Fact]
    public async Task Test_WithoutTheUnsafeRequestHeader_IsRejectedBeforeTheTargetIsOpened()
    {
        using var factory = StartHost();
        using var admin = await CreateAdminClientAsync(factory);

        using var response = await admin.SendAsync(
            TestRequest("""{"database":{"provider":"SQLite","filePath":"never-opened.db"}}""",
                withUnsafeHeader: false),
            Token);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(Token);
        Assert.Contains("management.request.invalid", body, StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(_directory, "never-opened.db")));
    }

    [Fact]
    public async Task Test_WithoutTheManagementCookie_Is401()
    {
        using var factory = StartHost();
        using var anonymous = factory.CreateClient();

        using var response = await anonymous.SendAsync(
            TestRequest("""{"database":{"provider":"SQLite","filePath":"no.db"}}"""),
            Token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Test_WithTheRunningKeyImplicitlyBlank_ReportsKeyCompatibility()
    {
        using var factory = StartHost();
        using var admin = await CreateAdminClientAsync(factory);

        // A blank key keeps the running one: the running database is a completed installation the
        // running key can read, so the compatibility projection says compatible.
        var payload = JsonSerializer.Serialize(new
        {
            database = new { provider = "SQLite", filePath = _databasePath }
        });
        using var response = await admin.SendAsync(TestRequest(payload), Token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Token));
        Assert.Equal("completed_installation", document.RootElement.GetProperty("target").GetString());
        Assert.Equal("compatible", document.RootElement.GetProperty("masterKey").GetString());
    }
}
