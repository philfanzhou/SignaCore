using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Host;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The shared management cookie across instances and restarts: two hosts over one database accept
/// the same cookie, the session survives an instance restart, and the Data Protection key ring is
/// persisted per service id in the shared table without plaintext key XML.
/// </summary>
public sealed class ManagementSessionCookieSharingTests : IAsyncLifetime
{
    private const string Root = "/management/v1";
    private const string CookieName = "__Host-ServiceMantle.Management";
    private const string AdminUsername = "sharing_admin";
    private const string AdminPassword = "SharingAdmin123!";

    private string? _databasePath;
    private string? _bootstrapDirectory;
    private string? _bootstrapFilePath;
    private readonly List<WebApplicationFactory<Program>> _factories = [];

    public async ValueTask InitializeAsync()
    {
        _bootstrapDirectory = Path.Combine(
            Path.GetTempPath(), $"signacore-sharing-{Guid.NewGuid():N}");
        _databasePath = Path.Combine(
            Path.GetTempPath(), $"signacore-sharing-{Guid.NewGuid():N}.db");
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath
        }.ConnectionString;

        _bootstrapFilePath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
            _bootstrapDirectory,
            new DatabaseOptions { Provider = "SQLite", ConnectionString = connectionString },
            IdentityServerFixture.RootSecret,
            AdminUsername,
            AdminPassword);
    }

    private WebApplicationFactory<Program> CreateInstance()
    {
        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
                builder.UseSetting("Bootstrap:FilePath", _bootstrapFilePath));
        _factories.Add(factory);
        // Materialize the host so its startup validators have run.
        factory.CreateClient();
        return factory;
    }

    private static async Task<string> LoginAsync(WebApplicationFactory<Program> factory)
    {
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{Root}/session/login")
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
        var cookie = cookieValues
            .Single(value => value.StartsWith($"{CookieName}=", StringComparison.Ordinal))
            .Split(';')[0];
        Assert.NotNull(cookie);
        return cookie;
    }

    private static async Task<HttpResponseMessage> GetCurrentSessionAsync(
        WebApplicationFactory<Program> factory,
        string cookie)
    {
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", cookie);
        return await client.GetAsync(Root + "/session", TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task TheSameCookie_IsAcceptedByBothInstancesAndSurvivesARestart()
    {
        using var first = CreateInstance();
        var cookie = await LoginAsync(first);

        // A second instance over the same database accepts the cookie issued by the first.
        using var second = CreateInstance();
        using var secondResponse = await GetCurrentSessionAsync(second, cookie);
        Assert.Equal(HttpStatusCode.OK, secondResponse.StatusCode);
        await AssertProjectionAsync(secondResponse);

        // The first instance goes away; a restarted replacement still validates the cookie because
        // the key ring lives in the shared table, not in process memory.
        first.Dispose();
        using var replacement = CreateInstance();
        using var replacementResponse = await GetCurrentSessionAsync(replacement, cookie);
        Assert.Equal(HttpStatusCode.OK, replacementResponse.StatusCode);
        await AssertProjectionAsync(replacementResponse);
    }

    [Fact]
    public async Task TheSharedKeyRing_IsStoredEncryptedUnderTheServiceId()
    {
        using var instance = CreateInstance();
        await LoginAsync(instance);

        using var scope = instance.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var rows = await db.Database.SqlQuery<string>($"""
                SELECT service_id AS Value FROM service_data_protection_keys
                """).ToListAsync(TestContext.Current.CancellationToken);
        Assert.NotEmpty(rows);
        Assert.All(rows, serviceId => Assert.Equal("signacore", serviceId));

        // The stored material is the ServiceMantle envelope, never plaintext key XML.
        var envelopes = await db.Database.SqlQuery<string>($"""
                SELECT encrypted_xml AS Value FROM service_data_protection_keys
                """).ToListAsync(TestContext.Current.CancellationToken);
        Assert.All(envelopes, envelope =>
        {
            Assert.StartsWith("sm:v1:", envelope, StringComparison.Ordinal);
            Assert.DoesNotContain("<key>", envelope, StringComparison.Ordinal);
        });
    }

    private static async Task AssertProjectionAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken));
        Assert.True(document.RootElement.GetProperty("authenticated").GetBoolean());
        Assert.Equal("management.admin",
            document.RootElement.GetProperty("permissions")[0].GetString());
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var factory in _factories)
        {
            factory.Dispose();
        }

        SqliteConnection.ClearAllPools();
        if (_databasePath != null && File.Exists(_databasePath))
        {
            File.Delete(_databasePath);
        }

        if (_bootstrapDirectory != null && Directory.Exists(_bootstrapDirectory))
        {
            Directory.Delete(_bootstrapDirectory, recursive: true);
        }

        await ValueTask.CompletedTask;
    }
}
