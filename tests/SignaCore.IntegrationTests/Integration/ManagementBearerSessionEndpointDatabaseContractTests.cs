using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using SignaCore.Database;
using SignaCore.Host.Startup;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The explicit management bearer session entries (#392) across two hosts sharing one PostgreSQL
/// database: a credential logged in on host A is used and logged out on host B, and the next
/// authentication on host A sees the revocation, because every step reads and writes the shared row.
/// </summary>
public sealed class ManagementBearerSessionEndpointDatabaseContractTests
{
    private const string RootSecret = "management-bearer-endpoint-root-secret";
    private const string AdminUsername = "bearer_endpoint_admin";
    private const string AdminPassword = "BearerEndpoint-123!";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task LoginOnA_UseAndLogoutOnB_ThenAIsUnauthenticated()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true", "Enable the PostgreSQL database contract matrix.");
        await using var container = new PostgreSqlBuilder(Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") ?? "postgres:15-alpine").Build();
        await container.StartAsync(Ct);
        var directory = Path.Combine(Path.GetTempPath(), $"signacore-bearer-endpoint-{Guid.NewGuid():N}");
        try
        {
            var database = new DatabaseOptions
            {
                Provider = "PostgreSQL",
                ServerVersion = "15",
                ConnectionString = container.GetConnectionString()
            };
            var bootstrapFilePath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
                directory, database, RootSecret, AdminUsername, AdminPassword, cancellationToken: Ct);
            using var a = CreateHost(bootstrapFilePath);
            using var b = CreateHost(bootstrapFilePath);
            using var clientA = Client(a);
            using var clientB = Client(b);

            string token;
            using (var login = new HttpRequestMessage(HttpMethod.Post, "/api/admin/session/bearer/login")
                   {
                       Content = JsonContent.Create(new { username = AdminUsername, password = AdminPassword })
                   })
            {
                login.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
                using var issued = await clientA.SendAsync(login, Ct);
                Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
                token = JsonDocument.Parse(await issued.Content.ReadAsStringAsync(Ct))
                    .RootElement.GetProperty("accessToken").GetString()!;
            }

            using (var used = await clientB.SendAsync(Me(token), Ct))
            {
                Assert.Equal(HttpStatusCode.OK, used.StatusCode);
            }

            using (var logout = new HttpRequestMessage(HttpMethod.Post, "/api/admin/session/bearer/logout"))
            {
                logout.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                logout.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
                using var revoked = await clientB.SendAsync(logout, Ct);
                Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);
            }

            using var after = await clientA.SendAsync(Me(token), Ct);
            Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
            Assert.Equal("no-store", after.Headers.CacheControl?.ToString());
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    private static WebApplicationFactory<Program> CreateHost(string bootstrapFilePath)
    {
        var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath);
            builder.UseSetting("Endpoints:Http", "0");
        });
        factory.CreateClient().Dispose();
        return factory;
    }

    private static HttpClient Client(WebApplicationFactory<Program> host) =>
        host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = false
        });

    private static HttpRequestMessage Me(string token) =>
        new(HttpMethod.Get, "/api/admin/session/me")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", token) }
        };
}
