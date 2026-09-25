using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Host;
using SignaCore.Host.Management;
using SignaCore.Host.Startup;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The management bearer scheme across two hosts sharing one PostgreSQL database (#384): a
/// credential issued by one replica authenticates on the other, and a revocation on one replica is
/// seen by the next authentication on the other, because every validation reads the shared row.
/// </summary>
public sealed class ManagementBearerAuthenticationDatabaseContractTests
{
    private const string RootSecret = "management-bearer-scheme-root-secret";
    private const string AdminUsername = "bearer_scheme_admin";
    private const string AdminPassword = "BearerScheme-123!";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ACredentialIssuedOnOneHost_AuthenticatesOnTheOther_UntilItIsRevoked()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true", "Enable the PostgreSQL database contract matrix.");
        await using var container = new PostgreSqlBuilder(Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") ?? "postgres:15-alpine").Build();
        await container.StartAsync(Ct);
        var directory = Path.Combine(Path.GetTempPath(), $"signacore-bearer-scheme-{Guid.NewGuid():N}");
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
            using var clientB = b.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                HandleCookies = false
            });

            var adminId = await AdminAccountIdAsync(a);
            var issued = await a.Services.GetRequiredService<ManagementBearerSessionService>().IssueAsync(adminId, Ct);
            Assert.Equal(ManagementBearerIssueStatus.Issued, issued.Status);

            using (var before = await clientB.SendAsync(Me(issued.Token!), Ct))
            {
                Assert.Equal(HttpStatusCode.OK, before.StatusCode);
                Assert.Contains(adminId.ToString(), await before.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
            }

            Assert.Equal(
                ManagementBearerRevocationResult.Revoked,
                await a.Services.GetRequiredService<ManagementBearerSessionService>().RevokeAsync(issued.Token, Ct));

            using var after = await clientB.SendAsync(Me(issued.Token!), Ct);
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

    private static async Task<Guid> AdminAccountIdAsync(WebApplicationFactory<Program> host)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        return (await db.PasswordCredentials.AsNoTracking().SingleAsync(row => row.Username == AdminUsername, Ct)).AccountId;
    }

    private static HttpRequestMessage Me(string token) =>
        new(HttpMethod.Get, "/api/admin/session/me")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", token) }
        };
}
