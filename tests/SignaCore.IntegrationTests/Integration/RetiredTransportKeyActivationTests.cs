using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The activation semantics after ADR 0008 retired the hosted-login HTTP test-origin allowlist and
/// the non-HTTPS issuer opt-in: plain-HTTP public base URLs start in every environment with zero
/// configuration, leftover rows of the retired keys never block startup or management, and updates
/// naming a retired key keep the generic unknown-key rejection.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class RetiredTransportKeyActivationTests : IAsyncLifetime
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private readonly string _directory = Path.Combine(PhysicalTempPath.Root(), "retired-transport-" + Guid.NewGuid().ToString("N"));
    private readonly List<WebApplicationFactory<Program>> _hosts = [];
    private const string Admin = "policy_admin";
    private const string Password = "PolicyTests-123!";

    public ValueTask InitializeAsync() { Directory.CreateDirectory(_directory); return ValueTask.CompletedTask; }
    public async ValueTask DisposeAsync()
    {
        foreach (var host in _hosts) await host.DisposeAsync();
        SqliteConnection.ClearAllPools();
        Directory.Delete(_directory, recursive: true);
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Staging")]
    [InlineData("Production")]
    [InlineData("Testing")]
    public async Task PlainHttpPublicBaseUrl_StartsInEveryEnvironment_WithZeroExtraConfiguration(string environment)
    {
        var bootstrap = await PrepareAsync("http://accounts.example.test");
        var host = Host(bootstrap, environment);
        using var client = host.CreateClient();

        // The activated snapshot carries the http base URL as-is; discovery advertises the same
        // issuer, and the structural redirect-URI policy accepts http registrations in this
        // environment with no allowlist and no opt-in.
        using var discovery = await client.GetAsync("/.well-known/openid-configuration", Ct);
        Assert.Equal(HttpStatusCode.OK, discovery.StatusCode);
        var document = await discovery.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: Ct);
        Assert.Equal("http://accounts.example.test",
            document.GetProperty("issuer").GetString());
        Assert.True(host.Services.GetRequiredService<SignaCore.Domain.Validators.OidcRedirectUriPolicy>()
            .Allows("http://10.20.30.40:5002/callback"));
    }

    [Fact]
    public async Task RetiredKeyRows_NeverBlockStartupQueriesOrUpdates()
    {
        // An older release stored both retired rows. They survive the upgrade (dropping them is
        // the operator's optional cleanup), so every read must ignore them.
        var bootstrap = await PrepareAsync("https://accounts.example.test");
        var host = Host(bootstrap, "Production");
        using var client = host.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        await LoginAsync(client);
        var values = await StoredValuesAsync(host);
        values[RetiredSettingKeys.HostedLoginHttpTestOrigins] = "[\"http://10.20.30.40:5002\"]";
        values[RetiredSettingKeys.SecurityAllowNonHttpsIssuer] = "true";
        await WriteStoredValuesAsync(host, values);
        await host.DisposeAsync();

        var restarted = Host(bootstrap, "Production");
        using var nextClient = restarted.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        await LoginAsync(nextClient);
        using (var read = await nextClient.GetAsync("/management/v1/settings", Ct))
        {
            Assert.Equal(HttpStatusCode.OK, read.StatusCode);
            var body = await read.Content.ReadAsStringAsync(Ct);
            Assert.DoesNotContain(RetiredSettingKeys.HostedLoginHttpTestOrigins, body, StringComparison.Ordinal);
            Assert.DoesNotContain(RetiredSettingKeys.SecurityAllowNonHttpsIssuer, body, StringComparison.Ordinal);
        }

        var version = await VersionAsync(nextClient);
        foreach (var key in new[] { RetiredSettingKeys.HostedLoginHttpTestOrigins, RetiredSettingKeys.SecurityAllowNonHttpsIssuer })
        {
            using var rejected = await UpdateAsync(nextClient, version, key, "true");
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        }

        using var unrelated = await UpdateAsync(nextClient, version, "jwt.audience", "retired-key-audience");
        Assert.Equal(HttpStatusCode.OK, unrelated.StatusCode);
        var after = await StoredValuesAsync(restarted);
        Assert.Equal("[\"http://10.20.30.40:5002\"]", after[RetiredSettingKeys.HostedLoginHttpTestOrigins]);
        Assert.Equal("retired-key-audience", after["jwt.audience"]);
    }

    private async Task<Dictionary<string, string>> StoredValuesAsync(WebApplicationFactory<Program> host)
    {
        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(db, Ct);
        return SharedSettingTestDatabase.ParseValues(aggregate!);
    }

    private async Task WriteStoredValuesAsync(WebApplicationFactory<Program> host, Dictionary<string, string> values)
    {
        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        await db.Database.ExecuteSqlAsync(
            $"UPDATE service_settings SET values_json = {JsonSerializer.Serialize(values)} WHERE service_id = 'signacore'",
            Ct);
    }

    private async Task<string> PrepareAsync(string url)
    {
        var directory = Path.Combine(_directory, Guid.NewGuid().ToString("N"));
        return await InstallationTestSupport.PrepareCompletedInstallationAsync(directory,
            new DatabaseOptions { Provider = "SQLite", ConnectionString = "Data Source=" + directory + "/identity.db" },
            "policy-activation-synthetic-root", Admin, Password,
            new Dictionary<string, string>
            {
                [SystemSettingKeys.PublicBaseUrl] = url, [SystemSettingKeys.JwtIssuer] = url
            }, Ct);
    }

    private WebApplicationFactory<Program> Host(string bootstrap, string environment)
    {
        var host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Bootstrap:FilePath", bootstrap);
            builder.UseSetting("Endpoints:Http", "0");
            builder.UseEnvironment(environment);
        });
        _hosts.Add(host);
        return host;
    }

    private static async Task LoginAsync(HttpClient client)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
        { Content = JsonContent.Create(new { username = Admin, password = Password }) };
        request.Headers.Add("X-ServiceMantle-Request", "1");
        using var response = await client.SendAsync(request, Ct);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    private static Task<HttpResponseMessage> UpdateAsync(HttpClient client, long version, string key, string value) =>
        client.PostAsJsonAsync("/management/v1/settings", new
        { expectedVersion = version, changes = new[] { new { key, value } } }, Ct);

    private static async Task<long> VersionAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/management/v1/settings", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: Ct)).GetProperty("version").GetInt64();
    }
}
