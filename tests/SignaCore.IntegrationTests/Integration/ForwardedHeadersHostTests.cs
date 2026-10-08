using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class ForwardedHeadersHostTests : IAsyncLifetime
{
    private readonly string _directory = System.IO.Path.Combine(PhysicalTempPath.Root(), "signacore-proxy-" + Guid.NewGuid().ToString("N"));
    private WebApplicationFactory<Program>? _host;
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    public ValueTask InitializeAsync() { Directory.CreateDirectory(_directory); return ValueTask.CompletedTask; }
    public async ValueTask DisposeAsync()
    {
        if (_host is not null) await _host.DisposeAsync();
        try { Directory.Delete(_directory, true); } catch (IOException) { }
    }

    [Theory]
    [InlineData("10.20.30.40", true)]
    [InlineData("10.20.30.41", false)]
    public async Task ActivatedSnapshot_DrivesTheActualHost_DiscoveryAndManagementCookie(string peer, bool trusted)
    {
        using var client = await StartAsync();
        using var request = Request("/.well-known/openid-configuration", peer, "198.51.100.8");
        using var response = await client.SendAsync(request, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(trusted ? "198.51.100.8" : peer, response.Headers.GetValues("X-Test-Remote").Single());
        Assert.Equal(trusted ? "https" : "http", response.Headers.GetValues("X-Test-Scheme").Single());
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
        Assert.DoesNotContain("attacker.example.test", json.RootElement.GetProperty("issuer").GetString(), StringComparison.Ordinal);

        using var login = Request("/management/v1/session/login", peer, "198.51.100.8");
        login.Method = HttpMethod.Post;
        login.Headers.Add("X-ServiceMantle-Request", "1");
        login.Content = JsonContent.Create(new { username = "proxy_test_admin", password = "ProxyTest123!" });
        using var loggedIn = await client.SendAsync(login, Ct);
        Assert.Equal(HttpStatusCode.NoContent, loggedIn.StatusCode);
        var cookie = loggedIn.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("ServiceMantle.Management=", StringComparison.Ordinal));
        // Since ServiceMantle.Web 0.3.2 the management cookie's Secure attribute follows the
        // request scheme: the trusted proxy's forwarded https scheme keeps it Secure, and an
        // untrusted peer's plain-http request drops it.
        if (trusted)
        {
            Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);
        }
        else
        {
            Assert.DoesNotContain("secure", cookie, StringComparison.OrdinalIgnoreCase);
        }
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", cookie, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("10.20.30.40", true)]
    [InlineData("10.20.30.41", false)]
    public async Task IpBudget_UsesTrustedClientIp_AndIgnoresUntrustedForwardedIp(string peer, bool trusted)
    {
        using var client = await StartAsync();
        for (var i = 0; i < 100; i++)
        {
            using var request = Request("/.well-known/openid-configuration", peer, "198.51.100.8");
            using var response = await client.SendAsync(request, Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
        using var exhaustedRequest = Request("/.well-known/openid-configuration", peer, "198.51.100.8");
        using var exhausted = await client.SendAsync(exhaustedRequest, Ct);
        Assert.Equal(HttpStatusCode.TooManyRequests, exhausted.StatusCode);
        using var changedRequest = Request("/.well-known/openid-configuration", peer, "198.51.100.9");
        using var changed = await client.SendAsync(changedRequest, Ct);
        Assert.Equal(trusted ? HttpStatusCode.OK : HttpStatusCode.TooManyRequests, changed.StatusCode);
    }

    private async Task<HttpClient> StartAsync()
    {
        var bootstrap = await InstallationTestSupport.PrepareCompletedInstallationAsync(
            System.IO.Path.Combine(_directory, "config"),
            new DatabaseOptions { Provider = "SQLite", ConnectionString = "Data Source=" + System.IO.Path.Combine(_directory, "identity.db") },
            "proxy-tests-synthetic-root", "proxy_test_admin", "ProxyTest123!",
            new Dictionary<string, string> { [SystemSettingKeys.ReverseProxyKnownProxies] = JsonSerializer.Serialize(new[] { "10.20.30.40", "::1", "10.20.30.40" }) }, Ct);
        _host = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Bootstrap:FilePath", bootstrap);
            builder.UseSetting("Endpoints:Http", "0");
            // A launcher override cannot replace the activated database proxy setting.
            builder.UseSetting("ReverseProxy:KnownProxies:0", "10.20.30.41");
            builder.ConfigureTestServices(services => services.AddSingleton<IStartupFilter, PeerFilter>());
        });
        return _host.CreateClient(new() { HandleCookies = false, AllowAutoRedirect = false });
    }

    private static HttpRequestMessage Request(string path, string peer, string clientIp)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add("X-Test-Peer", peer);
        request.Headers.Add("X-Forwarded-For", clientIp);
        request.Headers.Add("X-Forwarded-Proto", "https");
        request.Headers.Add("X-Forwarded-Host", "attacker.example.test");
        return request;
    }

    private sealed class PeerFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, continuation) =>
            {
                context.Connection.RemoteIpAddress = IPAddress.Parse(context.Request.Headers["X-Test-Peer"].ToString());
                context.Response.OnStarting(() =>
                {
                    context.Response.Headers["X-Test-Remote"] = context.Connection.RemoteIpAddress!.ToString();
                    context.Response.Headers["X-Test-Scheme"] = context.Request.Scheme;
                    return Task.CompletedTask;
                });
                return continuation(context);
            });
            next(app);
        };
    }
}
