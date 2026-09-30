using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle.Web.Health;
using ServiceMantle.Web.Http;
using ServiceMantle.Health;
using ServiceMantle.Installation;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>Exercises the product trust projection and the actual shared pipeline insertion.</summary>
public sealed class ForwardedHeadersCompositionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("::1", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.42.10.20", true)]
    [InlineData("10.20.30.40", true)]
    [InlineData("10.20.30.41", false)]
    [InlineData("172.19.0.1", false)]
    public async Task OnlyDeclaredAndOriginalLoopbackPeers_CanChangeClientIpAndScheme(string peer, bool trusted)
    {
        await using var app = await StartAsync(["10.20.30.40", "::1", "0:0:0:0:0:0:0:1", "10.20.30.40"]);
        using var client = app.GetTestClient();
        using var request = Request(peer, "198.51.100.8", "https");
        using var response = await client.SendAsync(request, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var answer = (await response.Content.ReadFromJsonAsync<Observation>(Ct))!;
        Assert.Equal(trusted ? "198.51.100.8" : peer, answer.RemoteIp);
        Assert.Equal(trusted ? "https" : "http", answer.Scheme);
        Assert.Equal("localhost", answer.Host);
    }

    [Theory]
    [InlineData("198.51.100.8, 198.51.100.9", "https")]
    [InlineData("198.51.100.8", "https, http")]
    [InlineData("not-an-address", "https")]
    [InlineData("198.51.100.8", "not a scheme")]
    public async Task AsymmetricOrMalformedHeaders_AreNotApplied(string forwardedFor, string proto)
    {
        await using var app = await StartAsync([]);
        using var client = app.GetTestClient();
        using var request = Request("127.0.0.1", forwardedFor, proto);
        using var response = await client.SendAsync(request, Ct);
        var answer = (await response.Content.ReadFromJsonAsync<Observation>(Ct))!;
        Assert.Equal("127.0.0.1", answer.RemoteIp);
        Assert.Equal("http", answer.Scheme);
    }

    [Fact]
    public async Task AChainIsProcessedOnce_FromTheRight_WithAOneHopLimit()
    {
        await using var app = await StartAsync([]);
        using var client = app.GetTestClient();
        using var request = Request("127.0.0.1", "198.51.100.8, 127.0.0.2", "http, https");
        using var response = await client.SendAsync(request, Ct);
        var answer = (await response.Content.ReadFromJsonAsync<Observation>(Ct))!;
        Assert.Equal("127.0.0.2", answer.RemoteIp);
        Assert.Equal("https", answer.Scheme);
        Assert.Equal("198.51.100.8", answer.RemainingFor);
    }

    [Fact]
    public async Task AnExplicitContainerIngress_IsTrusted_AndDifferentHostsDoNotShareTrust()
    {
        await using var trusted = await StartAsync(["172.19.0.1"]);
        await using var untrusted = await StartAsync([]);
        foreach (var (app, scheme) in new[] { (trusted, "https"), (untrusted, "http") })
        {
            using var client = app.GetTestClient();
            using var request = Request("172.19.0.1", "198.51.100.8", "https");
            using var response = await client.SendAsync(request, Ct);
            Assert.Equal(scheme, (await response.Content.ReadFromJsonAsync<Observation>(Ct))!.Scheme);
        }
    }

    [Fact]
    public async Task InvalidProxy_FailsWithASafeFixedDiagnostic()
    {
        const string canary = "synthetic-private-proxy-canary";
        var error = await Assert.ThrowsAsync<ForwardedHeadersConfigurationException>(() => StartAsync([canary]));
        Assert.Equal("forwarded_headers.invalid_value", error.ErrorCode);
        Assert.Equal("KnownProxies", error.FieldName);
        Assert.DoesNotContain(canary, error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(canary, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CallerCancellation_IsNotReplacedByForwarding()
    {
        await using var app = await StartAsync([]);
        using var client = app.GetTestClient();
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        cancel.Cancel();
        using var request = Request("127.0.0.1", "198.51.100.8", "https");
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.SendAsync(request, cancel.Token));
    }

    private static HttpRequestMessage Request(string peer, string forwardedFor, string proto)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/observe");
        request.Headers.Add("X-Test-Peer", peer);
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", forwardedFor);
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", proto);
        request.Headers.Add("X-Forwarded-Host", "attacker.example.test");
        return request;
    }

    private static async Task<WebApplication> StartAsync(string[] proxies)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSignaCoreServiceMantle()
            .AddManagementCookieAuthentication().AddServiceMantleManagementApiV1()
            .AddSensitiveHeaders().AddSecurityResponseHeaders().AddRateLimiting().AddSignaCoreForwardedHeaders(proxies);
        builder.Services.AddSingleton<IServiceHealthSnapshotSource, CompletedSnapshot>();
        var app = builder.Build();
        app.Use((context, next) =>
        {
            context.Connection.RemoteIpAddress = IPAddress.Parse(context.Request.Headers["X-Test-Peer"].ToString());
            return next(context);
        });
        app.UseServiceMantlePipeline();
        app.MapGet("/observe", (HttpContext http) => new Observation(http.Connection.RemoteIpAddress!.ToString(), http.Request.Scheme,
            http.Request.Host.Host, http.Request.Headers["X-Forwarded-For"].ToString()))
            .WithServiceMantlePhaseAdmission(ServiceStartupPhase.Completed);
        try { await app.StartAsync(Ct); return app; }
        catch { await app.DisposeAsync(); throw; }
    }

    private sealed record Observation(string RemoteIp, string Scheme, string Host, string RemainingFor);
    private sealed class CompletedSnapshot : IServiceHealthSnapshotSource
    {
        public ValueTask<ServiceHealthSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new ServiceHealthSnapshot(ServiceStartupPhase.Completed, ServiceMigrationReadinessState.Succeeded, ServiceDatabaseReadinessState.Reachable));
    }
}
