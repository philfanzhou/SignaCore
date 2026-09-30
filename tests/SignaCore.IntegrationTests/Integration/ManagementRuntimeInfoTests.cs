using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ServiceMantle.AspNetCore.Health;
using ServiceMantle.AspNetCore.Management;
using ServiceMantle.Health;
using ServiceMantle.Installation;
using ServiceMantle.Management;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Integration;

[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class ManagementRuntimeInfoTests(IdentityServerFixture fixture) : IClassFixture<IdentityServerFixture>
{
    private const string Path = "/management/v1/runtime";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuthorizedCookieAndBearer_ProjectOnlyFourFixedFields_WithOnePhaseObservation(bool bearer)
    {
        var source = new SnapshotSource();
        using var host = Host(source);
        using var client = Client(host);
        await AuthorizeAsync(client, bearer);
        source.Reset();
        using var response = await client.GetAsync(Path, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        AssertSecurityHeaders(response);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
        Assert.Equal(new[] { "serviceName", "serviceVersion", "instanceId", "phase" },
            body.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal("signacore", body.RootElement.GetProperty("serviceName").GetString());
        Assert.False(string.IsNullOrWhiteSpace(body.RootElement.GetProperty("serviceVersion").GetString()));
        Assert.StartsWith("signacore-", body.RootElement.GetProperty("instanceId").GetString());
        Assert.Equal("Completed", body.RootElement.GetProperty("phase").GetString());
        Assert.Equal(1, source.Calls);
    }

    [Theory]
    [InlineData("anonymous", 401, "management.session.unauthenticated")]
    [InlineData("invalid-cookie", 401, "management.session.expired")]
    [InlineData("invalid-bearer", 401, "management.bearer.unauthenticated")]
    [InlineData("non-admin", 403, "management.session.forbidden")]
    public async Task AuthenticationAndAuthorization_KeepFixedRejections(string credential, int status, string error)
    {
        using var host = Host(new SnapshotSource());
        using var client = Client(host);
        if (credential == "invalid-cookie") client.DefaultRequestHeaders.Add("Cookie", ManagementSessionDefaults.CookieName + "=invalid");
        if (credential == "invalid-bearer") client.DefaultRequestHeaders.Authorization = new("Bearer", "invalid");
        if (credential == "non-admin")
        {
            await AuthorizeAsync(client, false);
            var options = host.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(ManagementSessionDefaults.AuthenticationScheme);
            var cookie = client.DefaultRequestHeaders.GetValues("Cookie").Single().Split('=', 2)[1];
            var ticket = options.TicketDataFormat.Unprotect(cookie)!;
            var principal = new ClaimsPrincipal(new ClaimsIdentity(ticket.Principal.Claims.Where(c => c.Type != ManagementClaimTypes.Permission), ManagementSessionDefaults.AuthenticationScheme));
            client.DefaultRequestHeaders.Remove("Cookie");
            client.DefaultRequestHeaders.Add("Cookie", ManagementSessionDefaults.CookieName + "=" + options.TicketDataFormat.Protect(new AuthenticationTicket(principal, ticket.Properties, ticket.AuthenticationScheme)));
        }
        using var response = await client.GetAsync(Path, Ct);
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal("{\"errorCode\":\"" + error + "\"}", await response.Content.ReadAsStringAsync(Ct));
        AssertSecurityHeaders(response);
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("HEAD")]
    public async Task OtherMethods_ArePhaseRejected(string method)
    {
        using var host = Host(new SnapshotSource());
        using var client = Client(host);
        await AuthorizeAsync(client, false);
        using var request = new HttpRequestMessage(new HttpMethod(method), Path);
        using var response = await client.SendAsync(request, Ct);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        if (method != "HEAD") Assert.Equal("""{"errorCode":"service.phase.unavailable"}""", await response.Content.ReadAsStringAsync(Ct));
    }

    [Theory]
    [InlineData("pending")]
    [InlineData("failed")]
    [InlineData("unreachable")]
    [InlineData("throws")]
    public async Task LostAuthorityOrFailedObservation_CannotPublishNormalIdentity(string fault)
    {
        var source = new SnapshotSource();
        using var host = Host(source);
        using var client = Client(host);
        await AuthorizeAsync(client, false);
        source.Fault = fault;
        source.Reset();
        using var response = await client.GetAsync(Path, Ct);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("""{"errorCode":"service.phase.unavailable"}""", await response.Content.ReadAsStringAsync(Ct));
        Assert.Equal(1, source.Calls);
    }

    [Fact]
    public async Task TwoHostsAndConcurrentRequests_KeepIndependentFixedIdentities()
    {
        using var first = Host(new SnapshotSource());
        using var second = Host(new SnapshotSource());
        using var a = Client(first);
        using var b = Client(second);
        await AuthorizeAsync(a, false);
        await AuthorizeAsync(b, false);
        async Task<string> Instance(HttpClient client)
        {
            using var response = await client.GetAsync(Path, Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
            return json.RootElement.GetProperty("instanceId").GetString()!;
        }
        var identities = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Instance(a)));
        Assert.Single(identities.Distinct());
        Assert.NotEqual(identities[0], await Instance(b));
    }

    [Fact]
    public async Task CallerCancellation_ReachesTheObservation_AndDoesNotPublishIdentity()
    {
        var source = new SnapshotSource();
        using var host = Host(source);
        using var client = Client(host);
        await AuthorizeAsync(client, false);
        source.Fault = "wait";
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var request = client.GetAsync(Path, cancellation.Token);
        await source.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);
        await source.Cancelled.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);
    }

    [Fact]
    public async Task ExhaustedBudget_KeepsTheHostRateLimitRejection()
    {
        using var host = Host(new SnapshotSource());
        using var client = Client(host);
        await AuthorizeAsync(client, false);
        HttpResponseMessage? rejected = null;
        for (var i = 0; i < 130; i++)
        {
            var response = await client.GetAsync(Path, Ct);
            if (response.StatusCode == HttpStatusCode.TooManyRequests) { rejected = response; break; }
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            response.Dispose();
        }
        using (rejected)
        {
            Assert.NotNull(rejected);
            Assert.Equal("""{"status":429,"title":"Too Many Requests","detail":"Rate limit exceeded. Please try again later."}""", await rejected.Content.ReadAsStringAsync(Ct));
            AssertSecurityHeaders(rejected);
        }
    }

    private WebApplicationFactory<Program> Host(SnapshotSource source) => fixture.WithTestServices(services =>
    {
        services.RemoveAll<IServiceHealthSnapshotSource>();
        services.AddSingleton<IServiceHealthSnapshotSource>(source);
    });

    private static HttpClient Client(WebApplicationFactory<Program> host) => host.CreateClient(new() { HandleCookies = false, AllowAutoRedirect = false });
    private static async Task AuthorizeAsync(HttpClient client, bool bearer)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, bearer ? "/api/admin/session/bearer/login" : "/management/v1/session/login")
        {
            Content = JsonContent.Create(new { username = IdentityServerFixture.AdminUsername, password = IdentityServerFixture.AdminPassword })
        };
        request.Headers.Add("X-ServiceMantle-Request", "1");
        using var response = await client.SendAsync(request, Ct);
        Assert.Equal(bearer ? HttpStatusCode.OK : HttpStatusCode.NoContent, response.StatusCode);
        if (bearer)
        {
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", json.RootElement.GetProperty("accessToken").GetString());
        }
        else client.DefaultRequestHeaders.Add("Cookie", response.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith(ManagementSessionDefaults.CookieName + "=", StringComparison.Ordinal)).Split(';')[0]);
    }

    private static void AssertSecurityHeaders(HttpResponseMessage response)
    {
        foreach (var (name, value) in new[] { ("Cache-Control", "no-store"), ("Pragma", "no-cache"), ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer"), ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'") })
            Assert.Equal(value, response.Headers.GetValues(name).Single());
        Assert.Single(response.Headers.GetValues("x-correlation-id"));
    }

    private sealed class SnapshotSource : IServiceHealthSnapshotSource
    {
        private int _calls;
        public int Calls => Volatile.Read(ref _calls);
        public string? Fault { get; set; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Cancelled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void Reset() => Interlocked.Exchange(ref _calls, 0);
        public async ValueTask<ServiceHealthSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref _calls);
            if (Fault == "throws") throw new InvalidOperationException("synthetic-private-canary");
            if (Fault == "wait")
            {
                Entered.TrySetResult();
                try { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); }
                catch (OperationCanceledException) { Cancelled.TrySetResult(); throw; }
            }
            return new(Fault == "pending" ? ServiceStartupPhase.PendingSetup : ServiceStartupPhase.Completed,
                Fault == "failed" ? ServiceMigrationReadinessState.Failed : ServiceMigrationReadinessState.Succeeded,
                Fault == "unreachable" ? ServiceDatabaseReadinessState.Unreachable : ServiceDatabaseReadinessState.Reachable);
        }
    }
}
