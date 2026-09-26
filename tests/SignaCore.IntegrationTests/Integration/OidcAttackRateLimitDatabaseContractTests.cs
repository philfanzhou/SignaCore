using System.Collections;
using System.Reflection;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SignaCore.Database.RateLimiting;
using SignaCore.Host.Security;
using Xunit;
using static SignaCore.Tests.Integration.OidcDatabaseTestSupport;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>R1–R7 and the disconnected-store/disabled-policy controls of AC-13 (#108).</summary>
public sealed class OidcAttackRateLimitDatabaseContractTests
{
    public static TheoryData<string, string> Partitions => new()
    {
        { "login", "ip" }, { "authorize", "ip" }, { "authorize", "client" },
        { "token", "ip" }, { "token", "client" }, { "revoke", "ip" }, { "revoke", "client" },
        { "userinfo", "ip" }, { "logout", "ip" }
    };

    [Theory]
    [MemberData(nameof(Partitions))]
    public Task AlternatingAttack_UsesExactlyOneSharedBudget(string endpoint, string partition) =>
        RunAttackAsync(endpoint, partition, "shared");

    public static IEnumerable<object[]> NegativeVariants =>
        from row in Partitions
        from variant in new[] { "local", "disabled" }
        select new object[] { row.Data.Item1, row.Data.Item2, variant };

    [Theory]
    [MemberData(nameof(NegativeVariants))]
    public async Task DisconnectedProtection_FailsTheSameBudgetAssertion(string endpoint, string partition, string variant)
    {
        // Setup and admitted-response assertions execute outside Record.Exception. Only the
        // exact shared rejection assertion can satisfy this negative control.
        await RunAttackAsync(endpoint, partition, variant);
    }

    private static async Task RunAttackAsync(string endpoint, string partition, string variant)
    {
        await using var harness = await Harness.CreateAsync();
        void Configure(IServiceCollection services)
        {
            if (variant == "local")
                services.Replace(ServiceDescriptor.Singleton<IOidcRateLimitStore>(new PerInstanceBudgetStore()));
            if (variant == "disabled")
                services.PostConfigure<RateLimiterOptions>(options =>
                {
                    // ASP.NET Core 10 exposes AddPolicy but no replacement API. Remove only
                    // the six named entries from its maps before adding the test variants.
                    foreach (var mapName in new[] { "PolicyMap", "UnactivatedPolicyMap" })
                    {
                        var map = (IDictionary)typeof(RateLimiterOptions).GetProperty(mapName,
                            BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(options)!;
                        foreach (var policy in OidcRateLimitPolicies.All) map.Remove(policy);
                    }
                    foreach (var policy in OidcRateLimitPolicies.All)
                        options.AddPolicy(policy, _ => RateLimitPartition.GetNoLimiter("disabled"));
                });
        }
        using var a = harness.CreateHost(Configure);
        using var b = harness.CreateHost(Configure);
        LoginSession? login = null;
        if (endpoint == "login")
        {
            login = await BeginSuccessLoginViaAuthorizeAsync(a.Factory.Services, a.Client);
            for (var i = 0; i < 45; i++)
                await SeedUserAsync(a.Factory.Services, "attack_user_" + i, "Attack-password-123!");
        }
        var code = await harness.SeedAuthorizationCodeAsync();
        await harness.ExecuteAsync("DELETE FROM oidc_rate_limit_buckets");
        var policyName = "oidc-" + endpoint;
        var digest = a.Digest(partition == "client" ? "client:" + ClientId : "ip:" + RemoteIp);
        for (var i = 0; i < Budget; i++)
        {
            using var request = AttackRequest(endpoint, partition, i, login);
            using var response = await (i % 2 == 0 ? a : b).Client.SendAsync(request, Ct);
            Assert.Equal(ExpectedStatus(endpoint, partition, i), response.StatusCode);
            // Pin only the database expiry, preserving the production 90/60 rule and avoiding
            // dependence on runner speed. Independent negative stores never expire here.
            if (i == 0)
                await harness.ExecuteAsync("UPDATE oidc_rate_limit_buckets SET window_expires_at = now() + interval '1 hour'");
        }
        var before = await LoginStateAsync(harness);
        var handled = a.Probe.HandlerInvocations + b.Probe.HandlerInvocations;
        using var last = endpoint == "token" && partition == "client"
            ? Redeem(code.Code)
            : AttackRequest(endpoint, partition, Budget, login);
        using var rejected = await a.Client.SendAsync(last, Ct);
        var rejection = await Record.ExceptionAsync(() => AssertFixedRejectionAsync(rejected, HttpStatusCode.TooManyRequests));
        if (variant != "shared")
        {
            Assert.IsAssignableFrom<Xunit.Sdk.XunitException>(rejection);
            return;
        }
        Assert.Null(rejection);
        Assert.Equal(handled, a.Probe.HandlerInvocations + b.Probe.HandlerInvocations);
        Assert.True(before == await LoginStateAsync(harness), "Rate rejection changed password failure/lockout state.");
        Assert.Equal(Budget, await harness.PermitCountAsync(policyName, digest));
        Assert.Equal(1, await harness.CountAsync());
        await using var db = harness.Context();
        Assert.Null((await db.AuthorizationCodes.AsNoTracking().SingleAsync(x => x.Id == code.Id, Ct)).ConsumedAt);
        if (login is not null)
        {
            Assert.Null((await db.AuthorizationRequests.AsNoTracking().SingleAsync(Ct)).ConsumedAt);
            Assert.Equal(45, await db.LoginAttempts.CountAsync(Ct));
        }
        // A fresh pair per R2/R3 prevents the host-wide budget from masking independence.
        if (endpoint == "authorize")
        {
            var other = partition == "client" ? "ip" : "client";
            using var independent = await b.Client.SendAsync(AttackRequest(endpoint, other, 0, null), Ct);
            Assert.Equal(ExpectedStatus(endpoint, other, 0), independent.StatusCode);
            Assert.Equal(2, await harness.CountAsync());
        }
    }

    [Fact]
    public async Task AExhaustsBudget_FirstRequestOnBIsImmediatelyRejected()
    {
        await using var harness = await Harness.CreateAsync();
        using var a = harness.CreateHost();
        using var b = harness.CreateHost();
        for (var i = 0; i < Budget; i++)
        {
            using var response = await a.Client.SendAsync(TokenRequest("ip"), Ct);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            if (i == 0) await harness.ExecuteAsync("UPDATE oidc_rate_limit_buckets SET window_expires_at = now() + interval '1 hour'");
        }
        using var rejected = await b.Client.SendAsync(TokenRequest("ip"), Ct);
        await AssertFixedRejectionAsync(rejected, HttpStatusCode.TooManyRequests);
        Assert.Equal(0, b.Probe.HandlerInvocations);
    }

    [Fact]
    public async Task LockedBudget_BothHostsTimeOutWithoutCounting_ThenResumeTheOriginalCount()
    {
        await using var harness = await Harness.CreateAsync();
        using var a = harness.CreateHost();
        using var b = harness.CreateHost();
        using var first = await a.Client.SendAsync(TokenRequest("ip"), Ct);
        var digest = a.Digest("ip:" + RemoteIp);
        var handled = a.Probe.HandlerInvocations + b.Probe.HandlerInvocations;
        await using (await harness.LockRowAsync(OidcRateLimitPolicies.Token, digest))
        {
            var started = TimeProvider.System.GetTimestamp();
            var pendingA = a.Client.SendAsync(TokenRequest("ip"), Ct);
            var pendingB = b.Client.SendAsync(TokenRequest("ip"), Ct);
            using var responseA = await pendingA;
            using var responseB = await pendingB;
            await AssertFixedRejectionAsync(responseA, HttpStatusCode.ServiceUnavailable);
            await AssertFixedRejectionAsync(responseB, HttpStatusCode.ServiceUnavailable);
            Assert.InRange(TimeProvider.System.GetElapsedTime(started), TimeSpan.FromSeconds(1.5), TimeSpan.FromSeconds(10));
            Assert.Equal(1, await harness.PermitCountAsync(OidcRateLimitPolicies.Token, digest));
        }
        Assert.Equal(handled, a.Probe.HandlerInvocations + b.Probe.HandlerInvocations);
        using var next = await b.Client.SendAsync(TokenRequest("ip"), Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, next.StatusCode);
        Assert.Equal(2, await harness.PermitCountAsync(OidcRateLimitPolicies.Token, digest));
    }

    [Fact]
    public async Task CanceledLockWait_OnEachHost_IsNeitherCountedRejectedNorHandled()
    {
        await using var harness = await Harness.CreateAsync();
        using var a = harness.CreateHost();
        using var b = harness.CreateHost();
        using var first = await a.Client.SendAsync(TokenRequest("ip"), Ct);
        var digest = a.Digest("ip:" + RemoteIp);
        foreach (var host in new[] { a, b })
        {
            var handled = host.Probe.HandlerInvocations;
            await using (await harness.LockRowAsync(OidcRateLimitPolicies.Token, digest))
            {
                using var caller = CancellationTokenSource.CreateLinkedTokenSource(Ct);
                var pending = host.Client.SendAsync(TokenRequest("ip"), caller.Token);
                await harness.WaitForLockWaitAsync();
                await caller.CancelAsync();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
                await harness.WaitForNoLockWaitAsync();
            }
            await host.Probe.WaitForRequestsToDrainAsync();
            Assert.Equal(handled, host.Probe.HandlerInvocations);
            Assert.Equal(0, host.Probe.Rejections);
            Assert.Equal(1, await harness.PermitCountAsync(OidcRateLimitPolicies.Token, digest));
        }
    }

    private static async Task<string> LoginStateAsync(Harness harness)
    {
        await using var db = harness.Context();
        return JsonSerializer.Serialize(await db.LoginAttempts.AsNoTracking().OrderBy(x => x.Id).ToListAsync(Ct));
    }

    internal static HttpRequestMessage Redeem(string code, string? verifier = null) => new(HttpMethod.Post, "/oauth2/token")
    {
        Headers = { Authorization = BasicHeader(ClientId, ClientSecret) },
        Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["code"] = code,
            ["redirect_uri"] = RedirectUri, ["code_verifier"] = verifier ?? CodeVerifier
        })
    };

    private static HttpStatusCode ExpectedStatus(string endpoint, string partition, int index) => endpoint switch
    {
        "login" => HttpStatusCode.OK,
        "authorize" => partition == "client" ? HttpStatusCode.Found : HttpStatusCode.BadRequest,
        "userinfo" => HttpStatusCode.Unauthorized,
        "logout" => index % 2 == 0 ? HttpStatusCode.BadRequest : HttpStatusCode.Unauthorized,
        _ => partition == "client" ? index % 2 == 0 ? HttpStatusCode.Unauthorized :
            endpoint == "token" ? HttpStatusCode.BadRequest : HttpStatusCode.OK :
            index % 3 == 0 ? HttpStatusCode.Unauthorized : HttpStatusCode.BadRequest
    };

    private static HttpRequestMessage AttackRequest(string endpoint, string partition, int index, LoginSession? login)
    {
        if (endpoint == "login")
            return CreateLoginPost(fields: LoginFields(login!, index == Budget ? "attack_user_0" :
                    index % 2 == 0 ? "attack_user_" + index / 2 : "unknown_" + index,
                    index == Budget ? "Attack-password-123!" : "wrong-password"), cookieHeader: CookieHeaderFor(login!));
        if (endpoint == "authorize")
            return new(HttpMethod.Get, "/oauth2/authorize?client_id=" + (partition == "client" ? ClientId : "unknown_" + index) +
                "&redirect_uri=" + Uri.EscapeDataString(partition == "client" ? RedirectUri : "https://unknown.test/" + index) +
                $"&response_type=code&scope=openid&state=state-{Guid.NewGuid():N}&nonce=nonce-{Guid.NewGuid():N}&code_challenge={CodeChallenge}&code_challenge_method=S256");
        if (endpoint == "userinfo")
            return new(HttpMethod.Get, "/oauth2/userinfo") { Headers = { Authorization = new AuthenticationHeaderValue("Bearer", "invalid-" + Guid.NewGuid().ToString("N")) } };
        if (endpoint == "logout")
            return index % 2 == 0 ? new(HttpMethod.Get, "/oauth2/logout?logout_handle=" + Guid.NewGuid().ToString("N")) :
                new(HttpMethod.Post, "/oauth2/logout/requests") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["id_token_hint"] = "invalid" }) };
        var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/" + endpoint);
        request.Headers.Authorization = BasicHeader(partition == "client" || index % 3 != 0 ? ClientId : "unknown_" + index,
            partition == "client" && index % 2 == 1 ? ClientSecret : "wrong-secret");
        request.Content = partition == "ip" && index % 3 != 0
            ? new StringContent(index % 3 == 1 ? "bad=%FF" : "bad=" + new string('x', 16385), Encoding.UTF8, "application/x-www-form-urlencoded")
            : new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "unsupported", ["token"] = "invalid-" + index });
        return request;
    }
}
