using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.RateLimiting;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Security;
using SignaCore.Host.Startup;
using Testcontainers.PostgreSql;
using Xunit;

using static SignaCore.Tests.Integration.OidcDatabaseTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The six interactive OIDC policies over real hosts sharing one PostgreSQL database (#381): one
/// PS-24 budget across replicas, the global per-IP limiter charged exactly once per request, the
/// 503 answer of an unavailable store, caller cancellation, bounded cleanup, and the absence of raw
/// partition values in logs and metrics. Negative variants prove the assertions detect a missing
/// shared store and a missing global-limiter deferral.
/// </summary>
public sealed class OidcDistributedRateLimitDatabaseContractTests
{
    [Theory]
    [InlineData("client")]
    [InlineData("ip")]
    public async Task TwoHosts_AlternatingOnePartition_ShareOneWindowBudget(string partition)
    {
        await using var harness = await Harness.CreateAsync();
        using var a = harness.CreateHost();
        using var b = harness.CreateHost();

        var outcomes = await AlternateTokenRequestsAsync(a, b, partition, Budget + 1);

        Assert.All(outcomes.Take(Budget), status => Assert.Equal(HttpStatusCode.Unauthorized, status));
        Assert.Equal(HttpStatusCode.TooManyRequests, outcomes[Budget]);
        var digest = a.Digest(partition == "client" ? "client:" + ClientId : "ip:" + RemoteIp);
        Assert.Equal(Budget, await harness.PermitCountAsync(OidcRateLimitPolicies.Token, digest));
        Assert.Equal(1, await harness.CountAsync());

        // The rejection is the fixed OIDC shape, and the table holds digests only.
        using var rejected = await a.Client.SendAsync(TokenRequest(partition), Ct);
        await AssertFixedRejectionAsync(rejected, HttpStatusCode.TooManyRequests);
        var dump = await harness.DumpAsync();
        AssertNoCanary(dump, ClientId, RemoteIp, ClientSecret);
    }

    [Fact]
    public async Task TwoHosts_WithPerInstanceBudgets_FailTheSharedAssertion()
    {
        await using var harness = await Harness.CreateAsync();
        using var a = harness.CreateHost(services => services.Replace(
            ServiceDescriptor.Singleton<IOidcRateLimitStore>(new PerInstanceBudgetStore())));
        using var b = harness.CreateHost(services => services.Replace(
            ServiceDescriptor.Singleton<IOidcRateLimitStore>(new PerInstanceBudgetStore())));

        var outcomes = await AlternateTokenRequestsAsync(a, b, "client", Budget + 1);

        // Disconnected from the shared store, each instance counts only its half: the 91st
        // request passes, so the shared-budget assertion above would fail.
        Assert.DoesNotContain(HttpStatusCode.TooManyRequests, outcomes);
        Assert.Equal(0, await harness.CountAsync());
    }

    [Fact]
    public async Task OneHost_SharedPolicy_ChargesTheGlobalLimiterExactlyOncePerRequest()
    {
        await using var harness = await Harness.CreateAsync();
        using var host = harness.CreateHost();
        var options = host.Factory.Services.GetRequiredService<IOptions<RateLimiterOptions>>().Value;
        Assert.IsType<SharedOidcBudgetAwareGlobalLimiter>(options.GlobalLimiter);

        for (var i = 0; i < Budget; i++)
        {
            using var within = await host.Client.SendAsync(TokenRequest("ip"), Ct);
            Assert.Equal(HttpStatusCode.Unauthorized, within.StatusCode);
        }

        // Ninety shared-policy requests took ninety global permits: ten non-OIDC requests
        // remain, and the eleventh is refused by the global limiter.
        for (var i = 0; i < GlobalBudget - Budget; i++)
        {
            using var within = await host.Client.GetAsync("/.well-known/openid-configuration", Ct);
            Assert.Equal(HttpStatusCode.OK, within.StatusCode);
        }

        using var global = await host.Client.GetAsync("/.well-known/openid-configuration", Ct);
        Assert.Equal(HttpStatusCode.TooManyRequests, global.StatusCode);
        Assert.Contains("Rate limit exceeded", await global.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        Assert.Equal(Budget, await harness.PermitCountAsync(OidcRateLimitPolicies.Token, host.Digest("ip:" + RemoteIp)));
    }

    [Fact]
    public async Task OneHost_The91stRequest_IsRejectedByTheSharedBudget_AndNoLocalWindowRemains()
    {
        await using var harness = await Harness.CreateAsync();
        using var host = harness.CreateHost();
        var digest = host.Digest("ip:" + RemoteIp);

        var first = await SendTokenRequestsAsync(host, Budget + 1);

        Assert.All(first.Take(Budget), status => Assert.Equal(HttpStatusCode.Unauthorized, status));
        Assert.Equal(HttpStatusCode.TooManyRequests, first[Budget]);
        Assert.Equal(Budget, await harness.PermitCountAsync(OidcRateLimitPolicies.Token, digest));

        // Resetting the shared row admits the next request at once: no in-process named window
        // counted the ninety-one requests alongside the store.
        await harness.ExecuteAsync("DELETE FROM oidc_rate_limit_buckets");
        using var next = await host.Client.SendAsync(TokenRequest("ip"), Ct);
        Assert.Equal(HttpStatusCode.Unauthorized, next.StatusCode);
        Assert.Equal(1, await harness.PermitCountAsync(OidcRateLimitPolicies.Token, digest));
    }

    [Fact]
    public async Task OneHost_WithoutTheGlobalDeferral_IsRejectedAtTheFiftyFirstRequest()
    {
        await using var harness = await Harness.CreateAsync();
        using var host = harness.CreateHost(services =>
            services.PostConfigure<RateLimiterOptions>(options =>
                options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
                    RateLimitPartition.GetFixedWindowLimiter(
                        $"client:{httpContext.Connection.RemoteIpAddress}",
                        _ => new FixedWindowRateLimiterOptions
                        {
                            AutoReplenishment = true,
                            PermitLimit = GlobalBudget,
                            Window = TimeSpan.FromSeconds(60)
                        }))));

        var outcomes = await SendTokenRequestsAsync(host, Budget + 1);

        // Unwrapped, every shared-policy request takes two global permits, so the global limiter
        // refuses the 51st request long before the shared budget is reached: the exactly-once
        // assertion above would fail.
        Assert.All(outcomes.Take(GlobalBudget / 2), status => Assert.Equal(HttpStatusCode.Unauthorized, status));
        Assert.Equal(HttpStatusCode.TooManyRequests, outcomes[GlobalBudget / 2]);
        Assert.Equal(GlobalBudget / 2, await harness.PermitCountAsync(OidcRateLimitPolicies.Token, host.Digest("ip:" + RemoteIp)));
    }

    [Fact]
    public async Task EveryInteractivePolicy_IsAdmittedByTheSharedBudget_AndARejectionReachesNoHandler()
    {
        await using var harness = await Harness.CreateAsync();
        using var host = harness.CreateHost();

        foreach (var endpoint in InteractiveEndpoints())
        {
            await harness.ExecuteAsync("DELETE FROM oidc_rate_limit_buckets");
            var digest = host.Digest(endpoint.PartitionKey);

            using (var admitted = await host.Client.SendAsync(endpoint.Create(), Ct))
            {
                Assert.NotEqual(HttpStatusCode.TooManyRequests, admitted.StatusCode);
                Assert.NotEqual(HttpStatusCode.ServiceUnavailable, admitted.StatusCode);
            }

            Assert.Equal(1, await harness.PermitCountAsync(endpoint.Policy, digest));

            await harness.ExecuteAsync(
                $"UPDATE oidc_rate_limit_buckets SET permit_count = {Budget} WHERE policy = '{endpoint.Policy}'");
            var handled = host.Probe.HandlerInvocations;
            using var rejected = await host.Client.SendAsync(endpoint.Create(), Ct);

            await AssertFixedRejectionAsync(rejected, HttpStatusCode.TooManyRequests);
            Assert.Equal(handled, host.Probe.HandlerInvocations);
            Assert.Equal(Budget, await harness.PermitCountAsync(endpoint.Policy, digest));
        }
    }

    [Fact]
    public async Task ARejectedTokenRequest_LeavesAValidAuthorizationCodeUnconsumed()
    {
        await using var harness = await Harness.CreateAsync();
        using var host = harness.CreateHost();
        var code = await harness.SeedAuthorizationCodeAsync();
        await harness.ExecuteAsync(
            "INSERT INTO oidc_rate_limit_buckets (policy, partition_digest, window_expires_at, permit_count) " +
            $"VALUES ('{OidcRateLimitPolicies.Token}', '{host.Digest("client:" + ClientId)}', now() + interval '5 minutes', {Budget})");

        using var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code.Code,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = CodeVerifier
            })
        };
        request.Headers.Authorization = BasicHeader(ClientId, ClientSecret);
        using var rejected = await host.Client.SendAsync(request, Ct);

        await AssertFixedRejectionAsync(rejected, HttpStatusCode.TooManyRequests);
        Assert.Equal(0, host.Probe.HandlerInvocations);
        await using var db = harness.Context();
        var row = await db.AuthorizationCodes.AsNoTracking().SingleAsync(x => x.Id == code.Id, Ct);
        Assert.Null(row.ConsumedAt);
    }

    [Fact]
    public async Task AnUnreachableStore_Answers503WithoutReachingTheHandlerOrLeakingTheFailure()
    {
        await using var harness = await Harness.CreateAsync();
        var unreachable = new NpgsqlConnectionStringBuilder(harness.ConnectionString)
        {
            Port = 1,
            Timeout = 1,
            Database = "canary_db_5b1e",
            Username = "canary_user_5b1e",
            Password = "canary_pw_5b1e"
        }.ConnectionString;
        using var host = harness.CreateHost(services => services.Replace(ServiceDescriptor.Singleton<IOidcRateLimitStore>(
            _ => new PostgreSqlOidcRateLimitStore(new DatabaseOptions
            {
                Provider = "PostgreSQL",
                ServerVersion = "15",
                ConnectionString = unreachable
            }))));
        using var metrics = new RateLimitMetricsCapture(host);
        host.Probe.ClearLogs();

        using var response = await host.Client.SendAsync(TokenRequest("client"), Ct);

        await AssertFixedRejectionAsync(response, HttpStatusCode.ServiceUnavailable);
        Assert.Equal(0, host.Probe.HandlerInvocations);
        Assert.Equal(1, host.Probe.Rejections);
        Assert.Equal(0, await harness.CountAsync());
        var carriers = host.Probe.Logs.Concat(metrics.TagValues).ToList();
        AssertNoCanary(
            carriers,
            ClientId, RemoteIp, host.Digest("client:" + ClientId),
            "canary_db_5b1e", "canary_user_5b1e", "canary_pw_5b1e",
            "NpgsqlException", "SocketException", "TimeoutException", "refused", "Failed to connect");
        metrics.AssertOnlyPolicyTags();
    }

    [Fact]
    public async Task ARowLockHeldPastTheStoreBudget_Answers503AndCountsNothing()
    {
        await using var harness = await Harness.CreateAsync();
        using var host = harness.CreateHost();
        var digest = host.Digest("ip:" + RemoteIp);
        using (var first = await host.Client.SendAsync(TokenRequest("ip"), Ct))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, first.StatusCode);
        }

        var handled = host.Probe.HandlerInvocations;
        await using (await harness.LockRowAsync(OidcRateLimitPolicies.Token, digest))
        {
            var started = TimeProvider.System.GetTimestamp();
            using var response = await host.Client.SendAsync(TokenRequest("ip"), Ct);

            await AssertFixedRejectionAsync(response, HttpStatusCode.ServiceUnavailable);
            var elapsed = TimeProvider.System.GetElapsedTime(started);
            Assert.InRange(elapsed, TimeSpan.FromSeconds(1.5), TimeSpan.FromSeconds(10));
        }

        Assert.Equal(handled, host.Probe.HandlerInvocations);
        Assert.Equal(1, await harness.PermitCountAsync(OidcRateLimitPolicies.Token, digest));
    }

    [Fact]
    public async Task ACallerCanceledWhileWaitingForTheRowLock_IsNeitherRejectedNorHandled()
    {
        await using var harness = await Harness.CreateAsync();
        using var host = harness.CreateHost();
        var digest = host.Digest("ip:" + RemoteIp);
        using (var first = await host.Client.SendAsync(TokenRequest("ip"), Ct))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, first.StatusCode);
        }

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
        Assert.Equal(0, host.Probe.Rejections);
        Assert.Equal(handled, host.Probe.HandlerInvocations);
        Assert.Equal(1, await harness.PermitCountAsync(OidcRateLimitPolicies.Token, digest));
    }

    [Fact]
    public async Task RejectionPaths_KeepRawPartitionValuesOutOfLogsAndMetrics()
    {
        await using var harness = await Harness.CreateAsync();
        using var host = harness.CreateHost();
        using var metrics = new RateLimitMetricsCapture(host);
        await harness.ExecuteAsync(
            "INSERT INTO oidc_rate_limit_buckets (policy, partition_digest, window_expires_at, permit_count) " +
            $"VALUES ('{OidcRateLimitPolicies.Token}', '{host.Digest("client:" + ClientId)}', now() + interval '5 minutes', {Budget})");
        host.Probe.ClearLogs();

        using var rejected = await host.Client.SendAsync(TokenRequest("client"), Ct);

        await AssertFixedRejectionAsync(rejected, HttpStatusCode.TooManyRequests);
        Assert.NotEmpty(host.Probe.Logs);
        AssertNoCanary(
            host.Probe.Logs.Concat(metrics.TagValues).ToList(),
            ClientId, ClientSecret, RemoteIp, host.Digest("client:" + ClientId));
        metrics.AssertOnlyPolicyTags();
        Assert.Contains(OidcRateLimitPolicies.Token, metrics.TagValues);
    }

    [Fact]
    public void TheCanaryScanner_FindsAPlantedCanary()
    {
        Assert.ThrowsAny<Exception>(() => AssertNoCanary(["prefix RL-CANARY-CLIENT-7F3A suffix"], ClientId));
        Assert.ThrowsAny<Exception>(() => AssertNoCanary(["from 198.51.100.23:443"], RemoteIp));
        AssertNoCanary(["nothing to see"], ClientId, RemoteIp);
    }

    [Fact]
    public async Task TheCleanupWorker_DeletesOnlyRowsPastTheRetentionPeriod()
    {
        await using var harness = await Harness.CreateAsync();
        await harness.ExecuteAsync(
            "INSERT INTO oidc_rate_limit_buckets (policy, partition_digest, window_expires_at, permit_count) VALUES " +
            $"('{OidcRateLimitPolicies.Token}', '{new string('a', 64)}', now() - interval '25 hours', 5), " +
            $"('{OidcRateLimitPolicies.Token}', '{new string('b', 64)}', now() - interval '23 hours', 5), " +
            $"('{OidcRateLimitPolicies.Login}', '{new string('c', 64)}', now() + interval '30 seconds', 5)");

        // The cleanup worker runs its first round when the host starts.
        using var host = harness.CreateHost();
        var deadline = TimeProvider.System.GetTimestamp();
        while (await harness.CountAsync() == 3 && TimeProvider.System.GetElapsedTime(deadline) < TimeSpan.FromSeconds(20))
        {
            await Task.Delay(50, Ct);
        }

        var rows = await harness.DumpAsync();
        Assert.Equal(2, rows.Count);
        Assert.DoesNotContain(rows, row => row.Contains(new string('a', 64), StringComparison.Ordinal));
        Assert.Contains(host.Probe.Logs, line => line.Contains("Deleted 1 expired OIDC rate-limit buckets", StringComparison.Ordinal));
    }

}
