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
    private const string RootSecret = "oidc-distributed-rate-limit-root-secret";
    private const string AdminUsername = "shared_budget_admin";
    private const string AdminPassword = "SharedBudget-123!";
    private const string ClientId = "rl-canary-client-7f3a";
    private const string ClientSecret = "rl-canary-secret-7f3a";
    private const string RedirectUri = "https://bff.shared-budget.test/callback";
    private const string RemoteIp = "198.51.100.23";
    private const string CodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const int Budget = IdentityConstants.OidcTokenRateLimitPerMinute;
    private const int GlobalBudget = 100;
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

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

    // ---- Helpers ----

    private static async Task<List<HttpStatusCode>> AlternateTokenRequestsAsync(
        TestHost a,
        TestHost b,
        string partition,
        int count)
    {
        var outcomes = new List<HttpStatusCode>(count);
        for (var i = 0; i < count; i++)
        {
            using var response = await (i % 2 == 0 ? a : b).Client.SendAsync(TokenRequest(partition), Ct);
            outcomes.Add(response.StatusCode);
        }

        return outcomes;
    }

    private static async Task<List<HttpStatusCode>> SendTokenRequestsAsync(TestHost host, int count)
    {
        var outcomes = new List<HttpStatusCode>(count);
        for (var i = 0; i < count; i++)
        {
            using var response = await host.Client.SendAsync(TokenRequest("ip"), Ct);
            outcomes.Add(response.StatusCode);
        }

        return outcomes;
    }

    /// <summary>
    /// A token request that fails client authentication: the registered client with a wrong
    /// secret lands in its client partition, an unknown client in the source-network partition.
    /// </summary>
    private static HttpRequestMessage TokenRequest(string partition)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials"
            })
        };
        request.Headers.Authorization = partition == "client"
            ? BasicHeader(ClientId, "wrong-secret")
            : BasicHeader("unknown-client", "wrong-secret");
        return request;
    }

    private sealed record InteractiveEndpoint(string Policy, string PartitionKey, Func<HttpRequestMessage> Create);

    private static IEnumerable<InteractiveEndpoint> InteractiveEndpoints()
    {
        yield return new(OidcRateLimitPolicies.Authorize, "client:" + ClientId, () => new HttpRequestMessage(
            HttpMethod.Get,
            "/oauth2/authorize?" + string.Join('&',
                $"client_id={ClientId}",
                $"redirect_uri={Uri.EscapeDataString(RedirectUri)}",
                "response_type=code",
                "scope=openid",
                $"state=state-{Guid.NewGuid():N}",
                $"nonce=nonce-{Guid.NewGuid():N}",
                $"code_challenge={CodeChallenge}",
                "code_challenge_method=S256")));
        yield return new(OidcRateLimitPolicies.Login, "ip:" + RemoteIp, () => new HttpRequestMessage(HttpMethod.Post, "/oauth2/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["login_handle"] = "unknown-handle",
                ["username"] = "nobody",
                ["password"] = "wrong-password"
            })
        });
        yield return new(OidcRateLimitPolicies.Token, "ip:" + RemoteIp, () => TokenRequest("ip"));
        yield return new(OidcRateLimitPolicies.UserInfo, "ip:" + RemoteIp, () => new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", "not-a-real-token") }
        });
        yield return new(OidcRateLimitPolicies.Logout, "ip:" + RemoteIp, () => new HttpRequestMessage(HttpMethod.Get, "/oauth2/logout"));
        yield return new(OidcRateLimitPolicies.Logout, "ip:" + RemoteIp, () => new HttpRequestMessage(HttpMethod.Post, "/oauth2/logout/requests")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["id_token_hint"] = "x" })
        });
        yield return new(OidcRateLimitPolicies.Revoke, "ip:" + RemoteIp, () =>
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/revoke")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = "opaque" })
            };
            request.Headers.Authorization = BasicHeader("unknown-client", "wrong-secret");
            return request;
        });
    }

    private static async Task AssertFixedRejectionAsync(HttpResponseMessage response, HttpStatusCode status)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Null(response.Headers.Location);
        Assert.Equal(OidcRateLimitPolicies.RejectionBody, await response.Content.ReadAsStringAsync(Ct));
    }

    private static AuthenticationHeaderValue BasicHeader(string id, string secret) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}")));

    private static void AssertNoCanary(IReadOnlyCollection<string> values, params string[] canaries)
    {
        var index = 0;
        foreach (var value in values)
        {
            for (var c = 0; c < canaries.Length; c++)
            {
                if (value.Contains(canaries[c], StringComparison.OrdinalIgnoreCase))
                {
                    Assert.Fail($"Scanned value #{index} contains canary #{c}.");
                }
            }

            index++;
        }
    }

    /// <summary>A per-instance budget: what a disconnected shared store would amount to.</summary>
    private sealed class PerInstanceBudgetStore : IOidcRateLimitStore
    {
        private readonly ConcurrentDictionary<(string, string), int> _counts = new();

        public Task<OidcRateLimitAcquireResult> AcquireAsync(
            string policy,
            string partitionDigest,
            CancellationToken cancellationToken)
        {
            var count = _counts.AddOrUpdate((policy, partitionDigest), 1, (_, current) => current + 1);
            return Task.FromResult(count <= Budget ? OidcRateLimitAcquireResult.Granted : OidcRateLimitAcquireResult.Rejected);
        }

        public Task<int?> DeleteExpiredAsync(CancellationToken cancellationToken) => Task.FromResult<int?>(0);
    }

    /// <summary>What one host did: handler invocations, rejection callbacks, and its log lines.</summary>
    private sealed class HostProbe
    {
        private int _handlerInvocations;
        private int _rejections;
        private int _inFlight;
        private readonly ConcurrentQueue<string> _logs = new();

        public int HandlerInvocations => Volatile.Read(ref _handlerInvocations);

        public int Rejections => Volatile.Read(ref _rejections);

        public IReadOnlyCollection<string> Logs => _logs.ToArray();

        public void Handled() => Interlocked.Increment(ref _handlerInvocations);

        public void Rejected() => Interlocked.Increment(ref _rejections);

        public void Log(string line) => _logs.Enqueue(line);

        public void ClearLogs() => _logs.Clear();

        public IDisposable Request()
        {
            Interlocked.Increment(ref _inFlight);
            return new Exit(this);
        }

        public async Task WaitForRequestsToDrainAsync()
        {
            var started = TimeProvider.System.GetTimestamp();
            while (Volatile.Read(ref _inFlight) > 0 && TimeProvider.System.GetElapsedTime(started) < TimeSpan.FromSeconds(10))
            {
                await Task.Delay(20, Ct);
            }

            Assert.Equal(0, Volatile.Read(ref _inFlight));
        }

        private sealed class Exit(HostProbe probe) : IDisposable
        {
            public void Dispose() => Interlocked.Decrement(ref probe._inFlight);
        }
    }

    /// <summary>Counts every controller action that started executing.</summary>
    private sealed class HandlerProbeFilter(HostProbe probe) : IResourceFilter
    {
        public void OnResourceExecuting(ResourceExecutingContext context) => probe.Handled();

        public void OnResourceExecuted(ResourceExecutedContext context)
        {
        }
    }

    /// <summary>
    /// Pins the source address of every request, ahead of the whole pipeline, and tracks requests
    /// still in flight so a canceled request is observed to its end.
    /// </summary>
    private sealed class RemoteAddressStartupFilter(HostProbe probe) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, following) =>
            {
                using var _ = probe.Request();
                context.Connection.RemoteIpAddress = IPAddress.Parse(RemoteIp);
                await following(context);
            });
            next(app);
        };
    }

    private sealed class CaptureLoggerProvider(HostProbe probe) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new CaptureLogger(probe, categoryName);

        public void Dispose()
        {
        }

        private sealed class CaptureLogger(HostProbe probe, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var properties = state is IEnumerable<KeyValuePair<string, object?>> pairs
                    ? string.Join(' ', pairs.Select(pair => $"{pair.Key}={pair.Value}"))
                    : string.Empty;
                probe.Log($"{category} {formatter(state, exception)} {properties} {exception}");
            }
        }
    }

    /// <summary>Captures every tag of the ASP.NET Core rate-limiting instruments.</summary>
    private sealed class RateLimitMetricsCapture : IDisposable
    {
        private static readonly HashSet<string> AllowedTagKeys = new(StringComparer.Ordinal)
        {
            "aspnetcore.rate_limiting.policy",
            "aspnetcore.rate_limiting.result"
        };

        private readonly MeterListener _listener = new();
        private readonly ConcurrentQueue<KeyValuePair<string, object?>> _tags = new();

        public RateLimitMetricsCapture(TestHost host)
        {
            // Only this host's meters: other hosts in the process keep their own measurements.
            var scope = host.Factory.Services.GetRequiredService<IMeterFactory>();
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "Microsoft.AspNetCore.RateLimiting"
                    && ReferenceEquals(instrument.Meter.Scope, scope))
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<long>((_, _, tags, _) => Record(tags));
            _listener.SetMeasurementEventCallback<double>((_, _, tags, _) => Record(tags));
            _listener.Start();
        }

        public IReadOnlyCollection<string> TagValues =>
            _tags.Select(tag => Convert.ToString(tag.Value, CultureInfo.InvariantCulture) ?? string.Empty).ToArray();

        public void AssertOnlyPolicyTags()
        {
            Assert.NotEmpty(_tags);
            Assert.All(_tags, tag =>
            {
                Assert.Contains(tag.Key, AllowedTagKeys);
                if (tag.Key == "aspnetcore.rate_limiting.policy")
                {
                    Assert.Contains((string)tag.Value!, OidcRateLimitPolicies.All);
                }
            });
        }

        public void Dispose() => _listener.Dispose();

        private void Record(ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            foreach (var tag in tags)
            {
                _tags.Enqueue(tag);
            }
        }
    }

    private sealed class TestHost(WebApplicationFactory<Program> factory, HttpClient client, HostProbe probe) : IDisposable
    {
        public WebApplicationFactory<Program> Factory => factory;

        public HttpClient Client => client;

        public HostProbe Probe => probe;

        public string Digest(string partitionKey) =>
            factory.Services.GetRequiredService<OidcRateLimitPartitioner>().Digest(partitionKey);

        public void Dispose()
        {
            client.Dispose();
            factory.Dispose();
        }
    }

    private sealed record SeededCode(string Code, Guid Id);

    private sealed class Harness(DatabaseOptions database, string bootstrapDirectory, string bootstrapFilePath, PostgreSqlContainer container) : IAsyncDisposable
    {
        public string ConnectionString => database.ConnectionString;

        public static async Task<Harness> CreateAsync()
        {
            Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true", "Enable the PostgreSQL database contract matrix.");
            var container = new PostgreSqlBuilder(Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") ?? "postgres:15-alpine").Build();
            var directory = Path.Combine(Path.GetTempPath(), $"signacore-shared-budget-{Guid.NewGuid():N}");
            try
            {
                await container.StartAsync(Ct);
                var database = new DatabaseOptions
                {
                    Provider = "PostgreSQL",
                    ServerVersion = "15",
                    ConnectionString = container.GetConnectionString()
                };
                var bootstrapFilePath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
                    directory, database, RootSecret, AdminUsername, AdminPassword, cancellationToken: Ct);
                var harness = new Harness(database, directory, bootstrapFilePath, container);
                await harness.SeedClientAsync();
                return harness;
            }
            catch
            {
                await container.DisposeAsync();
                throw;
            }
        }

        /// <summary>One more replica: its own process state, the shared database and root key.</summary>
        public TestHost CreateHost(Action<IServiceCollection>? configure = null)
        {
            var probe = new HostProbe();
            var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath);
                builder.UseSetting("Endpoints:Http", "0");
                builder.ConfigureTestServices(services =>
                {
                    services.AddSingleton<IStartupFilter>(new RemoteAddressStartupFilter(probe));
                    services.Configure<MvcOptions>(options => options.Filters.Add(new HandlerProbeFilter(probe)));
                    services.RemoveAll<ILoggerFactory>();
                    services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
                        logging.SetMinimumLevel(LogLevel.Trace).AddProvider(new CaptureLoggerProvider(probe))));
                    services.PostConfigure<RateLimiterOptions>(options =>
                    {
                        var inner = options.OnRejected;
                        options.OnRejected = async (context, cancellationToken) =>
                        {
                            probe.Rejected();
                            if (inner is not null)
                            {
                                await inner(context, cancellationToken);
                            }
                        };
                    });
                    configure?.Invoke(services);
                });
            });
            var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                HandleCookies = false
            });
            return new TestHost(factory, client, probe);
        }

        public IdentityDbContext Context()
        {
            var builder = new DbContextOptionsBuilder<IdentityDbContext>();
            builder.UseIdentityDatabase(database, enableRetryOnFailure: false);
            return new IdentityDbContext(builder.Options);
        }

        public async Task ExecuteAsync(string sql)
        {
            await using var connection = await OpenAsync();
            await using var command = new NpgsqlCommand(sql, connection);
            await command.ExecuteNonQueryAsync(Ct);
        }

        public async Task<int> CountAsync()
        {
            await using var connection = await OpenAsync();
            await using var command = new NpgsqlCommand("SELECT count(*) FROM oidc_rate_limit_buckets", connection);
            return Convert.ToInt32(await command.ExecuteScalarAsync(Ct), CultureInfo.InvariantCulture);
        }

        public async Task<int?> PermitCountAsync(string policy, string digest)
        {
            await using var connection = await OpenAsync();
            await using var command = new NpgsqlCommand(
                "SELECT permit_count FROM oidc_rate_limit_buckets WHERE policy = @p AND partition_digest = @d",
                connection);
            command.Parameters.AddWithValue("p", policy);
            command.Parameters.AddWithValue("d", digest);
            var value = await command.ExecuteScalarAsync(Ct);
            return value is null ? null : Convert.ToInt32(value, CultureInfo.InvariantCulture);
        }

        public async Task<List<string>> DumpAsync()
        {
            await using var connection = await OpenAsync();
            await using var command = new NpgsqlCommand(
                "SELECT policy, partition_digest, window_expires_at::text, permit_count::text FROM oidc_rate_limit_buckets",
                connection);
            await using var reader = await command.ExecuteReaderAsync(Ct);
            var rows = new List<string>();
            while (await reader.ReadAsync(Ct))
            {
                rows.Add(string.Join('|', reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3)));
            }

            return rows;
        }

        /// <summary>Holds the row lock of one bucket in an open transaction until disposed.</summary>
        public async Task<IAsyncDisposable> LockRowAsync(string policy, string digest)
        {
            var connection = await OpenAsync();
            var transaction = await connection.BeginTransactionAsync(Ct);
            await using (var command = new NpgsqlCommand(
                "SELECT 1 FROM oidc_rate_limit_buckets WHERE policy = @p AND partition_digest = @d FOR UPDATE",
                connection,
                transaction))
            {
                command.Parameters.AddWithValue("p", policy);
                command.Parameters.AddWithValue("d", digest);
                Assert.NotNull(await command.ExecuteScalarAsync(Ct));
            }

            return new RowLock(connection, transaction);
        }

        public Task WaitForLockWaitAsync() => WaitForLockWaitersAsync(expectWaiting: true);

        public Task WaitForNoLockWaitAsync() => WaitForLockWaitersAsync(expectWaiting: false);

        public async Task<SeededCode> SeedAuthorizationCodeAsync()
        {
            await using var context = Context();
            var application = await context.AppRegistrations.AsNoTracking().SingleAsync(x => x.AppId == ClientId, Ct);
            var accountId = Guid.NewGuid();
            var credentialId = Guid.NewGuid();
            context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
            context.PasswordCredentials.Add(new PasswordCredentialEntity
            {
                Id = credentialId,
                AccountId = accountId,
                Username = $"shared_budget_user_{Guid.NewGuid():N}",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("Shared-Budget-123!", 4),
                CreatedAt = DateTimeOffset.UtcNow
            });
            await context.SaveChangesAsync(Ct);
            context.ChangeTracker.Clear();

            var session = await new IdentitySessionStore(
                    new Database.Repositories.IdentitySessionRepository(context),
                    new Database.Repositories.EfCoreUnitOfWork(context))
                .CreateAsync(accountId, credentialId, DateTimeOffset.UtcNow, Ct);
            var creation = await new AuthorizationCodeStore(
                    new Database.Repositories.AuthorizationCodeRepository(context),
                    new Database.Repositories.EfCoreUnitOfWork(context))
                .CreateAsync(
                    session,
                    new AuthorizationCodeBinding(application.Id, RedirectUri, "openid", "shared-budget-nonce", CodeChallenge),
                    DateTimeOffset.UtcNow,
                    Ct);
            return new SeededCode(creation.Code, creation.Id);
        }

        public async ValueTask DisposeAsync()
        {
            await container.DisposeAsync();
            if (Directory.Exists(bootstrapDirectory))
            {
                Directory.Delete(bootstrapDirectory, recursive: true);
            }
        }

        private async Task SeedClientAsync()
        {
            await using var context = Context();
            var application = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = ClientId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword(ClientSecret, 4),
                AppName = "Shared Budget App",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.PerApplication,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = "openid profile",
                AllowRefreshToken = false
            };
            context.AppRegistrations.Add(application);
            context.AppRedirectUris.Add(new AppRedirectUriEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = application.Id,
                Kind = RedirectUriKind.Redirect,
                CanonicalUri = RedirectUri
            });
            await context.SaveChangesAsync(Ct);
        }

        private async Task<NpgsqlConnection> OpenAsync()
        {
            var connection = new NpgsqlConnection(
                new NpgsqlConnectionStringBuilder(database.ConnectionString) { Pooling = false }.ConnectionString);
            await connection.OpenAsync(Ct);
            return connection;
        }

        private async Task WaitForLockWaitersAsync(bool expectWaiting)
        {
            var started = TimeProvider.System.GetTimestamp();
            while (TimeProvider.System.GetElapsedTime(started) < TimeSpan.FromSeconds(10))
            {
                await using var connection = await OpenAsync();
                await using var command = new NpgsqlCommand(
                    "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()",
                    connection);
                var waiting = Convert.ToInt32(await command.ExecuteScalarAsync(Ct), CultureInfo.InvariantCulture) > 0;
                if (waiting == expectWaiting)
                {
                    return;
                }

                await Task.Delay(20, Ct);
            }

            Assert.Fail(expectWaiting
                ? "No session started waiting for the row lock."
                : "A session kept waiting for the row lock.");
        }

        private sealed class RowLock(NpgsqlConnection connection, NpgsqlTransaction transaction) : IAsyncDisposable
        {
            private bool _disposed;

            public async ValueTask DisposeAsync()
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                await transaction.DisposeAsync();
                await connection.DisposeAsync();
            }
        }
    }
}
