using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using SignaCore.Database;
using SignaCore.Database.RateLimiting;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Host;

/// <summary>
/// The shared OIDC budget adapter and the global-limiter deferral (#381) in isolation: the
/// synchronous path never touches the store, each asynchronous acquisition is exactly one store
/// call, the store answers map to leases, and only shared-budget endpoints defer their global
/// permit to the asynchronous pass.
/// </summary>
public sealed class SharedOidcRateLimitingTests
{
    private const string Digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Fact]
    public void TheSynchronousAttempt_FailsWithoutTouchingTheStore()
    {
        var store = new ScriptedStore(OidcRateLimitAcquireResult.Granted);
        using var limiter = new SharedOidcBudgetRateLimiter(store, OidcRateLimitPolicies.Token, Digest);

        using var lease = limiter.AttemptAcquire();

        Assert.False(lease.IsAcquired);
        Assert.False(SharedOidcRateLimiting.IsStoreUnavailable(lease));
        Assert.Equal(0, store.Calls);
    }

    [Theory]
    [InlineData(OidcRateLimitAcquireResult.Granted, true, false)]
    [InlineData(OidcRateLimitAcquireResult.Rejected, false, false)]
    [InlineData(OidcRateLimitAcquireResult.Unavailable, false, true)]
    public async Task EachAsynchronousAcquisition_IsOneStoreCall_MappedToItsLease(
        OidcRateLimitAcquireResult answer,
        bool acquired,
        bool unavailable)
    {
        var store = new ScriptedStore(answer);
        using var limiter = new SharedOidcBudgetRateLimiter(store, OidcRateLimitPolicies.Logout, Digest);

        using var lease = await limiter.AcquireAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(acquired, lease.IsAcquired);
        Assert.Equal(unavailable, SharedOidcRateLimiting.IsStoreUnavailable(lease));
        Assert.Equal(1, store.Calls);
        Assert.Equal((OidcRateLimitPolicies.Logout, Digest), store.LastCall);
    }

    [Fact]
    public async Task CallerCancellation_PropagatesInsteadOfBecomingALease()
    {
        using var caller = new CancellationTokenSource();
        var store = new ScriptedStore(OidcRateLimitAcquireResult.Granted) { CancelWith = caller };
        using var limiter = new SharedOidcBudgetRateLimiter(store, OidcRateLimitPolicies.Token, Digest);

        var thrown = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await limiter.AcquireAsync(cancellationToken: caller.Token));

        Assert.Equal(caller.Token, thrown.CancellationToken);
        Assert.Equal(1, store.Calls);
    }

    [Fact]
    public async Task TheIdleDuration_IsNullWhileAStoreCallIsInFlight()
    {
        var release = new TaskCompletionSource<OidcRateLimitAcquireResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var store = new ScriptedStore(OidcRateLimitAcquireResult.Granted) { Pending = release.Task };
        using var limiter = new SharedOidcBudgetRateLimiter(store, OidcRateLimitPolicies.Token, Digest);
        Assert.NotNull(limiter.IdleDuration);

        var acquisition = limiter.AcquireAsync(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(limiter.IdleDuration);

        release.SetResult(OidcRateLimitAcquireResult.Granted);
        using var lease = await acquisition;
        Assert.NotNull(limiter.IdleDuration);
    }

    [Fact]
    public async Task DisposingAPartition_LeavesTheSharedStoreOpen()
    {
        var store = new ScriptedStore(OidcRateLimitAcquireResult.Granted);
        var limiter = new SharedOidcBudgetRateLimiter(store, OidcRateLimitPolicies.Token, Digest);

        limiter.Dispose();
        await limiter.DisposeAsync();

        Assert.False(store.Disposed);
    }

    [Fact]
    public async Task OnASharedEndpoint_TheGlobalPermitIsTakenOnlyOnTheAsynchronousPass()
    {
        using var global = new SharedOidcBudgetAwareGlobalLimiter(OnePermitGlobal());
        var context = ContextFor(OidcRateLimitPolicies.Token);

        // The middleware's synchronous pass: a success that takes nothing, then released.
        using (var deferred = global.AttemptAcquire(context))
        {
            Assert.True(deferred.IsAcquired);
        }

        // The asynchronous pass takes the only permit; the next request is refused.
        using var charged = await global.AcquireAsync(context, cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(charged.IsAcquired);
        using var refused = await global.AcquireAsync(context, cancellationToken: TestContext.Current.CancellationToken);
        Assert.False(refused.IsAcquired);
    }

    [Theory]
    [InlineData("sms-code")]
    [InlineData("default")]
    [InlineData(null)]
    public void EveryOtherRequest_IsChargedOnTheSynchronousPass(string? policy)
    {
        using var global = new SharedOidcBudgetAwareGlobalLimiter(OnePermitGlobal());
        var context = ContextFor(policy);

        using var first = global.AttemptAcquire(context);
        using var second = global.AttemptAcquire(context);

        Assert.True(first.IsAcquired);
        Assert.False(second.IsAcquired);
    }

    [Fact]
    public void TheSharedDecision_CoversExactlyTheSixPoliciesOnPostgreSqlOnly()
    {
        Assert.True(SharedOidcRateLimiting.IsEnabled(new DatabaseOptions { Provider = "PostgreSQL", ConnectionString = "Host=db" }));
        Assert.False(SharedOidcRateLimiting.IsEnabled(new DatabaseOptions { Provider = "SQLite", ConnectionString = "Data Source=x.db" }));

        foreach (var policy in OidcRateLimitPolicies.All)
        {
            Assert.True(SharedOidcRateLimiting.IsSharedBudgetEndpoint(ContextFor(policy)));
        }

        Assert.Equal(OidcRateLimitBudgets.Policies.Order(), OidcRateLimitPolicies.All.Order());
        Assert.False(SharedOidcRateLimiting.IsSharedBudgetEndpoint(ContextFor("sms-code")));
        Assert.False(SharedOidcRateLimiting.IsSharedBudgetEndpoint(ContextFor(null)));
    }

    private static PartitionedRateLimiter<HttpContext> OnePermitGlobal() =>
        PartitionedRateLimiter.Create<HttpContext, string>(_ =>
            RateLimitPartition.GetFixedWindowLimiter("client", _ => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = false,
                PermitLimit = 1,
                Window = TimeSpan.FromMinutes(1)
            }));

    private static HttpContext ContextFor(string? policy)
    {
        var context = new DefaultHttpContext();
        var metadata = policy is null
            ? new EndpointMetadataCollection()
            : new EndpointMetadataCollection(new EnableRateLimitingAttribute(policy));
        context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, metadata, "test"));
        return context;
    }

    private sealed class ScriptedStore(OidcRateLimitAcquireResult answer) : IOidcRateLimitStore, IDisposable
    {
        public int Calls { get; private set; }

        public (string Policy, string Digest) LastCall { get; private set; }

        public CancellationTokenSource? CancelWith { get; init; }

        public Task<OidcRateLimitAcquireResult>? Pending { get; init; }

        public bool Disposed { get; private set; }

        public async Task<OidcRateLimitAcquireResult> AcquireAsync(
            string policy,
            string partitionDigest,
            CancellationToken cancellationToken)
        {
            Calls++;
            LastCall = (policy, partitionDigest);
            if (CancelWith is not null)
            {
                await CancelWith.CancelAsync();
                cancellationToken.ThrowIfCancellationRequested();
            }

            return Pending is null ? answer : await Pending;
        }

        public Task<int?> DeleteExpiredAsync(CancellationToken cancellationToken) => Task.FromResult<int?>(0);

        public void Dispose() => Disposed = true;
    }
}
