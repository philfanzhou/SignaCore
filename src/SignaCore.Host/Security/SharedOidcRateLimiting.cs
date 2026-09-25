using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using SignaCore.Database;
using SignaCore.Database.RateLimiting;

namespace SignaCore.Host.Security;

/// <summary>
/// The one decision of whether the six interactive OIDC policies count against the PS-24 shared
/// budget. The policy registration and the global-limiter deferral both read it, so they can never
/// disagree about which requests are counted by the database.
/// </summary>
public static class SharedOidcRateLimiting
{
    /// <summary>PostgreSQL deployments share one budget; SQLite keeps the in-process windows.</summary>
    public static bool IsEnabled(DatabaseOptions databaseOptions) =>
        databaseOptions.ProviderKind == DatabaseProvider.PostgreSql;

    /// <summary>Whether this request's endpoint is admitted by a shared-budget policy.</summary>
    public static bool IsSharedBudgetEndpoint(HttpContext httpContext) =>
        httpContext.GetEndpoint()?.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName is { } policy
        && OidcRateLimitPolicies.All.Contains(policy);

    /// <summary>
    /// Whether a rejected lease came from a store that could not decide, which answers 503 instead
    /// of 429.
    /// </summary>
    public static bool IsStoreUnavailable(RateLimitLease lease) =>
        lease.TryGetMetadata(SharedOidcBudgetRateLimiter.StoreUnavailableMetadataName, out _);
}

/// <summary>
/// One partition of a shared-budget policy: the policy name and the partition digest computed once
/// when the partition is created. Every admission is one store call on the asynchronous path; the
/// synchronous attempt always fails and never waits on the store, so the rate-limiting middleware
/// moves on to <see cref="RateLimiter.AcquireAsync"/>.
/// <para>
/// The limiter holds no budget state of its own and does not own the store. Its idle duration
/// follows the last use, so the partitioned limiter's heartbeat reclaims quiet partitions.
/// </para>
/// </summary>
public sealed class SharedOidcBudgetRateLimiter : RateLimiter
{
    /// <summary>The lease metadata that marks an answer of an unavailable store.</summary>
    public const string StoreUnavailableMetadataName = "signacore.oidc-rate-limit.store-unavailable";

    private readonly IOidcRateLimitStore _store;
    private readonly string _policy;
    private readonly string _partitionDigest;
    private long _lastUseTicks = Environment.TickCount64;
    private int _inFlight;

    public SharedOidcBudgetRateLimiter(IOidcRateLimitStore store, string policy, string partitionDigest)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrEmpty(policy);
        ArgumentException.ThrowIfNullOrEmpty(partitionDigest);
        _store = store;
        _policy = policy;
        _partitionDigest = partitionDigest;
    }

    public override TimeSpan? IdleDuration =>
        Volatile.Read(ref _inFlight) > 0
            ? null
            : TimeSpan.FromMilliseconds(Environment.TickCount64 - Volatile.Read(ref _lastUseTicks));

    public override RateLimiterStatistics? GetStatistics() => null;

    protected override RateLimitLease AttemptAcquireCore(int permitCount) => SharedBudgetLease.Rejected;

    protected override async ValueTask<RateLimitLease> AcquireAsyncCore(
        int permitCount,
        CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _inFlight);
        try
        {
            // Caller cancellation propagates as thrown by the store, so the middleware takes its
            // canceled-request path instead of answering a rejection.
            return await _store.AcquireAsync(_policy, _partitionDigest, cancellationToken) switch
            {
                OidcRateLimitAcquireResult.Granted => SharedBudgetLease.Granted,
                OidcRateLimitAcquireResult.Rejected => SharedBudgetLease.Rejected,
                _ => SharedBudgetLease.StoreUnavailable
            };
        }
        finally
        {
            Volatile.Write(ref _lastUseTicks, Environment.TickCount64);
            Interlocked.Decrement(ref _inFlight);
        }
    }

    private sealed class SharedBudgetLease(bool isAcquired, bool storeUnavailable) : RateLimitLease
    {
        public static readonly SharedBudgetLease Granted = new(isAcquired: true, storeUnavailable: false);
        public static readonly SharedBudgetLease Rejected = new(isAcquired: false, storeUnavailable: false);
        public static readonly SharedBudgetLease StoreUnavailable = new(isAcquired: false, storeUnavailable: true);

        public override bool IsAcquired => isAcquired;

        public override IEnumerable<string> MetadataNames =>
            storeUnavailable ? [StoreUnavailableMetadataName] : [];

        public override bool TryGetMetadata(string metadataName, out object? metadata)
        {
            if (storeUnavailable && metadataName == StoreUnavailableMetadataName)
            {
                metadata = true;
                return true;
            }

            metadata = null;
            return false;
        }
    }
}

/// <summary>
/// Keeps the global per-IP limiter at exactly one permit per request on shared-budget endpoints.
/// <para>
/// The rate-limiting middleware first tries the global and the endpoint limiter synchronously and,
/// when the endpoint attempt fails, releases the global lease and acquires both again on the
/// asynchronous path. A fixed window does not refund a released permit, and the shared budget
/// always fails synchronously, so an unwrapped global limiter would count every such request twice.
/// For shared-budget endpoints the synchronous global attempt is therefore a non-consuming success;
/// the real global permit is taken on the asynchronous path, still ahead of the store. Every other
/// request is passed through unchanged.
/// </para>
/// </summary>
public sealed class SharedOidcBudgetAwareGlobalLimiter(PartitionedRateLimiter<HttpContext> inner)
    : PartitionedRateLimiter<HttpContext>
{
    public override RateLimiterStatistics? GetStatistics(HttpContext resource) => inner.GetStatistics(resource);

    protected override RateLimitLease AttemptAcquireCore(HttpContext resource, int permitCount) =>
        SharedOidcRateLimiting.IsSharedBudgetEndpoint(resource)
            ? DeferredLease.Instance
            : inner.AttemptAcquire(resource, permitCount);

    protected override ValueTask<RateLimitLease> AcquireAsyncCore(
        HttpContext resource,
        int permitCount,
        CancellationToken cancellationToken) =>
        inner.AcquireAsync(resource, permitCount, cancellationToken);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            inner.Dispose();
        }
    }

    protected override ValueTask DisposeAsyncCore() => inner.DisposeAsync();

    private sealed class DeferredLease : RateLimitLease
    {
        public static readonly DeferredLease Instance = new();

        public override bool IsAcquired => true;

        public override IEnumerable<string> MetadataNames => [];

        public override bool TryGetMetadata(string metadataName, out object? metadata)
        {
            metadata = null;
            return false;
        }
    }
}
