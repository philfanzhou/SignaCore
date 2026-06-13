using System.Collections.Concurrent;
using System.Threading.RateLimiting;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace QuantumZhou.Identity.Service;

public class RateLimitingOptions
{
    public int PermitLimitPerClient { get; set; } = 20;
    public int WindowSeconds { get; set; } = 60;
    public int CleanupIntervalSeconds { get; set; } = 300;
}

public class RateLimitingInterceptor : Interceptor
{
    private readonly RateLimitingOptions _options;
    private readonly ConcurrentDictionary<string, (RateLimiter Limiter, DateTime LastAccess)> _limiters = new();
    private readonly object _cleanupLock = new();
    private DateTime _lastCleanup = DateTime.UtcNow;

    public RateLimitingInterceptor(RateLimitingOptions options)
    {
        _options = options;
    }

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        var clientIp = context.Peer;

        var entry = _limiters.GetOrAdd(clientIp, ip =>
        {
            var limiter = new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions
            {
                PermitLimit = _options.PermitLimitPerClient,
                Window = TimeSpan.FromSeconds(_options.WindowSeconds),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            });
            return (limiter, DateTime.UtcNow);
        });

        _limiters.TryUpdate(clientIp, (entry.Limiter, DateTime.UtcNow), entry);

        var lease = await entry.Limiter.AcquireAsync(permitCount: 1, context.CancellationToken);
        if (!lease.IsAcquired)
        {
            throw new RpcException(new Status(StatusCode.ResourceExhausted, "Rate limit exceeded. Please try again later."));
        }

        try
        {
            MaybeCleanupStaleEntries();
            return await continuation(request, context);
        }
        finally
        {
            lease.Dispose();
        }
    }

    private void MaybeCleanupStaleEntries()
    {
        var now = DateTime.UtcNow;
        if ((now - _lastCleanup).TotalSeconds < _options.CleanupIntervalSeconds)
        {
            return;
        }

        lock (_cleanupLock)
        {
            if ((now - _lastCleanup).TotalSeconds < _options.CleanupIntervalSeconds)
            {
                return;
            }

            _lastCleanup = now;
            var cutoff = now.AddSeconds(-_options.CleanupIntervalSeconds * 2);
            var staleKeys = _limiters.Where(e => e.Value.LastAccess < cutoff)
                                     .Select(e => e.Key)
                                     .ToList();
            foreach (var key in staleKeys)
            {
                _limiters.TryRemove(key, out var removed);
                removed.Limiter.Dispose();
            }
        }
    }
}
