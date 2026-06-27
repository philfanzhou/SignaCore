using System.Collections.Concurrent;
using System.Threading.RateLimiting;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Microsoft.Extensions.Logging;

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
    private readonly ILogger<RateLimitingInterceptor> _logger;
    private readonly ConcurrentDictionary<string, (RateLimiter Limiter, DateTime LastAccess)> _limiters = new();
    private readonly object _cleanupLock = new();
    private DateTime _lastCleanup = DateTime.UtcNow;

    public RateLimitingInterceptor(RateLimitingOptions options, ILogger<RateLimitingInterceptor> logger)
    {
        _options = options;
        _logger = logger;
    }

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        var clientIp = ExtractClientIp(context.Peer);

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
            _logger.LogWarning(
                "gRPC rate limit exceeded: ClientIp={ClientIp}, Method={Method}, Limit={PermitLimit}/{WindowSeconds}s",
                clientIp, context.Method, _options.PermitLimitPerClient, _options.WindowSeconds);
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

    private static string ExtractClientIp(string peer)
    {
        // gRPC Peer format: "ipv4:1.2.3.4:12345" or "ipv6:[::1]:12345"
        if (string.IsNullOrEmpty(peer)) return peer;

        var colonIndex = peer.IndexOf(':');
        if (colonIndex < 0) return peer;

        var afterScheme = peer.AsSpan(colonIndex + 1);

        // IPv6: "ipv6:[::1]:12345" -> extract between brackets
        if (afterScheme.StartsWith("[" ))
        {
            var closeBracket = afterScheme.IndexOf(']');
            if (closeBracket > 0) return afterScheme.Slice(1, closeBracket - 1).ToString();
        }

        // IPv4: "ipv4:1.2.3.4:12345" -> extract between first and last colon
        var lastColon = afterScheme.LastIndexOf(':');
        if (lastColon > 0) return afterScheme.Slice(0, lastColon).ToString();

        return peer;
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
