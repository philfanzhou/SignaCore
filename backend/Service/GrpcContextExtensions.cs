using Grpc.Core;

namespace QuantumZhou.Identity.Service;

public static class GrpcContextExtensions
{
    public static string? GetClientIp(this ServerCallContext context)
    {
        var forwardedIp = context.RequestHeaders
            .FirstOrDefault(h => h.Key.Equals("x-forwarded-for", StringComparison.OrdinalIgnoreCase))?.Value;
        if (!string.IsNullOrEmpty(forwardedIp))
            return forwardedIp.Split(',')[0].Trim();

        return ExtractIpFromPeer(context.Peer);
    }

    public static string? GetUserAgent(this ServerCallContext context)
    {
        return context.RequestHeaders
            .FirstOrDefault(h => h.Key.Equals("user-agent", StringComparison.OrdinalIgnoreCase))?.Value;
    }

    public static string? GetCorrelationId(this ServerCallContext context)
    {
        return context.RequestHeaders
            .FirstOrDefault(h => h.Key.Equals("x-correlation-id", StringComparison.OrdinalIgnoreCase))?.Value;
    }

    public static string? ExtractIpFromPeer(string? peer)
    {
        if (string.IsNullOrEmpty(peer))
            return null;

        if (peer.StartsWith("ipv4:"))
        {
            var withoutPrefix = peer[5..];
            var lastColon = withoutPrefix.LastIndexOf(':');
            return lastColon > 0 ? withoutPrefix[..lastColon] : withoutPrefix;
        }

        if (peer.StartsWith("ipv6:"))
        {
            var withoutPrefix = peer[5..];
            var lastBracket = withoutPrefix.LastIndexOf(']');
            if (lastBracket > 0)
                return withoutPrefix[..(lastBracket + 1)];
            return withoutPrefix;
        }

        return peer;
    }
}
