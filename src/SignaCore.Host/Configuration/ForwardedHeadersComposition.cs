using System.Net;
using ServiceMantle.Web;
using ServiceMantle.Configuration;

namespace SignaCore.Host.Configuration;

/// <summary>Projects the activated proxy setting into the shared immutable forwarding boundary.</summary>
internal static class ForwardedHeadersComposition
{
    internal const string SettingKey = "reverse_proxy.known_proxies";

    internal static ServiceMantleBuilder AddSignaCoreForwardedHeaders(
        this ServiceMantleBuilder builder, ServiceSettingSnapshot snapshot)
    {
        var proxies = snapshot.Values.TryGetValue(SettingKey, out var value) && value.HasValue
            ? value.GetJson().EnumerateArray().Select(item => item.GetString() ?? string.Empty)
            : [];
        return builder.AddSignaCoreForwardedHeaders(proxies);
    }

    internal static ServiceMantleBuilder AddSignaCoreForwardedHeaders(
        this ServiceMantleBuilder builder, IEnumerable<string> configuredProxies)
    {
        // Preserve ASP.NET Core's previous loopback defaults explicitly. The shared snapshot
        // clears framework defaults and must receive the complete trust boundary.
        var proxies = configuredProxies.Prepend("::1")
            .Select(value => IPAddress.TryParse(value, out var address) ? address.ToString() : value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return builder.AddForwardedHeaders(options =>
        {
            options.KnownProxies = proxies;
            options.KnownIPNetworks = ["127.0.0.0/8"];
            options.AllowedHosts = [];
            options.ForwardLimit = 1;
        });
    }
}
