using System.Net;

namespace SignaCore.Domain;

public class CallbackUrlValidator
{
    private readonly HashSet<string> _allowedDomains;
    private readonly bool _allowPrivateAddresses;
    private readonly bool _requireHttps;
    private readonly CallbackHostResolver _resolveHostAddressesAsync;

    public CallbackUrlValidator(
        IEnumerable<string>? allowedDomains = null,
        bool allowPrivateAddresses = true,
        bool requireHttps = false)
        : this(
            allowedDomains,
            allowPrivateAddresses,
            requireHttps,
            ResolveHostAddressesAsync)
    {
    }

    internal CallbackUrlValidator(
        IEnumerable<string>? allowedDomains,
        bool allowPrivateAddresses,
        bool requireHttps,
        CallbackHostResolver resolveHostAddressesAsync)
    {
        _allowedDomains = new HashSet<string>(
            allowedDomains ?? Enumerable.Empty<string>(),
            StringComparer.OrdinalIgnoreCase);
        _allowPrivateAddresses = allowPrivateAddresses;
        _requireHttps = requireHttps;
        _resolveHostAddressesAsync = resolveHostAddressesAsync;
    }

    public ValidationResult Validate(string callbackUrl)
    {
        if (!Uri.TryCreate(callbackUrl, UriKind.Absolute, out var uri))
        {
            return ValidationResult.Invalid("Callback URL is not a valid absolute URL");
        }

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            return ValidationResult.Invalid("Callback URL must use HTTP or HTTPS scheme");
        }

        if (_requireHttps && uri.Scheme != Uri.UriSchemeHttps)
        {
            return ValidationResult.Invalid("Callback URL must use HTTPS");
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            return ValidationResult.Invalid("Callback URL must not contain user information");
        }

        var host = uri.Host;

        if (_allowedDomains.Count > 0 && !_allowedDomains.Contains(host))
        {
            return ValidationResult.Invalid($"Callback domain '{host}' is not in the allowed domains list");
        }

        if (!_allowPrivateAddresses && IPAddress.TryParse(host, out var parsedIp))
        {
            if (IsNonPublicAddress(parsedIp))
            {
                return ValidationResult.Invalid("Callback URL must not point to a private/internal IP address");
            }
        }

        if (!_allowPrivateAddresses && !IPAddress.TryParse(host, out _))
        {
            var addresses = ResolveHostAddresses(host);
            if (addresses is null or { Length: 0 })
            {
                return ValidationResult.Invalid("Callback URL host could not be resolved");
            }

            if (addresses.Any(IsNonPublicAddress))
            {
                return ValidationResult.Invalid("Callback URL must not resolve to a private/internal IP address");
            }
        }

        return ValidationResult.Valid();
    }

    /// <summary>
    /// 异步验证回调 URL，避免同步 DNS 解析阻塞请求线程。
    /// </summary>
    public async Task<ValidationResult> ValidateAsync(
        string callbackUrl,
        CancellationToken cancellationToken = default)
    {
        if (!Uri.TryCreate(callbackUrl, UriKind.Absolute, out var uri))
        {
            return ValidationResult.Invalid("Callback URL is not a valid absolute URL");
        }

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            return ValidationResult.Invalid("Callback URL must use HTTP or HTTPS scheme");
        }

        if (_requireHttps && uri.Scheme != Uri.UriSchemeHttps)
        {
            return ValidationResult.Invalid("Callback URL must use HTTPS");
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            return ValidationResult.Invalid("Callback URL must not contain user information");
        }

        var host = uri.Host;

        if (_allowedDomains.Count > 0 && !_allowedDomains.Contains(host))
        {
            return ValidationResult.Invalid($"Callback domain '{host}' is not in the allowed domains list");
        }

        if (!_allowPrivateAddresses && IPAddress.TryParse(host, out var parsedIp))
        {
            if (IsNonPublicAddress(parsedIp))
            {
                return ValidationResult.Invalid("Callback URL must not point to a private/internal IP address");
            }
        }

        if (!_allowPrivateAddresses && !IPAddress.TryParse(host, out _))
        {
            var addresses = await _resolveHostAddressesAsync(host, cancellationToken);
            if (addresses is null or { Length: 0 })
            {
                return ValidationResult.Invalid("Callback URL host could not be resolved");
            }

            if (addresses.Any(IsNonPublicAddress))
            {
                return ValidationResult.Invalid("Callback URL must not resolve to a private/internal IP address");
            }
        }

        return ValidationResult.Valid();
    }

    internal delegate Task<IPAddress[]?> CallbackHostResolver(
        string host,
        CancellationToken cancellationToken);

    private static IPAddress[]? ResolveHostAddresses(string host)
    {
        try
        {
            return Dns.GetHostAddresses(host);
        }
        catch (System.Net.Sockets.SocketException)
        {
            return null;
        }
    }

    private static async Task<IPAddress[]?> ResolveHostAddressesAsync(
        string host,
        CancellationToken cancellationToken)
    {
        try
        {
            return await Dns.GetHostAddressesAsync(host, cancellationToken);
        }
        catch (System.Net.Sockets.SocketException)
        {
            return null;
        }
    }

    internal static bool IsNonPublicAddress(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6)
        {
            return IsNonPublicAddress(ip.MapToIPv4());
        }

        var bytes = ip.GetAddressBytes();

        switch (ip.AddressFamily)
        {
            case System.Net.Sockets.AddressFamily.InterNetwork:
                return bytes[0] switch
                {
                    10 => true,
                    100 => bytes[1] is >= 64 and <= 127,
                    172 => bytes[1] >= 16 && bytes[1] <= 31,
                    127 => true,
                    0 => true,
                    169 => bytes[1] == 254,
                    192 => (bytes[1] == 0 && bytes[2] is 0 or 2) ||
                           (bytes[1] == 88 && bytes[2] == 99) ||
                           bytes[1] == 168,
                    198 => bytes[1] is 18 or 19 ||
                           (bytes[1] == 51 && bytes[2] == 100),
                    203 => bytes[1] == 0 && bytes[2] == 113,
                    >= 224 => true,
                    _ => false
                };
            case System.Net.Sockets.AddressFamily.InterNetworkV6:
                return IPAddress.IPv6Any.Equals(ip) ||
                       IPAddress.IPv6Loopback.Equals(ip) ||
                       ip.IsIPv6LinkLocal ||
                       ip.IsIPv6SiteLocal ||
                       ip.IsIPv6Multicast ||
                       (bytes[0] & 0xfe) == 0xfc ||
                       IsIpv6DocumentationOrReserved(bytes);
            default:
                return false;
        }
    }

    private static bool IsIpv6DocumentationOrReserved(byte[] bytes) =>
        // ::/96 (IPv4-compatible and other reserved forms; mapped IPv4 was handled above).
        bytes[..12].All(value => value == 0) ||
        // 2001:2::/48 benchmark and 2001:db8::/32 documentation ranges.
        (bytes[0] == 0x20 && bytes[1] == 0x01 &&
         ((bytes[2] == 0x00 && bytes[3] == 0x02) ||
          (bytes[2] == 0x0d && bytes[3] == 0xb8)));

    public record ValidationResult(bool IsValid, string? ErrorMessage)
    {
        public static ValidationResult Valid() => new(true, null);
        public static ValidationResult Invalid(string error) => new(false, error);
    }
}
