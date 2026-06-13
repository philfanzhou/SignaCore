using System.Net;

namespace QuantumZhou.Identity.Domain;

public class CallbackUrlValidator
{
    private readonly HashSet<string> _allowedDomains;
    private readonly bool _allowPrivateAddresses;

    public CallbackUrlValidator(IEnumerable<string>? allowedDomains = null, bool allowPrivateAddresses = false)
    {
        _allowedDomains = new HashSet<string>(
            allowedDomains ?? Enumerable.Empty<string>(),
            StringComparer.OrdinalIgnoreCase);
        _allowPrivateAddresses = allowPrivateAddresses;
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

        var host = uri.Host;

        if (!_allowPrivateAddresses && IPAddress.TryParse(host, out _))
        {
            return ValidationResult.Invalid("Callback URL must use a domain name, not an IP address");
        }

        if (!_allowPrivateAddresses && IsPrivateIpAddress(host))
        {
            return ValidationResult.Invalid("Callback URL must not resolve to a private/internal IP address");
        }

        if (_allowedDomains.Count > 0 && !_allowedDomains.Contains(host))
        {
            return ValidationResult.Invalid($"Callback domain '{host}' is not in the allowed domains list");
        }

        return ValidationResult.Valid();
    }

    private static bool IsPrivateIpAddress(string host)
    {
        try
        {
            var ipAddresses = Dns.GetHostAddresses(host);
            foreach (var ip in ipAddresses)
            {
                if (IsPrivateIpAddress(ip))
                {
                    return true;
                }
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    private static bool IsPrivateIpAddress(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();

        switch (ip.AddressFamily)
        {
            case System.Net.Sockets.AddressFamily.InterNetwork:
                return bytes[0] switch
                {
                    10 => true,
                    172 => bytes[1] >= 16 && bytes[1] <= 31,
                    192 => bytes[1] == 168,
                    127 => true,
                    0 => true,
                    169 => bytes[1] == 254,
                    _ => false
                };
            case System.Net.Sockets.AddressFamily.InterNetworkV6:
                return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal;
            default:
                return false;
        }
    }

    public record ValidationResult(bool IsValid, string? ErrorMessage)
    {
        public static ValidationResult Valid() => new(true, null);
        public static ValidationResult Invalid(string error) => new(false, error);
    }
}
