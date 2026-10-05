using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SignaCore.Domain.Validators;

/// <summary>Strict literal private-IP origin parsing shared by registration and host policy.</summary>
public static class HostedLoginHttpTestOrigin
{
    public static bool TryCanonicalize(string? value, out string origin)
    {
        origin = string.Empty;
        if (value is null || !value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) return false;
        var authority = value[7..];
        if (authority.Length == 0 || authority.Any(character =>
                character is '/' or '\\' or '?' or '#' or '@' or '%' || char.IsWhiteSpace(character))) return false;
        string host;
        string portText;
        bool ipv6;
        if (authority[0] == '[')
        {
            var end = authority.IndexOf(']');
            if (end <= 1 || end + 1 >= authority.Length || authority[end + 1] != ':') return false;
            host = authority[1..end];
            portText = authority[(end + 2)..];
            ipv6 = true;
        }
        else
        {
            var separator = authority.IndexOf(':');
            if (separator <= 0) return false;
            host = authority[..separator];
            portText = authority[(separator + 1)..];
            ipv6 = false;
            var parts = host.Split('.');
            if (parts.Length != 4 || parts.Any(part => part.Length is 0 or > 3
                    || (part.Length > 1 && part[0] == '0') || !part.All(char.IsAsciiDigit))) return false;
        }
        if (portText.Length == 0 || !portText.All(char.IsAsciiDigit)
            || !int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out var port)
            || port is < 1 or > 65535 || !IPAddress.TryParse(host, out var address)) return false;
        var bytes = address.GetAddressBytes();
        if (ipv6)
        {
            if (address.AddressFamily != AddressFamily.InterNetworkV6 || address.IsIPv4MappedToIPv6
                || (bytes[0] & 0xfe) != 0xfc) return false;
            host = "[" + address.ToString().ToLowerInvariant() + "]";
        }
        else
        {
            if (address.AddressFamily != AddressFamily.InterNetwork
                || !(bytes[0] == 10 || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
                     || (bytes[0] == 192 && bytes[1] == 168))) return false;
            host = address.ToString();
        }
        origin = "http://" + host + ":" + port.ToString(CultureInfo.InvariantCulture);
        return true;
    }
}
