using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// Strict literal private-IP HTTP origin parsing for the explicit intranet deployment opt-in
/// (<see cref="SignaCoreHostedLoginOptions.IntranetHttpOrigins"/>). An entry is
/// <c>http://</c> plus an RFC 1918 IPv4 literal (10/8, 172.16/12, 192.168/16, no leading zeros)
/// or a bracketed IPv6 Unique Local Address literal (fc00::/7, IPv4-mapped addresses rejected),
/// plus an explicit port 1–65535 — nothing else: no user info, path, query, fragment, percent
/// escapes, whitespace, domain names, or public addresses, and parsing never resolves a network
/// name. The grammar is byte-for-byte the SignaCore host's authoritative
/// <c>HostedLoginHttpTestOrigin</c> parser; per ADR 0007 the package must not reference a server
/// assembly, so the same semantics are implemented here.
/// </summary>
internal static class IntranetHttpOrigin
{
    /// <summary>Canonicalizes one configured origin; the output is the normalized
    /// <c>http://host:port</c> spelling (lowercase IPv6, no IPv4 aliases).</summary>
    internal static bool TryCanonicalize(string? value, out string origin)
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

    /// <summary>
    /// Canonicalizes the whole configured list into one set. Every member must canonicalize, and
    /// two members that normalize to the same origin are a duplicate configuration error — the
    /// caller's failure names the option, never a configured value.
    /// </summary>
    internal static bool TryResolve(IEnumerable<string?>? values, out HashSet<string> origins)
    {
        origins = new(StringComparer.Ordinal);
        if (values is null) return true;
        foreach (var value in values)
        {
            if (!TryCanonicalize(value, out var origin) || !origins.Add(origin)) return false;
        }

        return true;
    }
}
