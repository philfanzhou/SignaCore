using System.Globalization;
using SignaCore.Database;
using SignaCore.Domain.Models;

namespace SignaCore.Domain.Validators;

public static class OidcRedirectUriValidator
{
    public static IReadOnlyList<OidcRedirectUri> ValidateAndCanonicalize(
        IEnumerable<string> values,
        bool isDevelopment)
    {
        ArgumentNullException.ThrowIfNull(values);

        var canonicalUris = new List<OidcRedirectUri>();
        var uniqueValues = new HashSet<string>(StringComparer.Ordinal);

        foreach (var value in values)
        {
            if (canonicalUris.Count == IdentityConstants.MaxOidcRedirectUrisPerKind)
            {
                throw new OidcClientConfigurationException(
                    "A redirect URI set cannot contain more than ten values.");
            }

            var canonical = Canonicalize(value, isDevelopment);
            if (!uniqueValues.Add(canonical))
            {
                throw new OidcClientConfigurationException(
                    "A redirect URI set contains a duplicate canonical value.");
            }

            canonicalUris.Add(new OidcRedirectUri(canonical));
        }

        return canonicalUris;
    }

    public static OidcRedirectUri ValidateAndCanonicalize(
        string value,
        bool isDevelopment)
    {
        return new OidcRedirectUri(Canonicalize(value, isDevelopment));
    }

    private static string Canonicalize(string value, bool isDevelopment)
    {
        if (string.IsNullOrEmpty(value)
            || value.Length > IdentityConstants.MaxOidcRedirectUriLength
            || value.Any(character => character <= 0x20 || character >= 0x7f)
            || !HasValidPercentEncoding(value))
        {
            throw InvalidUri();
        }

        if (value.Contains('*', StringComparison.Ordinal)
            || value.Contains('\\', StringComparison.Ordinal)
            || value.Contains('#', StringComparison.Ordinal))
        {
            throw InvalidUri();
        }

        var schemeSeparator = value.IndexOf("://", StringComparison.Ordinal);
        if (schemeSeparator <= 0)
        {
            throw InvalidUri();
        }

        var rawScheme = value[..schemeSeparator];
        if (!IsValidScheme(rawScheme))
        {
            throw InvalidUri();
        }

        var scheme = rawScheme.ToLowerInvariant();
        if (scheme is not ("https" or "http"))
        {
            throw InvalidUri();
        }

        var authorityStart = schemeSeparator + 3;
        var authorityEnd = value.IndexOfAny(['/', '?'], authorityStart);
        if (authorityEnd < 0)
        {
            authorityEnd = value.Length;
        }

        var rawAuthority = value[authorityStart..authorityEnd];
        if (rawAuthority.Length == 0 || rawAuthority.Contains('@', StringComparison.Ordinal))
        {
            throw InvalidUri();
        }

        var (rawHost, rawPort, port) = ParseAuthority(rawAuthority);
        if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed)
            || string.IsNullOrEmpty(parsed.Host)
            || parsed.UserInfo.Length != 0
            || parsed.Scheme is not ("http" or "https"))
        {
            throw InvalidUri();
        }

        var host = rawHost.ToLowerInvariant();
        if (host.TrimEnd('.').Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            throw InvalidUri();
        }

        if (scheme == "http"
            && (!isDevelopment
                || (host != "127.0.0.1" && host != "[::1]")))
        {
            throw InvalidUri();
        }

        var includePort = rawPort is not null
            && !((scheme == "https" && port == 443) || (scheme == "http" && port == 80));
        var remainder = value[authorityEnd..];
        if (remainder.Length == 0)
        {
            remainder = "/";
        }
        else if (remainder[0] == '?')
        {
            remainder = "/" + remainder;
        }

        return string.Concat(
            scheme,
            "://",
            host,
            includePort ? ":" + rawPort : string.Empty,
            remainder);
    }

    private static (string Host, string? RawPort, int? Port) ParseAuthority(string authority)
    {
        string host;
        string? rawPort = null;

        if (authority[0] == '[')
        {
            var closeBracket = authority.IndexOf(']');
            if (closeBracket <= 1)
            {
                throw InvalidUri();
            }

            host = authority[..(closeBracket + 1)];
            var suffix = authority[(closeBracket + 1)..];
            if (suffix.Length > 0)
            {
                if (suffix[0] != ':' || suffix.Length == 1)
                {
                    throw InvalidUri();
                }

                rawPort = suffix[1..];
            }
        }
        else
        {
            var colon = authority.LastIndexOf(':');
            if (colon >= 0)
            {
                if (authority.IndexOf(':') != colon || colon == 0 || colon == authority.Length - 1)
                {
                    throw InvalidUri();
                }

                host = authority[..colon];
                rawPort = authority[(colon + 1)..];
            }
            else
            {
                host = authority;
            }
        }

        if (host.Length == 0)
        {
            throw InvalidUri();
        }

        int? port = null;
        if (rawPort is not null)
        {
            if (!rawPort.All(char.IsAsciiDigit)
                || !int.TryParse(rawPort, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedPort)
                || parsedPort > 65535)
            {
                throw InvalidUri();
            }

            port = parsedPort;
        }

        return (host, rawPort, port);
    }

    private static bool IsValidScheme(string scheme)
    {
        return char.IsAsciiLetter(scheme[0])
            && scheme[1..].All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '+' or '-' or '.');
    }

    private static bool HasValidPercentEncoding(string value)
    {
        for (var index = 0; index < value.Length; index++)
        {
            if (value[index] != '%')
            {
                continue;
            }

            if (index + 2 >= value.Length
                || !char.IsAsciiHexDigit(value[index + 1])
                || !char.IsAsciiHexDigit(value[index + 2]))
            {
                return false;
            }

            index += 2;
        }

        return true;
    }

    private static OidcClientConfigurationException InvalidUri()
    {
        return new OidcClientConfigurationException(
            "A redirect URI does not satisfy the registration policy.");
    }
}
