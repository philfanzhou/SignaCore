using SignaCore.Database;

namespace SignaCore.Domain.Validators;

/// <summary>Registration-time validation for Public SPA Origins.</summary>
public static class OidcAllowedOriginValidator
{
    public static IReadOnlyList<string> ValidateAndCanonicalize(
        IEnumerable<string> values,
        bool isDevelopment)
    {
        ArgumentNullException.ThrowIfNull(values);
        var result = new List<string>();
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in values)
        {
            if (result.Count == IdentityConstants.MaxOidcAllowedOrigins)
            {
                throw Invalid();
            }

            var canonical = Canonicalize(value, isDevelopment);
            if (!unique.Add(canonical))
            {
                throw Invalid();
            }

            result.Add(canonical);
        }

        return result;
    }

    private static string Canonicalize(string? value, bool isDevelopment)
    {
        if (string.IsNullOrEmpty(value)
            || value.Length > IdentityConstants.MaxOidcCanonicalOriginLength
            || value.Any(character => character <= 0x20 || character >= 0x7f)
            || value.Contains('%', StringComparison.Ordinal)
            || value.Contains('*', StringComparison.Ordinal)
            || value.Contains('\\', StringComparison.Ordinal)
            || value.Contains('@', StringComparison.Ordinal)
            || value.Contains('#', StringComparison.Ordinal)
            || value.Contains('?', StringComparison.Ordinal)
            || string.Equals(value, "null", StringComparison.OrdinalIgnoreCase))
        {
            throw Invalid();
        }

        var delimiter = value.IndexOf("://", StringComparison.Ordinal);
        if (delimiter <= 0 || value.IndexOf('/', delimiter + 3) >= 0)
        {
            throw Invalid();
        }

        var scheme = value[..delimiter];
        if (!scheme.Equals("https", StringComparison.OrdinalIgnoreCase)
            && !scheme.Equals("http", StringComparison.OrdinalIgnoreCase))
        {
            throw Invalid();
        }

        var authority = value[(delimiter + 3)..];
        if (authority.Length == 0 || authority.EndsWith(':'))
        {
            throw Invalid();
        }

        if (!Uri.TryCreate(value + "/", UriKind.Absolute, out var parsed)
            || !parsed.Scheme.Equals(scheme, StringComparison.OrdinalIgnoreCase)
            || parsed.HostNameType == UriHostNameType.Unknown
            || parsed.UserInfo.Length != 0
            || parsed.Port is < 1 or > 65535)
        {
            throw Invalid();
        }

        if (scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
            && (!isDevelopment
                || !(authority.Equals("127.0.0.1", StringComparison.Ordinal)
                    || authority.StartsWith("127.0.0.1:", StringComparison.Ordinal)
                    || authority.Equals("[::1]", StringComparison.Ordinal)
                    || authority.StartsWith("[::1]:", StringComparison.Ordinal))))
        {
            throw Invalid();
        }

        var canonical = parsed.GetLeftPart(UriPartial.Authority);
        if (canonical.Length > IdentityConstants.MaxOidcCanonicalOriginLength)
        {
            throw Invalid();
        }

        return canonical;
    }

    private static OidcClientConfigurationException Invalid() =>
        new("An allowed Origin must be a unique, canonical HTTPS host and port (development loopback HTTP is allowed), with at most ten entries.");
}
