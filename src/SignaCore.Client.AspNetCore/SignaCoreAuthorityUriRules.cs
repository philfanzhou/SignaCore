namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The shared URI rules of the integration: what a base Authority and a registered RedirectUri
/// may look like, and how two origin strings are compared. <c>http</c> and <c>https</c> are equal
/// inputs in every environment name (ADR 0008: transport security is a deployment decision), so
/// only the structural rules remain — no environment privilege, no loopback exception, and no
/// origin allowlist.
/// </summary>
internal static class SignaCoreAuthorityUriRules
{
    /// <summary>
    /// Whether a configured value is an acceptable base address: an absolute <c>http</c> or
    /// <c>https</c> URI without path, query, fragment, or user info.
    /// </summary>
    internal static bool IsAcceptableAuthority(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || !Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || uri.UserInfo.Length > 0
            || uri.Query.Length > 0
            || uri.Fragment.Length > 0
            || (uri.AbsolutePath is not "/" and not ""))
        {
            return false;
        }

        return uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp;
    }

    /// <summary>
    /// Whether a configured value is an acceptable redirect URI: an absolute <c>http</c> or
    /// <c>https</c> URI with a non-empty path and without query, fragment, or user info.
    /// </summary>
    internal static bool IsAcceptableRedirectUri(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || !Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || uri.UserInfo.Length > 0
            || uri.Query.Length > 0
            || uri.Fragment.Length > 0
            || string.IsNullOrEmpty(uri.AbsolutePath)
            || uri.AbsolutePath == "/")
        {
            return false;
        }

        return uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp;
    }

    /// <summary>
    /// Whether a resolved endpoint from the Discovery document is acceptable: an absolute
    /// <c>http</c> or <c>https</c> URI without user info or fragment.
    /// </summary>
    internal static bool IsAcceptableEndpointUri(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || !Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || uri.UserInfo.Length > 0
            || uri.Fragment.Length > 0)
        {
            return false;
        }

        return uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp;
    }

    /// <summary>Whether two origin strings denote the same origin (scheme and host
    /// case-insensitively, path byte-for-byte after trimming trailing slashes).</summary>
    internal static bool SameOrigin(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right))
        {
            return false;
        }

        if (!Uri.TryCreate(left.TrimEnd('/'), UriKind.Absolute, out var leftUri)
            || !Uri.TryCreate(right.TrimEnd('/'), UriKind.Absolute, out var rightUri))
        {
            return false;
        }

        return string.Equals(leftUri.Scheme, rightUri.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(leftUri.Host, rightUri.Host, StringComparison.OrdinalIgnoreCase)
            && leftUri.Port == rightUri.Port
            && string.Equals(
                leftUri.AbsolutePath.TrimEnd('/'),
                rightUri.AbsolutePath.TrimEnd('/'),
                StringComparison.Ordinal);
    }

    /// <summary>
    /// Whether two absolute URI strings share one origin triple — scheme, host, and port —
    /// with no path comparison. This is the trust boundary for the authority's Discovery
    /// endpoints: SignaCore publishes its endpoints under the issuer's root, so differing paths
    /// are a legal document shape, while any differing origin component would move token or key
    /// traffic to a second host the consumer never validated.
    /// </summary>
    internal static bool SameOriginTriple(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right))
        {
            return false;
        }

        if (!Uri.TryCreate(left.TrimEnd('/'), UriKind.Absolute, out var leftUri)
            || !Uri.TryCreate(right.TrimEnd('/'), UriKind.Absolute, out var rightUri))
        {
            return false;
        }

        return string.Equals(leftUri.Scheme, rightUri.Scheme, StringComparison.OrdinalIgnoreCase)
            && string.Equals(leftUri.Host, rightUri.Host, StringComparison.OrdinalIgnoreCase)
            && leftUri.Port == rightUri.Port;
    }
}
