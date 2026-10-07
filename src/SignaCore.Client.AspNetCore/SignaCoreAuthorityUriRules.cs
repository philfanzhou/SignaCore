namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The shared URI rules of the integration: what a base Authority and a registered RedirectUri
/// may look like, and how two origin strings are compared. Only the Development and Testing
/// environments accept an explicit loopback HTTP origin (<c>127.0.0.1</c> / <c>[::1]</c>, never
/// <c>localhost</c>).
/// </summary>
internal static class SignaCoreAuthorityUriRules
{
    /// <summary>
    /// Whether a configured value is an acceptable base address: absolute, HTTPS (or an explicit
    /// loopback HTTP origin when the environment allows it), without path, query, fragment, or
    /// user info.
    /// </summary>
    internal static bool IsAcceptableAuthority(string? value, bool allowInsecureLoopback)
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

        return uri.Scheme == Uri.UriSchemeHttps
            || (allowInsecureLoopback && IsExplicitLoopbackHttp(uri));
    }

    /// <summary>
    /// Whether a configured value is an acceptable redirect URI: absolute HTTPS (or an explicit
    /// loopback HTTP origin when the environment allows it) with a non-empty path and without
    /// query, fragment, or user info.
    /// </summary>
    internal static bool IsAcceptableRedirectUri(string? value, bool allowInsecureLoopback)
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

        return uri.Scheme == Uri.UriSchemeHttps
            || (allowInsecureLoopback && IsExplicitLoopbackHttp(uri));
    }

    /// <summary>
    /// Whether a resolved endpoint from the Discovery document is acceptable: absolute, HTTPS (or
    /// an explicit loopback HTTP origin when the environment allows it), without user info or
    /// fragment.
    /// </summary>
    internal static bool IsAcceptableEndpointUri(string? value, bool allowInsecureLoopback)
    {
        if (string.IsNullOrWhiteSpace(value)
            || !Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || uri.UserInfo.Length > 0
            || uri.Fragment.Length > 0)
        {
            return false;
        }

        return uri.Scheme == Uri.UriSchemeHttps
            || (allowInsecureLoopback && IsExplicitLoopbackHttp(uri));
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

    private static bool IsExplicitLoopbackHttp(Uri uri) =>
        uri.Scheme == Uri.UriSchemeHttp
        && (uri.Host is "127.0.0.1" or "::1");
}
