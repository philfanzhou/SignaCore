using System.Globalization;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The shared URI rules of the integration: what a base Authority and a registered RedirectUri
/// may look like, and how two origin strings are compared. Only the Development and Testing
/// environments accept an explicit loopback HTTP origin (<c>127.0.0.1</c> / <c>[::1]</c>, never
/// <c>localhost</c>). A non-empty <see cref="SignaCoreHostedLoginOptions.IntranetHttpOrigins"/>
/// list additionally admits exactly its configured intranet HTTP origins, in every environment
/// name, without waiving any full-URI rule.
/// </summary>
internal static class SignaCoreAuthorityUriRules
{
    /// <summary>
    /// Whether a configured value is an acceptable base address: absolute, HTTPS (or an explicit
    /// loopback HTTP origin when the environment allows it), without path, query, fragment, or
    /// user info. An origin-exact hit in the configured intranet list additionally admits plain
    /// HTTP; every full-URI rule above still applies unchanged.
    /// </summary>
    internal static bool IsAcceptableAuthority(
        string? value, bool allowInsecureLoopback, IReadOnlySet<string>? intranetHttpOrigins = null)
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
            || (allowInsecureLoopback && IsExplicitLoopbackHttp(uri))
            || IsExplicitIntranetHttp(uri, intranetHttpOrigins);
    }

    /// <summary>
    /// Whether a configured value is an acceptable redirect URI: absolute HTTPS (or an explicit
    /// loopback HTTP origin when the environment allows it) with a non-empty path and without
    /// query, fragment, or user info. An origin-exact hit in the configured intranet list
    /// additionally admits plain HTTP; every full-URI rule above still applies unchanged.
    /// </summary>
    internal static bool IsAcceptableRedirectUri(
        string? value, bool allowInsecureLoopback, IReadOnlySet<string>? intranetHttpOrigins = null)
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
            || (allowInsecureLoopback && IsExplicitLoopbackHttp(uri))
            || IsExplicitIntranetHttp(uri, intranetHttpOrigins);
    }

    /// <summary>
    /// Whether a resolved endpoint from the Discovery document is acceptable: absolute, HTTPS (or
    /// an explicit loopback HTTP origin when the environment allows it), without user info or
    /// fragment. An origin-exact hit in the configured intranet list additionally admits plain
    /// HTTP; every full-URI rule above still applies unchanged.
    /// </summary>
    internal static bool IsAcceptableEndpointUri(
        string? value, bool allowInsecureLoopback, IReadOnlySet<string>? intranetHttpOrigins = null)
    {
        if (string.IsNullOrWhiteSpace(value)
            || !Uri.TryCreate(value, UriKind.Absolute, out var uri)
            || uri.UserInfo.Length > 0
            || uri.Fragment.Length > 0)
        {
            return false;
        }

        return uri.Scheme == Uri.UriSchemeHttps
            || (allowInsecureLoopback && IsExplicitLoopbackHttp(uri))
            || IsExplicitIntranetHttp(uri, intranetHttpOrigins);
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

    /// <summary>
    /// Whether a parsed URI sits on one of the explicitly configured intranet HTTP origins. The
    /// set holds canonical <c>http://host:port</c> spellings; the URI's own origin is rebuilt in
    /// the same spelling (bracketed IPv6 — <see cref="Uri.Host"/> already returns brackets for
    /// IPv6 literals — and the invariant port) so the comparison is exact: a nearby origin
    /// (another port, another host) never matches.
    /// </summary>
    private static bool IsExplicitIntranetHttp(Uri uri, IReadOnlySet<string>? intranetHttpOrigins)
    {
        if (intranetHttpOrigins is not { Count: > 0 } || uri.Scheme != Uri.UriSchemeHttp)
        {
            return false;
        }

        var host = uri.HostNameType == UriHostNameType.IPv6 && !uri.Host.StartsWith('[')
            ? "[" + uri.Host + "]"
            : uri.Host;
        return intranetHttpOrigins.Contains(
            "http://" + host + ":" + uri.Port.ToString(CultureInfo.InvariantCulture));
    }
}
