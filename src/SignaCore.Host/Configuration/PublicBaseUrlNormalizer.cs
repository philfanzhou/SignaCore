namespace SignaCore.Host.Configuration;

/// <summary>
/// Normalizes a public base URL to the canonical form stored in <c>system_settings</c>: absolute,
/// no trailing slash, no user information, query, or fragment.
/// </summary>
internal static class PublicBaseUrlNormalizer
{
    public static bool TryNormalizeBaseUrl(
        string? candidate,
        out string normalized,
        out string reason)
    {
        normalized = string.Empty;
        reason = string.Empty;

        if (string.IsNullOrWhiteSpace(candidate))
        {
            reason = "is required.";
            return false;
        }

        var trimmed = candidate.Trim();
        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) ||
            string.IsNullOrWhiteSpace(uri.Host) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            reason = "must be an absolute http or https base URL without user information, " +
                     "query, or fragment.";
            return false;
        }

        normalized = trimmed.TrimEnd('/');
        return true;
    }
}
