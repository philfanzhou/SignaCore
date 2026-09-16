using System.Text;

namespace SignaCore.Host.Http;

/// <summary>
/// The one builder of <c>PS-17</c> safe error redirects, shared by the authorize endpoint and the
/// login continuation flow: the exact registered URI plus <c>error</c>, a closed-set English
/// <c>error_description</c>, the byte-for-byte <c>state</c> when one was validated, and the
/// issuer, in that fixed parameter order. There is no fragment or form-post response mode.
/// </summary>
public static class OidcAuthorizationRedirect
{
    public static string BuildError(
        string registeredRedirectUri,
        string error,
        string errorDescription,
        string? state,
        string issuer)
    {
        ArgumentNullException.ThrowIfNull(registeredRedirectUri);

        // The registered URI may already carry a query, which registration preserves verbatim.
        var separator = registeredRedirectUri.Contains('?', StringComparison.Ordinal)
            ? '&'
            : '?';

        var builder = new StringBuilder(registeredRedirectUri);
        builder.Append(separator);
        AppendParameter(builder, "error", error, first: true);
        AppendParameter(builder, "error_description", errorDescription, first: false);
        if (state is not null)
        {
            // The IN-05 alphabet is exactly the URI unreserved set, so escaping leaves a valid
            // state unchanged and the client sees the bytes it sent.
            AppendParameter(builder, "state", state, first: false);
        }

        AppendParameter(builder, "iss", issuer, first: false);
        return builder.ToString();
    }

    private static void AppendParameter(StringBuilder builder, string name, string value, bool first)
    {
        if (!first)
        {
            builder.Append('&');
        }

        builder.Append(name).Append('=').Append(Uri.EscapeDataString(value));
    }
}
