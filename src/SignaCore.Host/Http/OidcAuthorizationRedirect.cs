using System.Text;

namespace SignaCore.Host.Http;

/// <summary>
/// The one builder of the <c>PS-17</c> redirects, shared by the authorize endpoint and the login
/// continuation flow: the exact registered URI plus the protocol fields in a fixed parameter order,
/// under one separator and escaping rule. <see cref="BuildError"/> carries <c>error</c>, a
/// closed-set English <c>error_description</c>, the byte-for-byte <c>state</c> when one was
/// validated, and the issuer; <see cref="BuildSuccess"/> carries the plaintext <c>code</c>, the
/// byte-for-byte <c>state</c> of the continuation snapshot, and the issuer. There is no fragment or
/// form-post response mode.
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

    /// <summary>
    /// Builds the <c>EV-01</c> success redirect: the exact registered URI plus <c>code</c>,
    /// <c>state</c>, and <c>iss</c>, in that fixed parameter order. The plaintext code appears
    /// here exactly once, only after its creation transaction has committed (<c>DF-03</c>).
    /// </summary>
    public static string BuildSuccess(
        string registeredRedirectUri,
        string code,
        string state,
        string issuer)
    {
        ArgumentNullException.ThrowIfNull(registeredRedirectUri);

        // The registered URI may already carry a query, which registration preserves verbatim.
        var separator = registeredRedirectUri.Contains('?', StringComparison.Ordinal)
            ? '&'
            : '?';

        var builder = new StringBuilder(registeredRedirectUri);
        builder.Append(separator);
        AppendParameter(builder, "code", code, first: true);
        // The IN-05 alphabet is exactly the URI unreserved set, so escaping leaves a valid
        // state unchanged and the client sees the bytes it sent.
        AppendParameter(builder, "state", state, first: false);
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
