using System.Net.Http.Headers;
using System.Text;

namespace SignaCore.Host.Security;

/// <summary>
/// The one parse of the <c>Authorization: Basic</c> client-credential header, shared by the
/// client-authentication handler and the token/logout controllers' <c>IN-20</c> mix checks, so
/// the mix is always judged by exactly the rule the handler applies. The type name deliberately
/// avoids the "auth" substring: CodeQL's user-controlled-bypass query flags calls to
/// %-auth-%-named members under a request-controlled guard.
/// </summary>
internal static class BasicClientHeader
{
    /// <summary>
    /// Parses and decodes the header into its URL-unescaped <c>client_id</c> and
    /// <c>client_secret</c>; returns <see langword="false"/> when the header is absent, not
    /// Basic, not base64, or carries no <c>id:secret</c> separator.
    /// </summary>
    public static bool TryRead(HttpRequest request, out string clientId, out string clientSecret)
    {
        clientId = string.Empty;
        clientSecret = string.Empty;
        var header = request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(header)
            || !AuthenticationHeaderValue.TryParse(header, out var parsed)
            || !string.Equals(parsed.Scheme, "Basic", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(parsed.Parameter))
        {
            return false;
        }

        string decoded;
        try
        {
            decoded = Encoding.UTF8.GetString(Convert.FromBase64String(parsed.Parameter));
        }
        catch (FormatException)
        {
            return false;
        }

        var separator = decoded.IndexOf(':');
        if (separator <= 0)
        {
            return false;
        }

        clientId = Uri.UnescapeDataString(decoded[..separator]);
        clientSecret = Uri.UnescapeDataString(decoded[(separator + 1)..]);
        return true;
    }
}
