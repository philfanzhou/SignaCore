using Microsoft.Extensions.Options;
using SignaCore.Client.AspNetCore;

namespace SignaCore.ReferenceBff;

/// <summary>
/// The local session teardown of the reference BFF, used by every surface that must end a dead
/// session itself (<c>/bff/me</c>, <c>/bff/admin</c>, and Setup). It works entirely through the
/// client package's public surface: the opaque session cookie names the key of the server-side
/// ticket, so removing the ticket and deleting the cookie is the whole local sign-out. The
/// prepared-logout endpoint of the package performs this same teardown itself.
/// </summary>
internal static class BffSession
{
    /// <summary>
    /// The opaque session-cookie name the sample has always issued; kept stable so the browser
    /// contract is unchanged by the move to the client package.
    /// </summary>
    internal const string CookieName = "signacore-bff-session";

    /// <summary>
    /// Revokes the browser's local session: the server-side ticket is removed first, then the
    /// cookie is deleted. An absent or unknown session is not an error — there is nothing to
    /// revoke, and no request input is ever echoed.
    /// </summary>
    internal static async Task RevokeAsync(HttpContext http, CancellationToken cancellationToken)
    {
        var current = http.RequestServices
            .GetRequiredService<IOptionsMonitor<SignaCoreHostedLoginOptions>>()
            .CurrentValue;
        if (http.Request.Cookies.TryGetValue(current.SessionCookieName, out var key)
            && !string.IsNullOrEmpty(key))
        {
            await http.RequestServices.GetRequiredService<ITicketStore>()
                .RemoveAsync(key, cancellationToken);
        }

        http.Response.Cookies.Append(current.SessionCookieName, string.Empty, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            Expires = DateTimeOffset.UnixEpoch,
            IsEssential = true
        });
    }
}
