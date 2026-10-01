using Microsoft.AspNetCore.Antiforgery;

namespace SignaCore.ReferenceBff;

/// <summary>
/// The sample's user-neutral antiforgery scope, mirroring the client package's boundary: every
/// antiforgery pair the sample issues or validates runs with an unauthenticated principal in
/// place, so the pair binds to the per-browser cookie alone and stays interchangeable across the
/// package's endpoints (<c>/bff/csrf</c>, the session CSRF boundary, the prepared logout) and the
/// sample's own Setup surface, whatever principal the surrounding pipeline presents.
/// </summary>
internal static class BffAntiforgery
{
    /// <summary>Issues one antiforgery token set with its cookie, user-neutrally.</summary>
    internal static AntiforgeryTokenSet Issue(HttpContext http, IAntiforgery antiforgery)
    {
        var originalUser = http.User;
        http.User = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity());
        try
        {
            return antiforgery.GetAndStoreTokens(http);
        }
        finally
        {
            http.User = originalUser;
        }
    }

    /// <summary>
    /// Validates the request's antiforgery pair, user-neutrally. An invalid pair still throws
    /// <see cref="AntiforgeryValidationException"/>.
    /// </summary>
    internal static async Task ValidateAsync(HttpContext http, IAntiforgery antiforgery)
    {
        var originalUser = http.User;
        http.User = new System.Security.Claims.ClaimsPrincipal(
            new System.Security.Claims.ClaimsIdentity());
        try
        {
            await antiforgery.ValidateRequestAsync(http);
        }
        finally
        {
            http.User = originalUser;
        }
    }
}
