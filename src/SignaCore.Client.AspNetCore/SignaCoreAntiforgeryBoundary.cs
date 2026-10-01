using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The user-neutral scope of the package's antiforgery boundary. Antiforgery binds every token
/// pair to the principal its issuer saw, so a pair issued while a consumer's pipeline presented
/// the session principal (for example when the package's scheme is the default scheme) would fail
/// validation at a stage that still sees an anonymous request — and vice versa. The package
/// therefore issues and validates every antiforgery pair with an unauthenticated principal in
/// place, which pins the pair to the per-browser cookie binding alone and makes the boundary
/// independent of whichever principal any pipeline stage happens to present. The session cookie,
/// the Strict-SameSite antiforgery cookie, and the pair's shared security family remain the
/// CSRF protection; the claims-based user binding adds no protection a cross-site request could
/// otherwise have defeated.
/// </summary>
internal static class SignaCoreAntiforgeryBoundary
{
    /// <summary>
    /// Runs <paramref name="operation"/> — one antiforgery issuance or validation — with the
    /// request's user temporarily replaced by an unauthenticated principal. The original user is
    /// always restored; the operation's result or exception passes through unchanged.
    /// </summary>
    /// <typeparam name="T">The operation's result, for example the issued token set.</typeparam>
    /// <param name="context">The request whose antiforgery pair is issued or validated.</param>
    /// <param name="operation">The antiforgery call to run user-neutrally.</param>
    internal static async Task<T> RunUserNeutralAsync<T>(
        HttpContext context,
        Func<Task<T>> operation)
    {
        var originalUser = context.User;
        context.User = new ClaimsPrincipal(new ClaimsIdentity());
        try
        {
            return await operation();
        }
        finally
        {
            context.User = originalUser;
        }
    }

    /// <summary>Issues the antiforgery token set user-neutrally; see the class summary.</summary>
    internal static Task<AntiforgeryTokenSet> GetAndStoreTokensUserNeutralAsync(
        this IAntiforgery antiforgery,
        HttpContext context) =>
        RunUserNeutralAsync(
            context,
            () => Task.FromResult(antiforgery.GetAndStoreTokens(context)));

    /// <summary>Validates the request's antiforgery pair user-neutrally; see the class summary.
    /// An invalid pair still throws <see cref="AntiforgeryValidationException"/>.</summary>
    internal static Task ValidateRequestUserNeutralAsync(
        this IAntiforgery antiforgery,
        HttpContext context) =>
        RunUserNeutralAsync<object?>(
            context,
            async () =>
            {
                await antiforgery.ValidateRequestAsync(context);
                return null;
            });
}
