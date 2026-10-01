using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The scheme options of the package's session scheme: the standard scheme options, nothing
/// package-specific — every package setting lives in
/// <see cref="SignaCoreHostedLoginOptions"/>.
/// </summary>
internal sealed class SignaCoreSessionSchemeOptions : AuthenticationSchemeOptions;

/// <summary>
/// The session scheme's handler: it resolves a request's principal from the opaque session cookie
/// through the server-side ticket store. The ticket — and with it the access token and ID token —
/// never leaves the server. An absent cookie, an unknown key, and an expired ticket all answer
/// <c>NoResult</c>: the distinction is not observable. A challenge redirects to the package's
/// start endpoint; forbid is a plain 403, because a denial is the consumer's own decision.
/// </summary>
internal sealed class SignaCoreSessionAuthenticationHandler(
    IOptionsMonitor<SignaCoreSessionSchemeOptions> schemeOptions,
    IOptionsMonitor<SignaCoreHostedLoginOptions> loginOptions,
    ITicketStore ticketStore,
    ILoggerFactory loggerFactory,
    UrlEncoder urlEncoder)
    : AuthenticationHandler<SignaCoreSessionSchemeOptions>(
        schemeOptions, loggerFactory, urlEncoder)
{
    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var current = loginOptions.CurrentValue;
        if (!Request.Cookies.TryGetValue(current.SessionCookieName, out var key)
            || string.IsNullOrEmpty(key))
        {
            return AuthenticateResult.NoResult();
        }

        var ticket = await ticketStore.RetrieveAsync(key, Context.RequestAborted);
        if (ticket is null)
        {
            return AuthenticateResult.NoResult();
        }

        // The principal was verified from the ID token at sign-in; the session merely re-presents
        // it. Re-asserting the authentication type keeps Identity.IsAuthenticated true without
        // re-deriving anything.
        if (ticket.Principal.Identity is not { IsAuthenticated: true })
        {
            return AuthenticateResult.NoResult();
        }

        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(
                ticket.Principal.Claims,
                Scheme.Name,
                nameType: "name",
                roleType: "role"));
        var properties = new AuthenticationProperties
        {
            IssuedUtc = ticket.IssuedUtc,
            ExpiresUtc = ticket.ExpiresUtc
        };
        return AuthenticateResult.Success(
            new AuthenticationTicket(principal, properties, Scheme.Name));
    }

    /// <inheritdoc />
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var current = loginOptions.CurrentValue;
        var returnUrl = Request.PathBase + Request.Path;
        if (Request.QueryString.HasValue)
        {
            returnUrl += Request.QueryString.Value;
        }

        Response.Redirect(
            $"{current.Prefix}/{SignaCoreHostedLoginDefaults.StartPathSegment}"
            + $"?returnUrl={Uri.EscapeDataString(returnUrl)}");
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }
}
