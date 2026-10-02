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
/// <c>NoResult</c>: the distinction is not observable. A request authenticated by the session
/// cookie with an unsafe method must additionally pass antiforgery validation — the CSRF boundary
/// of the hosted session; a missing or wrong token fails the whole authentication. Requests a
/// consumer's <see cref="SignaCoreHostedLoginOptions.SchemeSelector"/> forwards to its own scheme
/// (typically Bearer) never pass through here and stay unaffected. A challenge redirects to the
/// package's start endpoint; forbid is a plain 403, because a denial is the consumer's own
/// decision.
/// </summary>
internal sealed class SignaCoreSessionAuthenticationHandler(
    IOptionsMonitor<SignaCoreSessionSchemeOptions> schemeOptions,
    IOptionsMonitor<SignaCoreHostedLoginOptions> loginOptions,
    ITicketStore ticketStore,
    Microsoft.AspNetCore.Antiforgery.IAntiforgery antiforgery,
    ILoggerFactory loggerFactory,
    UrlEncoder urlEncoder)
    : AuthenticationHandler<SignaCoreSessionSchemeOptions>(
        schemeOptions, loggerFactory, urlEncoder)
{
    /// <summary>
    /// The per-request marker of a failed antiforgery validation. It tells the challenge path to
    /// answer one fixed 403 instead of redirecting the browser to the sign-in start: a request
    /// that failed the CSRF boundary must not silently trigger a re-authentication round-trip.
    /// </summary>
    internal const string CsrfFailedItemKey = "SignaCoreHostedLogin.CsrfFailed";

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

        // The CSRF boundary: a session-authenticated unsafe method must present a valid
        // antiforgery token (header or form field, as configured). Failing the authentication —
        // not merely hiding it — keeps the request from reaching any authorization policy. The
        // validation is user-neutral (see SignaCoreAntiforgeryBoundary): the ambient principal at
        // this stage is whatever the consumer's pipeline presented, which must not decide the
        // pair's validity.
        if (!IsSafeMethod(Request.Method))
        {
            try
            {
                await antiforgery.ValidateRequestUserNeutralAsync(Context);
            }
            catch (Microsoft.AspNetCore.Antiforgery.AntiforgeryValidationException)
            {
                Context.Items[CsrfFailedItemKey] = true;
                return AuthenticateResult.Fail("The session request failed antiforgery validation.");
            }
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
        // A failed antiforgery validation answers one fixed 403: redirecting the browser to the
        // sign-in start would turn a cross-site write into a silent re-authentication round-trip.
        if (Context.Items.ContainsKey(CsrfFailedItemKey))
        {
            Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }

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

    /// <summary>
    /// The RFC 9110 safe methods: GET, HEAD, OPTIONS, and TRACE. Everything else — POST, PUT,
    /// PATCH, DELETE, and any extension method — must carry an antiforgery token.
    /// </summary>
    private static bool IsSafeMethod(string method) =>
        HttpMethods.IsGet(method)
        || HttpMethods.IsHead(method)
        || HttpMethods.IsOptions(method)
        || HttpMethods.IsTrace(method);
}
