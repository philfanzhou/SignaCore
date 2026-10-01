namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The well-known names of the hosted-login integration: the authentication scheme names, the
/// default session cookie, the route segments under the consumer's prefix, and the protocol
/// constants the package enforces.
/// </summary>
public static class SignaCoreHostedLoginDefaults
{
    /// <summary>
    /// The authentication scheme a consumer's routes authenticate against. It forwards each
    /// request either to the package's session scheme or, when the consumer sets
    /// <see cref="SignaCoreHostedLoginOptions.SchemeSelector"/>, to a scheme of its own
    /// (typically its Bearer handler).
    /// </summary>
    public const string AuthenticationScheme = "SignaCoreHostedLogin";

    /// <summary>The package's own session scheme: it resolves requests from the server-side ticket.</summary>
    public const string SessionAuthenticationScheme = "SignaCoreHostedLogin.Session";

    /// <summary>The default name of the opaque session cookie. HttpOnly, Secure, SameSite=Lax.</summary>
    public const string SessionCookieName = "signacore-hosted-login-session";

    /// <summary>The route segment of the sign-in start endpoint under the consumer's prefix.</summary>
    public const string StartPathSegment = "start";

    /// <summary>The route segment of the callback endpoint under the consumer's prefix.</summary>
    public const string CallbackPathSegment = "callback";

    /// <summary>The route segment of the session-status endpoint under the consumer's prefix.</summary>
    public const string SessionPathSegment = "session";

    /// <summary>The default route segment of the fixed sign-in failure page under the prefix.</summary>
    public const string FailurePathSegment = "signin-failed";

    /// <summary>The route segment of the antiforgery-token endpoint under the consumer's prefix.</summary>
    public const string CsrfPathSegment = "csrf";

    /// <summary>
    /// The route segment of the logout endpoint under the consumer's prefix. The segment also
    /// prefixes <see cref="LogoutReturnPathSegment"/>, so both endpoints share the logout-return
    /// cookie's path.
    /// </summary>
    public const string LogoutPathSegment = "logout";

    /// <summary>
    /// The route segment of the logout return endpoint under the consumer's prefix. This is the
    /// path the consumer registers in SignaCore as its post-logout redirect URI.
    /// </summary>
    public const string LogoutReturnPathSegment = "logout/return";

    /// <summary>
    /// The default request-header name the antiforgery validation accepts for session-authenticated
    /// unsafe methods and the package's logout endpoint. Configure through
    /// <see cref="SignaCoreHostedLoginOptions.AntiforgeryHeaderName"/>.
    /// </summary>
    public const string AntiforgeryHeaderName = "X-SignaCore-CSRF";

    /// <summary>
    /// The suffix appended to <see cref="SessionCookieName"/> to name the one-time logout-return
    /// correlation cookie: HttpOnly, Secure, SameSite=Lax, scoped to the package's logout paths,
    /// and alive for the five-minute prepared-logout window.
    /// </summary>
    public const string LogoutReturnCookieSuffix = "-logout-return";

    /// <summary>The lifetime of one prepared logout and of its return state: five minutes.</summary>
    public static readonly TimeSpan LogoutReturnLifetime = TimeSpan.FromMinutes(5);

    /// <summary>The only response type the package sends.</summary>
    public const string ResponseType = "code";

    /// <summary>The only PKCE transform the package sends.</summary>
    public const string CodeChallengeMethod = "S256";

    /// <summary>The name of the HTTP client the package uses for Discovery, JWKS, and the token endpoint.</summary>
    public const string HttpClientName = "SignaCoreHostedLogin";
}
