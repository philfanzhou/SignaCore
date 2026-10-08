namespace SignaCore.Host.Security;

/// <summary>
/// One request's carrier, derived only from the trusted effective request scheme (ADR 0008):
/// <c>https</c> rides the Secure prefixed carriers and plain <c>http</c> rides the neutral
/// non-Secure carriers. There is no allowlist, environment name, or opt-in — whether TLS reaches
/// the browser is a deployment decision made in front of the service.
/// </summary>
internal sealed record IdentityCookieProfile(bool PlainHttp)
{
    internal static readonly IdentityCookieProfile Https = new(false);
    internal static readonly IdentityCookieProfile Http = new(true);
    internal const string HttpScheme = "SignaCore.IdentitySession.Http";
    internal const string UnavailableScheme = "SignaCore.IdentitySession.Unavailable";
    internal const string HttpIdentityCookie = "signacore_http_identity";
    internal const string HttpCsrfCookie = "signacore_http_login_csrf";
    internal const string HttpIdentityPurpose = "SignaCore.IdentitySession.Http.v1";
    internal const string HttpCsrfPurpose = "SignaCore.LoginAntiforgery.Http.v1";
    internal string CsrfCookie => PlainHttp ? HttpCsrfCookie : LoginAntiforgeryDefaults.CookieName;
    internal CookieOptions CsrfOptions() => new()
    {
        Secure = !PlainHttp, HttpOnly = true, SameSite = SameSiteMode.Strict,
        Path = "/", Domain = null, IsEssential = true
    };
    internal static IdentityCookieProfile? Resolve(HttpContext context)
    {
        if (context.Request.IsHttps) return Https;
        return string.Equals(context.Request.Scheme, "http", StringComparison.OrdinalIgnoreCase)
            ? Http
            : null;
    }
    internal static string? Forward(HttpContext context) => Resolve(context) switch
    {
        { PlainHttp: true } => HttpScheme,
        { PlainHttp: false } => null,
        _ => UnavailableScheme
    };
}
