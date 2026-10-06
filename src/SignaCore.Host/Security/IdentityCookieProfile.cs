namespace SignaCore.Host.Security;

/// <summary>One request's carrier, based only on the trusted effective request origin.</summary>
internal sealed record IdentityCookieProfile(bool HttpTest)
{
    internal static readonly IdentityCookieProfile Https = new(false);
    internal static readonly IdentityCookieProfile Test = new(true);
    internal const string TestScheme = "SignaCore.IdentitySession.HttpTest";
    internal const string UnavailableScheme = "SignaCore.IdentitySession.Unavailable";
    internal const string TestIdentityCookie = "signacore_http_test_identity";
    internal const string TestCsrfCookie = "signacore_http_test_login_csrf";
    internal const string TestIdentityPurpose = "SignaCore.IdentitySession.HttpTest.v1";
    internal const string TestCsrfPurpose = "SignaCore.LoginAntiforgery.HttpTest.v1";
    internal string CsrfCookie => HttpTest ? TestCsrfCookie : LoginAntiforgeryDefaults.CookieName;
    internal CookieOptions CsrfOptions() => new()
    {
        Secure = !HttpTest, HttpOnly = true, SameSite = SameSiteMode.Strict,
        Path = "/", Domain = null, IsEssential = true
    };
    internal static IdentityCookieProfile? Resolve(HttpContext context)
    {
        if (context.Request.IsHttps) return Https;
        if (!string.Equals(context.Request.Scheme, "http", StringComparison.OrdinalIgnoreCase)) return null;
        var policy = context.RequestServices.GetService<HostedLoginHttpTestPolicy>();
        var authority = context.Request.Host.Value ?? string.Empty;
        var hasPort = authority.StartsWith('[') ? !authority.EndsWith(']') : authority.Contains(':');
        return policy?.ContainsOrigin("http://" + authority + (hasPort ? "" : ":80")) == true ? Test : null;
    }
    internal static string? Forward(HttpContext context) => Resolve(context) switch
    {
        { HttpTest: true } => TestScheme,
        { HttpTest: false } => null,
        _ => UnavailableScheme
    };
}
