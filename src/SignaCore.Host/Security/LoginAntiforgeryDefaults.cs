namespace SignaCore.Host.Security;

/// <summary>
/// The SignaCore-owned login antiforgery contract (canonical <c>PS-19</c>, form field
/// <c>IN-14</c>): a host-only secure cookie paired with a hidden form token, both protecting the
/// same per-browser secret under the dedicated <see cref="DataProtectionPurpose"/>.
/// </summary>
/// <remarks>
/// ASP.NET Core's <c>IAntiforgery</c> is deliberately not used. Its request token binds to the
/// default-populated <c>HttpContext.User</c>, which <c>PS-18</c> forbids the identity path to
/// depend on: an anonymous form render followed by a management-session POST (or the reverse)
/// would fail validation, so establishing or ending an admin session would break the login form.
/// It also writes its own <c>X-Frame-Options: SAMEORIGIN</c>, conflicting with the login page's
/// framing denial, and its global singleton options would occupy the application's single
/// antiforgery configuration. This service is principal-independent instead, and like the
/// identity cookie it rides the fixed ServiceMantle application discriminator and the shared
/// encrypted key ring — never a second application name — so any instance validates any other
/// instance's pair.
/// </remarks>
public static class LoginAntiforgeryDefaults
{
    /// <summary>The host-only antiforgery cookie name fixed by canonical <c>PS-19</c>.</summary>
    public const string CookieName = "__Host-signacore_login_csrf";

    /// <summary>The hidden form field carrying the request token (<c>IN-14</c>).</summary>
    public const string TokenFieldName = "__RequestVerificationToken";

    /// <summary>
    /// The stable Data Protection purpose of the login antiforgery pair. The <c>cookie</c> and
    /// <c>request</c> sub-purposes are derived from it, so neither value can stand in for the
    /// other and neither collides with the identity or management payload purposes.
    /// </summary>
    public const string DataProtectionPurpose = "SignaCore.LoginAntiforgery.v1";

    /// <summary>The CSPRNG secret length both protected values wrap.</summary>
    public const int SecretLength = 32;

    /// <summary>The <c>IN-14</c> upper bound of the submitted form token in characters.</summary>
    public const int MaxTokenLength = 2048;
}
