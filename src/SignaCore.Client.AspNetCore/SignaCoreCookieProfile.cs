namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The package's two cookie profiles and the one derivation every cookie-name suffix goes
/// through. The profile follows the configured RedirectUri's scheme (ADR 0008: transport is a
/// deployment decision made in front of the application): an <c>https</c> redirect URI rides the
/// historical Secure profile, a plain-<c>http</c> redirect URI rides the neutral non-Secure
/// profile. The browser reaches the consumer exactly at the redirect URI, so that URI's scheme
/// is the scheme every carrier cookie is written under.
/// <para>
/// One invariant rules both profiles: a derived cookie name must itself satisfy every browser
/// rule its prefix implies — <c>__Host-</c> demands Secure, Path=/, and no Domain attribute;
/// <c>__Secure-</c> demands Secure — and a name must never carry a prefix its own attributes
/// cannot satisfy. In the HTTPS profile a <c>__Host-</c>-prefixed session name therefore derives
/// <c>__Secure-&lt;rest&gt;</c> names (the only prefix a scoped, Secure cookie may carry); every
/// other session name keeps the byte-for-byte historical derivation. In the plain-HTTP profile no
/// rewrite happens at all: the session name is used as configured (a name carrying either prefix
/// fails startup in this profile), the cookies are written without the Secure attribute, and no
/// prefix is ever introduced.
/// </para>
/// </summary>
internal static class SignaCoreCookieProfile
{
    /// <summary>
    /// Whether the plain-HTTP profile is active: the configured RedirectUri is served over
    /// plain <c>http</c>. A blank RedirectUri (optional sign-in mode) keeps the HTTPS profile.
    /// </summary>
    internal static bool IsPlainHttp(SignaCoreHostedLoginOptions options) =>
        Uri.TryCreate(options.RedirectUri, UriKind.Absolute, out var redirect)
        && redirect.Scheme == Uri.UriSchemeHttp;

    /// <summary>Whether the package's cookies carry the Secure attribute under the active
    /// profile.</summary>
    internal static bool SecureCookies(SignaCoreHostedLoginOptions options) =>
        !IsPlainHttp(options);

    /// <summary>
    /// The cookie name derived from the configured session-cookie name by appending one suffix
    /// (the login-binding suffix including its <c>&lt;state&gt;</c> part, or the logout-return
    /// suffix), honoring the prefix invariant of the active profile.
    /// </summary>
    internal static string DerivedCookieName(SignaCoreHostedLoginOptions options, string suffix)
    {
        // The plain-HTTP profile never rewrites: its cookies are not Secure, so no prefix
        // could be satisfied, and a session name carrying one fails startup in this profile.
        if (IsPlainHttp(options))
        {
            return options.SessionCookieName + suffix;
        }

        return options.SessionCookieName.StartsWith(
                SignaCoreHostedLoginDefaults.HostCookiePrefix, StringComparison.Ordinal)
            ? SignaCoreHostedLoginDefaults.SecureCookiePrefix
                + options.SessionCookieName[SignaCoreHostedLoginDefaults.HostCookiePrefix.Length..]
                + suffix
            : options.SessionCookieName + suffix;
    }
}
