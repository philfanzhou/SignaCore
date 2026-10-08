namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The package's two cookie profiles and the one derivation every cookie-name suffix goes
/// through. The HTTPS profile is the historical default; the intranet HTTP profile is active
/// exactly while <see cref="SignaCoreHostedLoginOptions.IntranetHttpOrigins"/> resolves to a
/// non-empty set.
/// <para>
/// One invariant rules both profiles: a derived cookie name must itself satisfy every browser
/// rule its prefix implies — <c>__Host-</c> demands Secure, Path=/, and no Domain attribute;
/// <c>__Secure-</c> demands Secure — and a name must never carry a prefix its own attributes
/// cannot satisfy. In the HTTPS profile a <c>__Host-</c>-prefixed session name therefore derives
/// <c>__Secure-&lt;rest&gt;</c> names (the only prefix a scoped, Secure cookie may carry); every
/// other session name keeps the byte-for-byte historical derivation. In the intranet HTTP
/// profile no rewrite happens at all: the session name is used as configured (a name carrying
/// either prefix fails startup in this profile), the cookies are written without the Secure
/// attribute, and no prefix is ever introduced.
/// </para>
/// </summary>
internal static class SignaCoreCookieProfile
{
    /// <summary>
    /// Whether the intranet HTTP profile is active. An illegal list fails startup before this
    /// can matter; if one is ever observed at runtime (an unvalidated reload), it fails closed
    /// to the HTTPS profile.
    /// </summary>
    internal static bool IsIntranetHttp(SignaCoreHostedLoginOptions options) =>
        IntranetHttpOrigin.TryResolve(options.IntranetHttpOrigins, out var origins)
        && origins.Count > 0;

    /// <summary>Whether the package's cookies carry the Secure attribute under the active
    /// profile.</summary>
    internal static bool SecureCookies(SignaCoreHostedLoginOptions options) =>
        !IsIntranetHttp(options);

    /// <summary>
    /// The cookie name derived from the configured session-cookie name by appending one suffix
    /// (the login-binding suffix including its <c>&lt;state&gt;</c> part, or the logout-return
    /// suffix), honoring the prefix invariant of the active profile.
    /// </summary>
    internal static string DerivedCookieName(SignaCoreHostedLoginOptions options, string suffix)
    {
        // The intranet HTTP profile never rewrites: its cookies are not Secure, so no prefix
        // could be satisfied, and a session name carrying one fails startup in this profile.
        if (IsIntranetHttp(options))
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
