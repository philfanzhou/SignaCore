namespace SignaCore.Host.Security;

/// <summary>
/// The isolated SignaCore identity cookie scheme (canonical <c>PS-18</c>). The cookie is only the
/// protected carrier of the opaque identity-session id; the session authority (<c>PS-04</c>) owns
/// the subject, authentication time/method, activity, and revocation facts, and none of them is
/// ever copied into the cookie.
/// </summary>
/// <remarks>
/// The shared ServiceMantle package fixes every default authentication scheme on the management
/// cookie, so every identity authentication, challenge, forbid, sign-in, sign-out, and identity
/// authorization policy must name <see cref="AuthenticationScheme"/> explicitly and must never
/// rely on the default scheme or the default-populated <c>HttpContext.User</c>. The identity
/// scheme also must not set a second Data Protection application name: both cookies ride the
/// fixed ServiceMantle application discriminator with the key ring in the shared encrypted store,
/// and isolation from the management cookie exists solely through the distinct
/// <see cref="DataProtectionPurpose"/>.
/// </remarks>
public static class IdentitySessionDefaults
{
    /// <summary>The identity cookie authentication scheme. Never a default scheme.</summary>
    public const string AuthenticationScheme = "SignaCore.IdentitySession";

    /// <summary>The identity authorization policy; it rides only the identity scheme.</summary>
    public const string Policy = "IdentitySession";

    /// <summary>The host-only identity cookie name fixed by canonical <c>PS-18</c>.</summary>
    public const string CookieName = "__Host-signacore_identity";

    /// <summary>
    /// The stable Data Protection purpose of the identity cookie. It is pinned here instead of
    /// derived from the scheme name so the protected payload stays readable across a scheme
    /// rename, and it never collides with the scheme-derived management purpose.
    /// </summary>
    public const string DataProtectionPurpose = "SignaCore.IdentitySession.v1";

    /// <summary>
    /// The single claim the protected identity payload carries: the opaque session id used to
    /// load the <c>PS-04</c> session authority.
    /// </summary>
    public const string SessionIdClaim = "identity_session_id";
}
