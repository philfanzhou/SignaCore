namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The closed set of reasons a sign-in or session operation can fail. Every failure redirects to
/// the fixed failure page carrying one of these values; no other failure detail — and never a
/// code, state, token, or query string — reaches the browser.
/// </summary>
public enum SignaCoreSignInReason
{
    /// <summary>The Authority's Discovery document could not be read or did not validate.</summary>
    AuthorityUnreachable,

    /// <summary>The <c>returnUrl</c> was not a local absolute path.</summary>
    InvalidReturnUrl,

    /// <summary>The authorization response was malformed: a required single-valued parameter was
    /// missing, duplicated, or otherwise not usable.</summary>
    InvalidResponse,

    /// <summary>The user cancelled the sign-in (the authorization response's
    /// <c>error=access_denied</c>).</summary>
    AccessDenied,

    /// <summary>The response's <c>state</c> did not match a pending sign-in.</summary>
    StateMismatch,

    /// <summary>The response's <c>iss</c> did not equal the Discovery issuer.</summary>
    IssuerMismatch,

    /// <summary>The code could not be redeemed at the token endpoint.</summary>
    TokenExchangeFailed,

    /// <summary>The token response or the ID token failed validation.</summary>
    InvalidToken,

    /// <summary>The server-side ticket store rejected the new session (capacity reached).</summary>
    SessionStoreFull,

    /// <summary>The fixed reason of an expired or absent session; used by the session endpoint.</summary>
    RequiresReauthentication
}
