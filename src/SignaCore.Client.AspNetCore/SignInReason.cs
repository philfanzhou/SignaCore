namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The closed set of reasons a sign-in or session operation can fail. Every failure redirects to
/// the fixed failure page carrying one of these values; no other failure detail — and never a
/// code, state, token, or query string — reaches the browser.
/// </summary>
public enum SignInReason
{
    /// <summary>The Authority's Discovery document could not be read or did not validate.</summary>
    AuthorityUnreachable,

    /// <summary>The <c>returnUrl</c> was not a local absolute path.</summary>
    InvalidReturnUrl,

    /// <summary>The authorization response was malformed: a required single-valued parameter was
    /// missing, duplicated, or otherwise not usable.</summary>
    InvalidResponse,

    /// <summary>
    /// Legacy: a sign-in denial that the current package versions never produce. The paths that
    /// used to answer this value now distinguish <see cref="UserCanceled"/> (the user rejected
    /// the authorization at the hosted page) from <see cref="PreSignInDenied"/> (the optional
    /// pre-sign-in authorization gate denied, timed out, or failed). The value stays parseable
    /// so old failure-page links keep rendering.
    /// </summary>
    AccessDenied,

    /// <summary>The user cancelled the sign-in at the authority's authorization page (the
    /// upstream <c>error=access_denied</c> echo).</summary>
    UserCanceled,

    /// <summary>
    /// The optional pre-sign-in authorization gate denied the new session — the decision
    /// returned <c>Denied</c>, timed out, or failed; the gate never distinguishes its internal
    /// failure shapes to the browser.
    /// </summary>
    PreSignInDenied,

    /// <summary>The response's <c>state</c> did not match a pending sign-in.</summary>
    StateMismatch,

    /// <summary>The response's <c>iss</c> did not equal the Discovery issuer.</summary>
    IssuerMismatch,

    /// <summary>The code could not be redeemed at the token endpoint.</summary>
    TokenExchangeFailed,

    /// <summary>The token response, ID token, or gated access token/correlation failed validation.</summary>
    InvalidToken,

    /// <summary>The server-side ticket store rejected the new session (capacity reached).</summary>
    SessionStoreFull,

    /// <summary>The fixed reason of an expired or absent session; used by the session endpoint.</summary>
    RequiresReauthentication
}

/// <summary>
/// The single string↔enum table of the <see cref="SignInReason"/> wire names. The
/// failure page writes and the failure-page reader parse through these accessors so the two
/// directions can never drift apart: an unknown wire name parses to <c>null</c>, and an
/// out-of-range enum value renders as <see cref="SignInReason.InvalidResponse"/>.
/// </summary>
internal static class SignInReasonWireNames
{
    private static readonly IReadOnlyDictionary<SignInReason, string> WireNames =
        new Dictionary<SignInReason, string>
        {
            [SignInReason.AuthorityUnreachable] = "authority_unreachable",
            [SignInReason.InvalidReturnUrl] = "invalid_return_url",
            [SignInReason.InvalidResponse] = "invalid_response",
            [SignInReason.AccessDenied] = "access_denied",
            [SignInReason.UserCanceled] = "user_canceled",
            [SignInReason.PreSignInDenied] = "pre_sign_in_denied",
            [SignInReason.StateMismatch] = "state_mismatch",
            [SignInReason.IssuerMismatch] = "issuer_mismatch",
            [SignInReason.TokenExchangeFailed] = "token_exchange_failed",
            [SignInReason.InvalidToken] = "invalid_token",
            [SignInReason.SessionStoreFull] = "session_store_full",
            [SignInReason.RequiresReauthentication] = "requires_reauthentication"
        };

    private static readonly IReadOnlyDictionary<string, SignInReason> ReasonsByWireName =
        WireNames.ToDictionary(
            pair => pair.Value,
            pair => pair.Key,
            StringComparer.Ordinal);

    internal static string ToWireName(SignInReason reason) =>
        WireNames.TryGetValue(reason, out var wireName) ? wireName : "invalid_response";

    internal static SignInReason? FromWireName(string? value) =>
        value is not null && ReasonsByWireName.TryGetValue(value, out var reason)
            ? reason
            : null;
}
