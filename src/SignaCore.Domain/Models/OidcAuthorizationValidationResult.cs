namespace SignaCore.Domain.Models;

/// <summary>
/// Closed set of reasons an authorization request is rejected locally, i.e. without any redirect.
/// <para>
/// These values exist for audit, metrics, and logs only. They must never reach a response body: an
/// unknown client, an inactive client, a client without the interactive capability, and an
/// unmatched redirect URI all produce one identical local response so the endpoint is not an
/// existence oracle.
/// </para>
/// </summary>
public static class OidcAuthorizationLocalReasons
{
    public const string ClientParameterCardinality = "client_parameter_cardinality";
    public const string RedirectParameterCardinality = "redirect_parameter_cardinality";
    public const string ClientIdShape = "client_id_shape";
    public const string ClientUnknown = "client_unknown";
    public const string ClientInactive = "client_inactive";
    public const string ClientNotInteractive = "client_not_interactive";
    public const string RedirectUriShape = "redirect_uri_shape";
    public const string RedirectUriUnmatched = "redirect_uri_unmatched";
}

/// <summary>
/// The closed English set of <c>error_description</c> values the authorization endpoint may place
/// in a safe redirect. No member contains a credential, an account or session identifier, raw
/// request input, an exception, or a stack trace.
/// </summary>
public static class OidcAuthorizationErrorDescriptions
{
    public const string DuplicateParameter = "A request parameter was supplied more than once.";
    public const string UnsupportedResponseType = "The response_type must be code.";
    public const string UnsupportedParameter = "The request contains a parameter this authorization server does not support.";
    public const string RequestObjectNotSupported = "This authorization server does not support request objects.";
    public const string RequestUriNotSupported = "This authorization server does not support request_uri.";
    public const string RegistrationNotSupported = "This authorization server does not support dynamic registration.";
    public const string MalformedState = "The state parameter is missing or malformed.";
    public const string MalformedNonce = "The nonce parameter is missing or malformed.";
    public const string MalformedCodeChallenge = "The code_challenge parameter is missing or malformed.";
    public const string UnsupportedCodeChallengeMethod = "The code_challenge_method must be S256.";
    public const string InvalidScope = "The requested scope is not permitted for this client.";
}

/// <summary>
/// The outcome of validating one authorization request. Exactly one of the three shapes applies.
/// </summary>
public abstract record OidcAuthorizationValidationResult
{
    private OidcAuthorizationValidationResult()
    {
    }

    /// <summary>
    /// No trustworthy redirect destination was established, so the caller must answer locally and
    /// must not emit a <c>Location</c> header.
    /// </summary>
    public sealed record LocalRejection(string Reason) : OidcAuthorizationValidationResult;

    /// <summary>
    /// The current client and the exact registered redirect URI both validated, so a protocol error
    /// may travel back to that URI.
    /// </summary>
    /// <param name="RegisteredRedirectUri">
    /// The canonical registered string, never the submitted one. They are ordinally equal here, but
    /// building the response from the registration keeps request bytes out of the destination.
    /// </param>
    /// <param name="State">
    /// The byte-for-byte echo of a state that satisfied <c>IN-05</c>, or <c>null</c> when the
    /// request supplied no usable state. An unvalidated state is never echoed.
    /// </param>
    public sealed record RedirectRejection(
        string ClientId,
        Guid ApplicationId,
        string RegisteredRedirectUri,
        string Error,
        string ErrorDescription,
        string? State) : OidcAuthorizationValidationResult;

    /// <summary>
    /// Every protocol field validated. The interactive flow itself is not implemented by this
    /// slice, so the caller still produces no authorization code and no success redirect.
    /// </summary>
    public sealed record Accepted(
        string ClientId,
        Guid ApplicationId,
        string RegisteredRedirectUri,
        string CanonicalScope,
        string State,
        string Nonce,
        string CodeChallenge) : OidcAuthorizationValidationResult;
}
