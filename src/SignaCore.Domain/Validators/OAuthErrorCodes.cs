namespace SignaCore.Domain.Validators;

/// <summary>
/// OAuth 2.0 token-endpoint error codes (RFC 6749 §5.2).
/// <para>
/// These live in the domain rather than the host because the decision "was this a bad credential or a
/// policy refusal?" is made by the validators. Mapping free-text failure messages back to codes in the
/// transport layer would mean string-matching prose that exists to be read by humans.
/// </para>
/// </summary>
public static class OAuthErrorCodes
{
    /// <summary>A required parameter is missing or malformed.</summary>
    public const string InvalidRequest = "invalid_request";

    /// <summary>Client authentication failed.</summary>
    public const string InvalidClient = "invalid_client";

    /// <summary>The credential, code, or refresh token is invalid, expired, or revoked.</summary>
    public const string InvalidGrant = "invalid_grant";

    /// <summary>The authenticated client is not allowed to use this grant type.</summary>
    public const string UnauthorizedClient = "unauthorized_client";

    /// <summary>The grant type is not supported by this authorization server.</summary>
    public const string UnsupportedGrantType = "unsupported_grant_type";

    /// <summary>The requested scope is invalid, unknown, or exceeds what the client may request.</summary>
    public const string InvalidScope = "invalid_scope";

    /// <summary>An unexpected condition prevented the request from being fulfilled.</summary>
    public const string ServerError = "server_error";

    /// <summary>The service is temporarily unable to handle the request.</summary>
    public const string TemporarilyUnavailable = "temporarily_unavailable";

    /// <summary>
    /// The resource owner or authorization server denied the request (RFC 6749 §4.1.2.1). The
    /// authorization endpoint uses it for an explicit login cancellation.
    /// </summary>
    public const string AccessDenied = "access_denied";

    /// <summary>
    /// The authorization server does not support obtaining an authorization code using this
    /// response type (RFC 6749 §4.1.2.1).
    /// </summary>
    public const string UnsupportedResponseType = "unsupported_response_type";

    /// <summary>The authorization server does not support the OIDC Core <c>request</c> parameter.</summary>
    public const string RequestNotSupported = "request_not_supported";

    /// <summary>The authorization server does not support the OIDC Core <c>request_uri</c> parameter.</summary>
    public const string RequestUriNotSupported = "request_uri_not_supported";

    /// <summary>The authorization server does not support the OIDC Core <c>registration</c> parameter.</summary>
    public const string RegistrationNotSupported = "registration_not_supported";
}
