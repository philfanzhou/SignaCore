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
}
