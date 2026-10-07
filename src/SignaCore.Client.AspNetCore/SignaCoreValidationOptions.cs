namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The validation strictness policy of the hosted-login client. The defaults are the strict
/// profile: zero clock skew, a token-response <c>scope</c> echo that must be a subset of the
/// requested scopes, duplicate top-level JSON members rejected in both backchannel responses,
/// bounded response bodies (64 KB token, 4 KB logout), and future <c>iat</c> claims rejected.
/// Every dimension can be relaxed independently; relaxing a check removes a guarantee and is
/// the consumer's own risk call — an upstream clock drift belongs in <see cref="ClockSkew"/>,
/// never in disabling a time check.
/// </summary>
public sealed class SignaCoreValidationOptions
{
    /// <summary>
    /// The clock skew allowed by the ID-token lifetime validation and the gated access-token
    /// time checks. Default zero (strict); must be zero to thirty seconds.
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.Zero;

    /// <summary>
    /// When a token response carries a <c>scope</c> member, its space-separated values must be
    /// a subset of the scopes the sign-in requested (the configured
    /// <see cref="SignaCoreHostedLoginOptions.Scope"/>); a superset — an authority silently
    /// granting more than was asked for — fails the sign-in. A response without the member is
    /// accepted (the member is optional in the token contract). Default on.
    /// </summary>
    public bool RequireScopeEchoSubset { get; set; } = true;

    /// <summary>
    /// Rejects backchannel responses (token and prepared logout) whose top-level JSON object
    /// repeats a member name. <see cref="System.Text.Json.JsonDocument"/> keeps duplicate
    /// members, and a parser disagreement over which value wins is exactly the shape a crafted
    /// response would use, so duplicates are refused outright. Default on.
    /// </summary>
    public bool RejectDuplicateJsonMembers { get; set; } = true;

    /// <summary>
    /// The maximum accepted token-endpoint response body in bytes; a larger body is a closed
    /// malformed-response failure. Default 64 KB; must be positive.
    /// </summary>
    public int MaxTokenResponseBytes { get; set; } = 64 * 1024;

    /// <summary>
    /// The maximum accepted prepared-logout response body in bytes; a larger body is a closed
    /// malformed-response failure and the logout ends in the fixed local-only result. Default
    /// 4 KB; must be positive.
    /// </summary>
    public int MaxLogoutResponseBytes { get; set; } = 4 * 1024;

    /// <summary>
    /// Rejects ID tokens and gated access tokens whose <c>iat</c> (issued-at) lies in the
    /// future beyond <see cref="ClockSkew"/>. Default on; the tolerance equals the configured
    /// skew.
    /// </summary>
    public bool RejectFutureIssuedAt { get; set; } = true;
}
