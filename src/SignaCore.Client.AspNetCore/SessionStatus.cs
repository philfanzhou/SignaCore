namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The session-status answer of the package's session endpoint. It reports whether a session is
/// authenticated, whether a re-authentication is required (the fixed answer once the session has
/// reached the access token's expiry), the verified display name, and the consumer's authorization
/// decision. It never carries a token of any kind.
/// </summary>
public sealed record SessionStatus(
    bool Authenticated,
    bool RequiresReauthentication,
    string? DisplayName,
    AuthorizationDecisionResult? Authorization)
{
    /// <summary>The fixed status of an expired or absent session.</summary>
    public static SessionStatus Expired { get; } = new(
        Authenticated: false,
        RequiresReauthentication: true,
        DisplayName: null,
        Authorization: null);

    /// <summary>Creates the status of a verified, unexpired session.</summary>
    public static SessionStatus AuthenticatedSession(
        string? displayName,
        AuthorizationDecisionResult authorization) => new(
        Authenticated: true,
        RequiresReauthentication: false,
        DisplayName: displayName,
        Authorization: authorization);
}
