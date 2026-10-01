namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The session-status answer of the package's session endpoint. It reports whether a session is
/// authenticated, whether a re-authentication is required (the fixed answer once the session has
/// reached the access token's expiry), the verified display name, and the consumer's authorization
/// decision. It never carries a token of any kind.
/// </summary>
public sealed record SignaCoreSessionStatus(
    bool Authenticated,
    bool RequiresReauthentication,
    string? DisplayName,
    SignaCoreAuthorizationDecisionResult? Authorization)
{
    /// <summary>The fixed status of an expired or absent session.</summary>
    public static SignaCoreSessionStatus Expired { get; } = new(
        Authenticated: false,
        RequiresReauthentication: true,
        DisplayName: null,
        Authorization: null);

    /// <summary>Creates the status of a verified, unexpired session.</summary>
    public static SignaCoreSessionStatus AuthenticatedSession(
        string? displayName,
        SignaCoreAuthorizationDecisionResult authorization) => new(
        Authenticated: true,
        RequiresReauthentication: false,
        DisplayName: displayName,
        Authorization: authorization);
}
