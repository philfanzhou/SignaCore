namespace SignaCore.Host.Models;

/// <summary>
/// The success body of <c>GET /api/gateway/auth-capabilities</c>: the login methods the calling
/// application currently permits. Both fields are derived from the application's stored policy at
/// request time; they describe permitted methods, not whether a particular account can sign in or
/// whether an SMS provider is reachable.
/// </summary>
/// <param name="PasswordEnabled">
/// The password grant has no per-application switch, so this is <c>true</c> for every application
/// that passes gateway authentication.
/// </param>
/// <param name="SmsLoginEnabled">
/// <c>true</c> when the application's SMS login mode is <c>ManualApproval</c> or
/// <c>AutoProvision</c>; <c>false</c> when it is <c>Disabled</c>.
/// </param>
public sealed record GatewayAuthCapabilitiesResponse(bool PasswordEnabled, bool SmsLoginEnabled);
