using System.Text.Json.Serialization;

namespace SignaCore.Host.Models;

/// <summary>
/// First-run setup form. It collects only what is needed to establish an operable secured
/// installation; SMS, WeChat, LDAP, telemetry, callback allowlists, and application registrations are
/// configured later from authenticated administration pages.
/// </summary>
public sealed class SetupCompleteRequest
{
    [JsonPropertyName("publicBaseUrl")]
    public string PublicBaseUrl { get; set; } = string.Empty;

    /// <summary>
    /// Explicit operator acknowledgement required before an HTTP public base URL is accepted.
    /// The address is never classified by host name or IP range.
    /// </summary>
    [JsonPropertyName("allowNonHttpsIssuer")]
    public bool AllowNonHttpsIssuer { get; set; }

    /// <summary>Initial access-token audience. Defaults to the SignaCore product audience.</summary>
    [JsonPropertyName("jwtAudience")]
    public string JwtAudience { get; set; } = "SignaCore.Services";

    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty;

    [JsonPropertyName("confirmPassword")]
    public string ConfirmPassword { get; set; } = string.Empty;

    [JsonPropertyName("setupCode")]
    public string SetupCode { get; set; } = string.Empty;
}

public sealed class SetupStatusResponse
{
    /// <summary><c>pending</c> or <c>completed</c>.</summary>
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("installationId")]
    public string InstallationId { get; set; } = string.Empty;

    /// <summary>True while this process is shutting down to restart into the normal host.</summary>
    [JsonPropertyName("restarting")]
    public bool Restarting { get; set; }

    /// <summary>Where the browser should go once the service is available again.</summary>
    [JsonPropertyName("nextUrl")]
    public string NextUrl { get; set; } = "/admin";
}

public sealed class SetupCompleteResponse
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;
}
