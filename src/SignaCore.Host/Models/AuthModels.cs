using System.Text.Json.Serialization;

namespace SignaCore.Host.Models;

/// <summary>
/// Stable machine-readable failure codes of the legacy <c>/api/auth/token</c> and
/// <c>/api/auth/sms-code</c> responses. A code is additive: it is written only for the decisions
/// listed here and the property is omitted on success and on every other failure. Callers compare
/// it exactly and never parse <c>message</c>. See docs/modules/Auth/GetToken/02-SPEC.md.
/// </summary>
public static class LegacyAuthResponseCodes
{
    /// <summary>The application's SMS login mode is <c>Disabled</c>.</summary>
    public const string SmsLoginDisabled = "SMS_LOGIN_DISABLED";
}

/// <summary>
/// HTTP request body for POST /api/auth/token (OAuth2 grant_type mode).
/// </summary>
public sealed class TokenRequest
{
    public string GrantType { get; set; } = string.Empty;
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string? Phone { get; set; }
    public string? Code { get; set; }
    public string? RefreshToken { get; set; }
}

/// <summary>
/// HTTP response body for POST /api/auth/token.
/// </summary>
public sealed class TokenResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public long ExpiresIn { get; set; }
    public long ExpiresAt { get; set; }
    public UserInfo? UserInfo { get; set; }

    /// <summary>
    /// An optional stable failure code from <see cref="LegacyAuthResponseCodes"/>; omitted, not
    /// null, when there is none.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Code { get; set; }
}

public sealed class UserInfo
{
    public string UserId { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Phone { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string ClientType { get; set; } = string.Empty;
    public string AuthMethod { get; set; } = string.Empty;
    public List<string> Roles { get; set; } = new();
    public List<string> Permissions { get; set; } = new();
}

/// <summary>
/// HTTP request body for POST /api/auth/sms-code.
/// </summary>
public sealed class SmsCodeRequest
{
    public string Phone { get; set; } = string.Empty;
}

/// <summary>
/// HTTP response body for POST /api/auth/sms-code.
/// </summary>
public sealed class SmsCodeResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// An optional stable failure code from <see cref="LegacyAuthResponseCodes"/>; omitted, not
    /// null, when there is none.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Code { get; set; }
}

/// <summary>
/// HTTP request body for POST /api/auth/revoke.
/// </summary>
public sealed class RevokeRequest
{
    public string RefreshToken { get; set; } = string.Empty;
}

/// <summary>
/// HTTP response body for POST /api/auth/revoke.
/// </summary>
public sealed class RevokeResponse
{
    public bool Success { get; set; }
}

/// <summary>
/// HTTP request body for POST /api/auth/callback/register.
/// </summary>
public sealed class RegisterCallbackRequest
{
    public string CallbackUrl { get; set; } = string.Empty;
    public int TtlSeconds { get; set; }
}

/// <summary>
/// HTTP response body for POST /api/auth/callback/register.
/// </summary>
public sealed class RegisterCallbackResponse
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public long ExpiresAt { get; set; }
}
