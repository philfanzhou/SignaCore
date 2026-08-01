namespace QuantumZhou.Identity.Host.Models;

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
