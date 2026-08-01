namespace QuantumZhou.Identity.Host.Models;

// 仅管理控制台（/api/admin/*）使用的请求/响应。三个调用面共用的通用响应见 ApiModels.cs。

public sealed record AdminLoginRequest(string Username, string Password, bool RememberMe);

public sealed record AdminSessionResponse(
    string AccountId,
    string Username,
    bool IsAuthenticated);

public sealed record AdminCreateUserRequest(string Username, string Password, string? DisplayName, string? Remark, string? Nickname);

public sealed record AdminCreatePhoneUserRequest(string Phone, string? DisplayName, string? Remark, string? Nickname);

public sealed record AdminCreateUserResponse(
    string UserId,
    string Username,
    string DisplayName,
    bool IsActive,
    string Remark,
    string? Nickname,
    long CreatedAt);

public sealed record AdminUpdateRemarkRequest(string? Remark);

public sealed record AdminUpdateNicknameRequest(string? Nickname);

public sealed record AdminUpdateStatusRequest(bool IsActive);

public sealed record AdminAppListItemResponse(
    string AppId,
    string AppName,
    string CallbackUrl,
    long? CallbackExpiresAt,
    bool IsActive,
    long CreatedAt);

public sealed record AdminCreateAppRequest(string AppName, string? CallbackUrl, int TtlSeconds);

public sealed record AdminCreateAppResponse(
    string AppId,
    string AppSecret,
    string AppName,
    string CallbackUrl,
    long? CallbackExpiresAt);

public sealed record AdminUpdateCallbackRequest(string? CallbackUrl, int TtlSeconds, bool IsActive);

public sealed record AdminRevokeRefreshTokenRequest(string RefreshToken);

public sealed record AdminLoginHistoryItemResponse(
    string AuthMethod,
    string EventType,
    string ClientIp,
    string UserAgent,
    string? FailureReason,
    string? AppId,
    long CreatedAt);

public sealed record AdminAuditLogItemResponse(
    string Action,
    string TargetType,
    string TargetId,
    string? ActorId,
    string? ActorName,
    string? Description,
    string? ClientIp,
    string? CorrelationId,
    long CreatedAt);
