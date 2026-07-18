namespace QuantumZhou.Identity.Host.Models;

public sealed record AdminApiErrorResponse(string Message);

public sealed record AdminLoginRequest(string Username, string Password, bool RememberMe);

public sealed record AdminSessionResponse(
    string AccountId,
    string Username,
    bool IsAuthenticated);

public sealed record AdminPagedResponse<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);

public sealed record AdminUserListItemResponse(
    string UserId,
    string Username,
    string Phone,
    bool IsActive,
    string Remark,
    string? Nickname,
    long CreatedAt,
    string DisplayName);

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

public sealed record AdminOperationResponse(bool Success, string Message);

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

public sealed record ProfileResponse(
    string UserId,
    string? Nickname,
    bool IsActive,
    long CreatedAt);

public sealed record UpdateProfileNicknameRequest(string? Nickname);
