namespace SignaCore.Domain.Models;

/// <summary>
/// 账户列表项。管理控制台（/api/admin/users）与业务网关（/api/gateway/users/*）共用，
/// 因此不带 Admin 前缀——改它会同时影响两个调用面。
/// </summary>
public sealed record UserListItemResponse(
    string UserId,
    string Username,
    string Phone,
    bool IsActive,
    string Remark,
    string? Nickname,
    long CreatedAt,
    string DisplayName,
    bool HasPassword);
