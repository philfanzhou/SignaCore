namespace SignaCore.Domain.Models;

/// <summary>
/// One account list item. The administration console (/api/admin/users) and the business gateway
/// (/api/gateway/users/*) share it, which is why it carries no Admin prefix — changing it affects
/// both call surfaces at once.
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
