namespace QuantumZhou.Identity.Domain.Models;

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
