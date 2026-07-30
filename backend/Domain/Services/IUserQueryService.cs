using QuantumZhou.Identity.Domain.Models;

namespace QuantumZhou.Identity.Domain.Services;

public interface IUserQueryService
{
    Task<(List<AdminUserListItemResponse> Users, int Total)> SearchUsersAsync(string? username, string? phone, int page, int pageSize);
    Task<List<AdminUserListItemResponse>> GetUsersByIdsAsync(List<string> userIds);
}
