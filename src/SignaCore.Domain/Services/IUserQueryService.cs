using SignaCore.Domain.Models;

namespace SignaCore.Domain.Services;

public interface IUserQueryService
{
    Task<(List<UserListItemResponse> Users, int Total)> SearchUsersAsync(
        string? username,
        string? phone,
        int page,
        int pageSize,
        CancellationToken cancellationToken = default);

    Task<List<UserListItemResponse>> GetUsersByIdsAsync(
        List<string> userIds,
        CancellationToken cancellationToken = default);
}
