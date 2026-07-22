using Microsoft.EntityFrameworkCore;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Models;

namespace QuantumZhou.Identity.Domain.Services;

public class UserQueryService : IUserQueryService
{
    private readonly IdentityDbContext _dbContext;

    public UserQueryService(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<(List<AdminUserListItemResponse> Users, int Total)> SearchUsersAsync(
        string? username, string? phone, int page, int pageSize)
    {
        var searchTerm = username?.Trim();
        var phoneTerm = phone?.Trim();

        var query = _dbContext.Accounts
            .AsNoTracking()
            .Where(account =>
                (string.IsNullOrWhiteSpace(searchTerm) ||
                 _dbContext.PasswordCredentials.Any(credential =>
                     credential.AccountId == account.Id &&
                     EF.Functions.Like(credential.Username, $"%{searchTerm}%")) ||
                 EF.Functions.Like(account.Remark ?? string.Empty, $"%{searchTerm}%")) &&
                (string.IsNullOrWhiteSpace(phoneTerm) ||
                 _dbContext.UserLogins.Any(login =>
                     login.AccountId == account.Id &&
                     login.ProviderName == IdentityConstants.AuthMethodSms &&
                     EF.Functions.Like(login.ProviderUserId, $"%{phoneTerm}%"))));

        var total = await query.CountAsync();
        var users = await ProjectUsersAsync(query, page, pageSize);

        return (users, total);
    }

    public async Task<List<AdminUserListItemResponse>> GetUsersByIdsAsync(List<string> userIds)
    {
        var orderedUserIds = userIds
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var parsedUserIds = orderedUserIds
            .Select(id => Guid.TryParse(id, out var parsedId) ? parsedId : (Guid?)null)
            .Where(id => id.HasValue)
            .Select(id => id!.Value)
            .ToList();

        if (parsedUserIds.Count == 0)
        {
            return new List<AdminUserListItemResponse>();
        }

        var query = _dbContext.Accounts
            .AsNoTracking()
            .Where(account => parsedUserIds.Contains(account.Id));

        var users = await ProjectUsersAsync(query, page: 1, pageSize: parsedUserIds.Count);
        var userMap = users.ToDictionary(item => item.UserId, StringComparer.OrdinalIgnoreCase);

        var orderedUsers = orderedUserIds
            .Where(userMap.ContainsKey)
            .Select(id => userMap[id])
            .ToList();

        return orderedUsers;
    }

    private async Task<List<AdminUserListItemResponse>> ProjectUsersAsync(
        IQueryable<Database.Entity.AccountEntity> query,
        int page,
        int pageSize)
    {
        // Client evaluation is used for compatibility.
        var allAccounts = await query.ToListAsync();
        var pagedAccounts = allAccounts
            .OrderByDescending(account => account.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();

        var accountIds = pagedAccounts.Select(a => a.Id).ToList();

        var credentials = await _dbContext.PasswordCredentials
            .AsNoTracking()
            .Where(c => accountIds.Contains(c.AccountId))
            .ToDictionaryAsync(c => c.AccountId, c => c.Username);

        var phones = await _dbContext.UserLogins
            .AsNoTracking()
            .Where(l => accountIds.Contains(l.AccountId) && l.ProviderName == IdentityConstants.AuthMethodSms)
            .ToDictionaryAsync(l => l.AccountId, l => l.ProviderUserId);

        return pagedAccounts.Select(account =>
        {
            var username = credentials.GetValueOrDefault(account.Id);
            var phone = phones.GetValueOrDefault(account.Id);
            var name = username ?? phone ?? string.Empty;
            var displayName = !string.IsNullOrWhiteSpace(account.Nickname)
                ? account.Nickname
                : (!string.IsNullOrWhiteSpace(username)
                    ? username
                    : (!string.IsNullOrWhiteSpace(phone) ? phone : account.Id.ToString()[..8]));
            return new AdminUserListItemResponse(
                account.Id.ToString(),
                name,
                phone ?? string.Empty,
                account.IsActive,
                account.Remark ?? string.Empty,
                account.Nickname,
                account.CreatedAt.ToUnixTimeSeconds(),
                displayName,
                credentials.ContainsKey(account.Id));
        })
            .ToList();
    }
}
