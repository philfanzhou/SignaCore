using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;

namespace SignaCore.Domain.Services;

public class AccountLoginInfoService : IAccountLoginInfoService
{
    private readonly IAccountRepository _accountRepository;

    public AccountLoginInfoService(IAccountRepository accountRepository)
    {
        _accountRepository = accountRepository;
    }

    public async Task UpdateLoginInfoAsync(AccountEntity account, string? clientIp, string authMethod)
    {
        account.LastLoginAt = DateTimeOffset.UtcNow;
        account.LastLoginIp = clientIp;
        account.LastLoginMethod = authMethod;
        account.TotalLoginCount++;
        await _accountRepository.UpdateAsync(account);
    }
}
