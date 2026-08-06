using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;

namespace SignaCore.Domain.Services;

public class AccountLoginInfoService : IAccountLoginInfoService
{
    private readonly IAccountRepository _accountRepository;
    private readonly IUnitOfWork _unitOfWork;

    public AccountLoginInfoService(IAccountRepository accountRepository, IUnitOfWork unitOfWork)
    {
        _accountRepository = accountRepository;
        _unitOfWork = unitOfWork;
    }

    public async Task UpdateLoginInfoAsync(AccountEntity account, string? clientIp, string authMethod)
    {
        account.LastLoginAt = DateTimeOffset.UtcNow;
        account.LastLoginIp = clientIp;
        account.LastLoginMethod = authMethod;
        account.TotalLoginCount++;
        await _accountRepository.UpdateAsync(account);
        await _unitOfWork.SaveChangesAsync();
    }
}
