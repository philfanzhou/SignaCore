using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IAccountRepository
{
    Task<AccountEntity?> GetByIdAsync(Guid id);
    Task<AccountEntity?> GetByLoginProviderAsync(string providerName, string providerUserId);
    Task<AccountEntity?> GetByPasswordCredentialUsernameAsync(string username);
    Task AddAsync(AccountEntity account);
    Task<AccountEntity> CreateDefaultAccountAsync();
    Task UpdateAsync(AccountEntity account);
}
