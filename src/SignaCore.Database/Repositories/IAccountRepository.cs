using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IAccountRepository
{
    Task<AccountEntity?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<AccountEntity?> GetByLoginProviderAsync(
        string providerName,
        string providerUserId,
        CancellationToken cancellationToken = default);
    Task<AccountEntity?> GetByPasswordCredentialUsernameAsync(
        string username,
        CancellationToken cancellationToken = default);
    Task AddAsync(AccountEntity account, CancellationToken cancellationToken = default);
    Task<AccountEntity> CreateDefaultAccountAsync(CancellationToken cancellationToken = default);
    Task UpdateAsync(AccountEntity account, CancellationToken cancellationToken = default);
}
