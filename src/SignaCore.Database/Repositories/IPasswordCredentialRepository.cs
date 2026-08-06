using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IPasswordCredentialRepository
{
    Task<PasswordCredentialEntity?> GetByUsernameAsync(string username);
    Task<PasswordCredentialEntity?> GetByAccountIdAsync(Guid accountId);
    Task AddAsync(PasswordCredentialEntity credential);
    Task<bool> ExistsByUsernameAsync(string username);
}
