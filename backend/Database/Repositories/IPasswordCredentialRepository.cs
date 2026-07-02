using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public interface IPasswordCredentialRepository
{
    Task<PasswordCredentialEntity?> GetByUsernameAsync(string username);
    Task<PasswordCredentialEntity?> GetByAccountIdAsync(Guid accountId);
    Task AddAsync(PasswordCredentialEntity credential);
    Task<bool> ExistsByUsernameAsync(string username);
}
