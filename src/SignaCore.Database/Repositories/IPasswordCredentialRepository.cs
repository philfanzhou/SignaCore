using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IPasswordCredentialRepository
{
    Task<PasswordCredentialEntity?> GetByUsernameAsync(
        string username,
        CancellationToken cancellationToken = default);
    Task<PasswordCredentialEntity?> GetByAccountIdAsync(
        Guid accountId,
        CancellationToken cancellationToken = default);
    Task AddAsync(
        PasswordCredentialEntity credential,
        CancellationToken cancellationToken = default);
    Task<bool> ExistsByUsernameAsync(
        string username,
        CancellationToken cancellationToken = default);
}
