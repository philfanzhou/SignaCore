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
    /// <summary>
    /// The username of the account's Password credential when the account has exactly one, read
    /// untracked; <c>null</c> when it has none or more than one. This is the <c>PS-12</c>/<c>PS-16</c>
    /// <c>name</c> source of an <c>Sms</c> identity session, which is bound to no credential.
    /// </summary>
    Task<string?> GetSoleUsernameByAccountIdAsync(
        Guid accountId,
        CancellationToken cancellationToken = default);
    Task AddAsync(
        PasswordCredentialEntity credential,
        CancellationToken cancellationToken = default);
    Task<bool> ExistsByUsernameAsync(
        string username,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// The single password-hash write of the self-service password change: replaces the stored
    /// hash of one credential inside the caller's transaction. The plaintext password and the
    /// old hash never leave the caller; returns the affected row count (0 or 1).
    /// </summary>
    Task<int> UpdatePasswordHashAsync(
        Guid credentialId,
        string newPasswordHash,
        CancellationToken cancellationToken = default);
}
