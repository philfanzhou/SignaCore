namespace SignaCore.Domain.Services.Ldap;

public interface ILdapDirectoryClient
{
    LdapDirectoryOptions ResolveDirectory(string username);
    LdapDirectoryOptions GetDirectory(string directoryKey);
    Task<LdapDirectoryIdentity?> FindUserAsync(string directoryKey, string username, CancellationToken cancellationToken);
    Task<LdapCredentialValidationResult> ValidateCredentialsAsync(
        string directoryKey,
        string userPrincipalName,
        string password,
        CancellationToken cancellationToken);
    Task<bool> IsUserEnabledAsync(string directoryKey, Guid objectGuid, CancellationToken cancellationToken);
}

public sealed record LdapDirectoryIdentity(
    string DirectoryKey,
    Guid ObjectGuid,
    string UserPrincipalName,
    string SamAccountName,
    bool IsEnabled);

public enum LdapCredentialValidationResult
{
    Success,
    InvalidCredentials
}

public sealed class LdapDirectoryUnavailableException : Exception
{
    public LdapDirectoryUnavailableException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
