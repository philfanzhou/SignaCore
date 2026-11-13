using SignaCore.Database.Repositories;

namespace SignaCore.Host.Services;

internal static class BootstrapAdministrator
{
    public static async Task<bool> IsAccountAsync(
        Guid accountId,
        AdminIdentityOptions options,
        IAccountRepository accounts,
        CancellationToken cancellationToken)
    {
        if (!options.IsConfigured)
        {
            return false;
        }

        var administrator = await accounts.GetByPasswordCredentialUsernameAsync(
            options.Username.Trim(), cancellationToken);
        return administrator?.Id == accountId;
    }
}
