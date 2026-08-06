using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Domain.Services.Ldap;

public interface ILdapAccountService
{
    Task<LdapCredentialEntity?> FindCredentialByLoginAsync(string directoryKey, string username);
    Task<LdapCredentialEntity?> GetCredentialAsync(Guid credentialId);
    Task<LdapCredentialEntity?> GetCredentialByObjectGuidAsync(string directoryKey, Guid objectGuid);
    Task<AppLdapAccessEntity?> GetAccessAsync(Guid appRegistrationId, Guid credentialId);
    Task<LdapProvisioningResult> ProvisionAsync(
        LdapDirectoryIdentity identity,
        AppRegistrationEntity app,
        LdapAccessApprovalSource source,
        Guid? approvedBy,
        CancellationToken cancellationToken);
}

public sealed record LdapProvisioningResult(
    AccountEntity Account,
    LdapCredentialEntity Credential,
    AppLdapAccessEntity Access,
    bool AccountCreated,
    bool AccessCreated);

public sealed class LdapAccountService : ILdapAccountService
{
    private readonly IdentityDbContext _dbContext;

    public LdapAccountService(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<LdapCredentialEntity?> FindCredentialByLoginAsync(string directoryKey, string username)
    {
        var normalizedDirectory = IdentityValueNormalizer.Normalize(directoryKey);
        var normalizedLogin = IdentityValueNormalizer.Normalize(StripDomainPrefix(username.Trim()));
        return await _dbContext.LdapCredentials.FirstOrDefaultAsync(credential =>
            credential.DirectoryKeyNormalized == normalizedDirectory &&
            (credential.UserPrincipalNameNormalized == normalizedLogin ||
             credential.SamAccountNameNormalized == normalizedLogin));
    }

    public Task<LdapCredentialEntity?> GetCredentialAsync(Guid credentialId) =>
        _dbContext.LdapCredentials.FirstOrDefaultAsync(credential => credential.Id == credentialId);

    public Task<LdapCredentialEntity?> GetCredentialByObjectGuidAsync(string directoryKey, Guid objectGuid)
    {
        var normalizedDirectory = IdentityValueNormalizer.Normalize(directoryKey);
        return _dbContext.LdapCredentials.FirstOrDefaultAsync(credential =>
            credential.DirectoryKeyNormalized == normalizedDirectory &&
            credential.ObjectGuid == objectGuid);
    }

    public Task<AppLdapAccessEntity?> GetAccessAsync(Guid appRegistrationId, Guid credentialId) =>
        _dbContext.AppLdapAccesses.FirstOrDefaultAsync(access =>
            access.AppRegistrationId == appRegistrationId &&
            access.LdapCredentialId == credentialId);

    public async Task<LdapProvisioningResult> ProvisionAsync(
        LdapDirectoryIdentity identity,
        AppRegistrationEntity app,
        LdapAccessApprovalSource source,
        Guid? approvedBy,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            try
            {
                var strategy = _dbContext.Database.CreateExecutionStrategy();
                return await strategy.ExecuteAsync(async () =>
                {
                    // The execution strategy can replay this whole delegate after a
                    // transient commit failure. Clear entities left Added/Modified by
                    // the previous attempt, then rebuild state from durable keys.
                    _dbContext.ChangeTracker.Clear();
                    await using var transaction = await _dbContext.Database.BeginTransactionAsync(cancellationToken);
                    var normalizedDirectory = IdentityValueNormalizer.Normalize(identity.DirectoryKey);
                    var credential = await _dbContext.LdapCredentials.FirstOrDefaultAsync(item =>
                        item.DirectoryKeyNormalized == normalizedDirectory &&
                        item.ObjectGuid == identity.ObjectGuid, cancellationToken);

                    var accountCreated = credential == null;
                    AccountEntity account;
                    if (credential == null)
                    {
                        account = new AccountEntity
                        {
                            Id = Guid.NewGuid(),
                            IsActive = true,
                            CreatedAt = DateTimeOffset.UtcNow
                        };
                        credential = new LdapCredentialEntity
                        {
                            Id = Guid.NewGuid(),
                            AccountId = account.Id,
                            DirectoryKey = identity.DirectoryKey,
                            ObjectGuid = identity.ObjectGuid,
                            UserPrincipalName = identity.UserPrincipalName,
                            SamAccountName = identity.SamAccountName,
                            CreatedAt = DateTimeOffset.UtcNow
                        };
                        _dbContext.Accounts.Add(account);
                        _dbContext.LdapCredentials.Add(credential);
                    }
                    else
                    {
                        account = await _dbContext.Accounts.SingleAsync(
                            item => item.Id == credential.AccountId,
                            cancellationToken);
                        // This is an explicit administrator action, not background
                        // synchronization. Re-approving the same objectGUID is the
                        // supported way to refresh renamed UPN/sAMAccountName aliases.
                        if (source == LdapAccessApprovalSource.Admin)
                        {
                            credential.UserPrincipalName = identity.UserPrincipalName;
                            credential.SamAccountName = identity.SamAccountName;
                        }
                    }

                    var access = await _dbContext.AppLdapAccesses.FirstOrDefaultAsync(item =>
                        item.AppRegistrationId == app.Id &&
                        item.LdapCredentialId == credential.Id, cancellationToken);
                    var accessCreated = access == null;
                    if (access == null)
                    {
                        access = new AppLdapAccessEntity
                        {
                            Id = Guid.NewGuid(),
                            AppRegistrationId = app.Id,
                            LdapCredentialId = credential.Id,
                            ApprovalSource = source,
                            IsActive = true,
                            ApprovedBy = approvedBy,
                            CreatedAt = DateTimeOffset.UtcNow
                        };
                        _dbContext.AppLdapAccesses.Add(access);
                    }
                    else if (source == LdapAccessApprovalSource.Admin)
                    {
                        access.ApprovalSource = LdapAccessApprovalSource.Admin;
                        access.IsActive = true;
                        access.ApprovedBy = approvedBy;
                    }

                    await _dbContext.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    return new LdapProvisioningResult(account, credential, access, accountCreated, accessCreated);
                });
            }
            catch (DbUpdateException) when (attempt == 0)
            {
                _dbContext.ChangeTracker.Clear();
            }
        }

        throw new InvalidOperationException("LDAP account provisioning failed after a concurrent update.");
    }

    private static string StripDomainPrefix(string username)
    {
        var slash = username.IndexOf('\\');
        return slash >= 0 ? username[(slash + 1)..] : username;
    }
}
