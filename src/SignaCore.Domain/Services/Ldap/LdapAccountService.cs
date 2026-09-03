using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Domain.Services.Ldap;

public interface ILdapAccountService
{
    Task<LdapCredentialEntity?> FindCredentialByLoginAsync(string directoryKey, string username, CancellationToken cancellationToken = default);
    Task<LdapCredentialEntity?> GetCredentialAsync(Guid credentialId, CancellationToken cancellationToken = default);
    Task<LdapCredentialEntity?> GetCredentialByObjectGuidAsync(string directoryKey, Guid objectGuid, CancellationToken cancellationToken = default);
    Task<AppLdapAccessEntity?> GetAccessAsync(Guid appRegistrationId, Guid credentialId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Admits an existing LDAP credential for <paramref name="appRegistrationId"/> without a directory
    /// bind, for an admission derived from one the account already holds elsewhere. Returns null when
    /// the credential does not exist. An existing admission row is returned unchanged, including a
    /// revoked one — restoring a revoked admission is an administrator action.
    /// </summary>
    Task<AppLdapAccessEntity?> GrantAccessAsync(
        Guid appRegistrationId,
        Guid credentialId,
        LdapAccessApprovalSource source,
        CancellationToken cancellationToken = default);
    /// <summary>
    /// Provisions the identity and invokes <paramref name="beforeCommit"/> after state is staged but
    /// before the service's single transactional commit.
    /// </summary>
    Task<LdapProvisioningResult> ProvisionAsync(
        LdapDirectoryIdentity identity,
        AppRegistrationEntity app,
        LdapAccessApprovalSource source,
        Guid? approvedBy,
        CancellationToken cancellationToken,
        Func<LdapProvisioningResult, Task>? beforeCommit = null);
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

    public async Task<LdapCredentialEntity?> FindCredentialByLoginAsync(string directoryKey, string username, CancellationToken cancellationToken = default)
    {
        var normalizedDirectory = IdentityValueNormalizer.Normalize(directoryKey);
        var normalizedLogin = IdentityValueNormalizer.Normalize(StripDomainPrefix(username.Trim()));
        return await _dbContext.LdapCredentials.FirstOrDefaultAsync(credential =>
            credential.DirectoryKeyNormalized == normalizedDirectory &&
            (credential.UserPrincipalNameNormalized == normalizedLogin ||
             credential.SamAccountNameNormalized == normalizedLogin), cancellationToken);
    }

    public Task<LdapCredentialEntity?> GetCredentialAsync(Guid credentialId, CancellationToken cancellationToken = default) =>
        _dbContext.LdapCredentials.FirstOrDefaultAsync(credential => credential.Id == credentialId, cancellationToken);

    public Task<LdapCredentialEntity?> GetCredentialByObjectGuidAsync(string directoryKey, Guid objectGuid, CancellationToken cancellationToken = default)
    {
        var normalizedDirectory = IdentityValueNormalizer.Normalize(directoryKey);
        return _dbContext.LdapCredentials.FirstOrDefaultAsync(credential =>
            credential.DirectoryKeyNormalized == normalizedDirectory &&
            credential.ObjectGuid == objectGuid, cancellationToken);
    }

    public Task<AppLdapAccessEntity?> GetAccessAsync(Guid appRegistrationId, Guid credentialId, CancellationToken cancellationToken = default) =>
        _dbContext.AppLdapAccesses.FirstOrDefaultAsync(access =>
            access.AppRegistrationId == appRegistrationId &&
            access.LdapCredentialId == credentialId, cancellationToken);

    public async Task<AppLdapAccessEntity?> GrantAccessAsync(
        Guid appRegistrationId,
        Guid credentialId,
        LdapAccessApprovalSource source,
        CancellationToken cancellationToken = default)
    {
        var credentialExists = await _dbContext.LdapCredentials
            .AnyAsync(credential => credential.Id == credentialId, cancellationToken);
        if (!credentialExists) return null;

        var access = await GetAccessAsync(appRegistrationId, credentialId, cancellationToken);
        if (access != null) return access;

        access = new AppLdapAccessEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = appRegistrationId,
            LdapCredentialId = credentialId,
            ApprovalSource = source,
            IsActive = true,
            ApprovedBy = null,
            CreatedAt = DateTimeOffset.UtcNow
        };
        _dbContext.AppLdapAccesses.Add(access);
        try
        {
            await _dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException)
        {
            // Two exchanges for the same credential raced. The unique index decided; re-read the
            // winner rather than failing a request that got the outcome it asked for.
            _dbContext.ChangeTracker.Clear();
            access = await _dbContext.AppLdapAccesses.AsNoTracking().FirstOrDefaultAsync(
                row => row.AppRegistrationId == appRegistrationId && row.LdapCredentialId == credentialId,
                cancellationToken);
            if (access == null) throw;
        }

        return access;
    }

    public async Task<LdapProvisioningResult> ProvisionAsync(
        LdapDirectoryIdentity identity,
        AppRegistrationEntity app,
        LdapAccessApprovalSource source,
        Guid? approvedBy,
        CancellationToken cancellationToken,
        Func<LdapProvisioningResult, Task>? beforeCommit = null)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var strategy = _dbContext.Database.CreateExecutionStrategy();
                return await strategy.ExecuteAsync(async operationCancellationToken =>
                {
                    // The execution strategy can replay this whole delegate after a
                    // transient commit failure. Clear entities left Added/Modified by
                    // the previous attempt, then rebuild state from durable keys.
                    _dbContext.ChangeTracker.Clear();
                    await using var transaction = await _dbContext.Database.BeginTransactionAsync(operationCancellationToken);
                    var normalizedDirectory = IdentityValueNormalizer.Normalize(identity.DirectoryKey);
                    var credential = await _dbContext.LdapCredentials.FirstOrDefaultAsync(item =>
                        item.DirectoryKeyNormalized == normalizedDirectory &&
                        item.ObjectGuid == identity.ObjectGuid, operationCancellationToken);

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
                            operationCancellationToken);
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
                        item.LdapCredentialId == credential.Id, operationCancellationToken);
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

                    var result = new LdapProvisioningResult(
                        account, credential, access, accountCreated, accessCreated);
                    if (beforeCommit is not null)
                    {
                        await beforeCommit(result);
                    }
                    await _dbContext.SaveChangesAsync(operationCancellationToken);
                    await transaction.CommitAsync(operationCancellationToken);
                    return result;
                }, cancellationToken);
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
