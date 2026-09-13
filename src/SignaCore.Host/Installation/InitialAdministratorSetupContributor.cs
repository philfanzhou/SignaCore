using ServiceMantle.Installation;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;

namespace SignaCore.Host.Installation;

/// <summary>
/// The setup contributor that stages the initial administrator account and its password
/// credential.
/// <para>
/// Validation is read-only: it re-checks the password policy and rejects a username whose
/// normalized form already owns a credential, without changing the staging scope. Registration
/// only stages entities in the caller-owned unit of work; it never saves or commits, and every
/// attempt generates fresh account and credential identifiers so a rolled-back attempt can never
/// be reused.
/// </para>
/// </summary>
internal sealed class InitialAdministratorSetupContributor : IServiceSetupContributor
{
    internal const string UsernameTakenErrorCode = "setup.admin_username_taken";
    internal const string InvalidPasswordErrorCode = "setup.invalid_password";

    private readonly IdentityDbContext _db;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IPasswordPolicy _passwordPolicy;
    private readonly InitialAdministratorSetupInput _input;

    internal InitialAdministratorSetupContributor(
        IdentityDbContext db,
        IPasswordHasher passwordHasher,
        IPasswordPolicy passwordPolicy,
        InitialAdministratorSetupInput input)
    {
        _db = db;
        _passwordHasher = passwordHasher;
        _passwordPolicy = passwordPolicy;
        _input = input;
    }

    /// <summary>The registration order shared orchestration uses for this contributor.</summary>
    public int Order => 100;

    /// <summary>
    /// The account identifier staged by <see cref="RegisterAsync"/>. It is meaningful only after a
    /// successful registration; the audit event for this attempt links to it.
    /// </summary>
    internal Guid AccountId { get; private set; }

    public async ValueTask<ServiceSetupContributorResult> ValidateAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_passwordPolicy.Validate(_input.Password, out _))
        {
            return ServiceSetupContributorResult.Rejected(InvalidPasswordErrorCode);
        }

        var credentials = new PasswordCredentialRepository(_db);
        if (await credentials.GetByUsernameAsync(_input.Username, cancellationToken) is not null)
        {
            return ServiceSetupContributorResult.Rejected(UsernameTakenErrorCode);
        }

        return ServiceSetupContributorResult.Success();
    }

    public ValueTask<ServiceSetupContributorResult> RegisterAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var accountId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;

        _db.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = now,
            Remark = "Initial administrator created by first-run setup"
        });
        _db.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = _input.Username,
            PasswordHash = _passwordHasher.HashPassword(_input.Password),
            CreatedAt = now
        });

        AccountId = accountId;
        return ValueTask.FromResult(ServiceSetupContributorResult.Success());
    }
}
