using SignaCore.Database;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;

namespace SignaCore.Host.Installation;

/// <summary>
/// Creates one <see cref="InitialAdministratorSetupContributor"/> per transaction attempt.
/// <para>
/// The shared orchestrator, its contributor, and the credentials they hold must never outlive a
/// single execution-strategy attempt: a PostgreSQL retry replays the whole setup transaction, and
/// replaying it with a reused contributor would stage the previous attempt's identifiers or leak
/// its tracked entities. The factory is request-scoped and hands every call a fresh instance
/// bound to the same request scope's <see cref="IdentityDbContext"/>.
/// </para>
/// </summary>
internal sealed class InitialAdministratorSetupContributorFactory
{
    private readonly IdentityDbContext _db;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IPasswordPolicy _passwordPolicy;

    public InitialAdministratorSetupContributorFactory(
        IdentityDbContext db,
        IPasswordHasher passwordHasher,
        IPasswordPolicy passwordPolicy)
    {
        _db = db;
        _passwordHasher = passwordHasher;
        _passwordPolicy = passwordPolicy;
    }

    public InitialAdministratorSetupContributor Create(InitialAdministratorSetupInput input) =>
        new(_db, _passwordHasher, _passwordPolicy, input);
}
