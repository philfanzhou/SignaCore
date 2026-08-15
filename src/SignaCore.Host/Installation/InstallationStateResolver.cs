using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Host.Installation;

/// <summary>
/// Decides which startup path a database takes. Runs under the provider migration lock so two
/// instances starting against the same brand-new database cannot both create a pending installation.
/// </summary>
internal static class InstallationStateResolver
{
    public static async Task<(InstallationPhase Phase, InstallationStateEntity State, string? PlaintextSetupCode)>
        ResolveAsync(IdentityDbContext db, CancellationToken cancellationToken = default)
    {
        var state = await db.InstallationStates
            .FirstOrDefaultAsync(row => row.Id == InstallationStateEntity.SingletonId, cancellationToken);

        if (state is not null)
        {
            db.ChangeTracker.Clear();
            return state.Status == InstallationStatus.Completed
                ? (InstallationPhase.Completed, state, null)
                : (InstallationPhase.PendingSetup, state, null);
        }

        // No state row. Anything meaningful already in the database means this is an upgrade of a
        // pre-change deployment, not a fresh install — anonymous setup must stay closed.
        if (await HasBusinessDataAsync(db, cancellationToken))
        {
            return (
                InstallationPhase.LegacyImportRequired,
                new InstallationStateEntity
                {
                    Id = InstallationStateEntity.SingletonId,
                    Status = InstallationStatus.Pending,
                    InstallationId = Guid.NewGuid(),
                    ConfigurationVersion = 0
                },
                null);
        }

        var setupCode = SetupCode.Generate();
        var pending = new InstallationStateEntity
        {
            Id = InstallationStateEntity.SingletonId,
            Status = InstallationStatus.Pending,
            InstallationId = Guid.NewGuid(),
            SetupCodeHash = SetupCode.Hash(setupCode),
            SetupCodeExpiresAt = DateTimeOffset.UtcNow.Add(SetupCode.DefaultLifetime),
            ConfigurationVersion = 0
        };

        db.InstallationStates.Add(pending);
        await db.SaveChangesAsync(cancellationToken);
        db.ChangeTracker.Clear();

        return (InstallationPhase.PendingSetup, pending, setupCode);
    }

    /// <summary>
    /// Conservative on purpose: any meaningful pre-existing row is enough to prevent anonymous setup.
    /// </summary>
    public static async Task<bool> HasBusinessDataAsync(
        IdentityDbContext db,
        CancellationToken cancellationToken = default)
    {
        return await db.Accounts.AnyAsync(cancellationToken)
            || await db.PasswordCredentials.AnyAsync(cancellationToken)
            || await db.UserLogins.AnyAsync(cancellationToken)
            || await db.LdapCredentials.AnyAsync(cancellationToken)
            || await db.AppRegistrations.AnyAsync(cancellationToken)
            || await db.SecurityKeys.AnyAsync(cancellationToken)
            || await db.RefreshTokens.AnyAsync(cancellationToken)
            || await db.AuditLogs.AnyAsync(cancellationToken)
            || await db.LoginHistories.AnyAsync(cancellationToken);
    }
}
