using Microsoft.EntityFrameworkCore;
using ServiceMantle;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Host.Configuration;

namespace SignaCore.Host.Installation;

/// <summary>
/// A setup code the bootstrap phase just issued, with its plaintext (available exactly once) and
/// its expiry.
/// </summary>
internal sealed record IssuedSetupCode(string Plaintext, DateTimeOffset ExpiresAtUtc);

/// <summary>
/// What the bootstrap phase concluded about the installation and the configuration version the
/// running snapshot is loaded at.
/// </summary>
internal sealed record InstallationResolution(
    InstallationPhase Phase,
    int ConfigurationVersion,
    IssuedSetupCode? SetupCode);

/// <summary>
/// Decides which startup path a database takes, reading the shared ServiceMantle installation
/// state (<c>service_installations</c>). Runs under the startup initialization lock so two
/// instances starting against the same brand-new database cannot both create a pending
/// installation.
/// <para>
/// A database whose installation row is missing but that already owns business data, or whose
/// completed row was adopted by the <c>AddServiceInstallations</c> backfill while both
/// <c>system_settings</c> and the shared <c>service_settings</c> aggregate are still empty, is an
/// upgrade of a pre-change deployment: it takes the protected legacy import, never anonymous
/// setup.
/// </para>
/// </summary>
internal static class InstallationStateResolver
{
    public static async Task<InstallationResolution> ResolveAsync(
        IdentityDbContext db,
        CancellationToken cancellationToken = default)
    {
        var serviceId = InstallationStores.ServiceId;
        var installationStore = InstallationStores.CreateInstallationStore(db);
        var state = await installationStore.FindAsync(serviceId, cancellationToken);
        var sharedPhase = SharedInstallationPhase.Resolve(state);

        if (state is null)
        {
            // No installation row. Anything meaningful already in the database means this is an
            // upgrade of a pre-change deployment, not a fresh install — anonymous setup must stay
            // closed.
            if (await HasBusinessDataAsync(db, cancellationToken))
            {
                return new InstallationResolution(InstallationPhase.LegacyImportRequired, 0, null);
            }

            db.ChangeTracker.Clear();
            await installationStore.CreatePendingAsync(serviceId, cancellationToken);
            var setupCode = await IssueInitialSetupCodeAsync(db, serviceId, cancellationToken);
            return new InstallationResolution(InstallationPhase.PendingSetup, 0, setupCode);
        }

        if (sharedPhase == ServiceStartupPhase.Completed)
        {
            // A completed row adopted by the backfill with neither stored settings nor a shared
            // aggregate is a real legacy upgrade that still has to run the import; a genuinely
            // completed installation always wrote its snapshot transactionally — into the shared
            // aggregate since the runtime switch, and into system_settings before it. A completed
            // installation of the switched era owns accounts but no legacy rows, so the aggregate
            // check is what keeps it out of the import path.
            if (!await db.SystemSettings.AnyAsync(cancellationToken) &&
                await SharedSettingAggregate.ReadVersionAsync(db, cancellationToken) is null &&
                await HasBusinessDataAsync(db, cancellationToken))
            {
                return new InstallationResolution(InstallationPhase.LegacyImportRequired, 0, null);
            }

            // The configuration-version authority is the shared aggregate; the bootstrap phase
            // fills the runtime configuration version from the activated snapshot.
            return new InstallationResolution(InstallationPhase.Completed, 0, null);
        }

        // Pending: the plaintext exists only in the issuance that created it. A restart does not
        // reissue a code. The single CreateAsync call distinguishes every case by itself: a row
        // whose code was never issued (the recovery window between creating the pending row and
        // saving its first code) gets one now, an already-issued code is left untouched
        // (setup_code.already_exists), and anything corrupt stays fail-closed without a code.
        var setupCodeStore = InstallationStores.CreateSetupCodeStore(db);
        var issued = await setupCodeStore.CreateAsync(serviceId, cancellationToken);
        if (issued.IsIssued)
        {
            return new InstallationResolution(
                InstallationPhase.PendingSetup,
                0,
                new IssuedSetupCode(
                    issued.SetupCode!.Reveal(),
                    new DateTimeOffset(issued.ExpiresAtUtc!.Value)));
        }

        return new InstallationResolution(InstallationPhase.PendingSetup, 0, null);
    }

    private static async Task<IssuedSetupCode?> IssueInitialSetupCodeAsync(
        IdentityDbContext db,
        ServiceId serviceId,
        CancellationToken cancellationToken)
    {
        var setupCodeStore = InstallationStores.CreateSetupCodeStore(db);
        var issued = await setupCodeStore.CreateAsync(serviceId, cancellationToken);
        if (issued.ErrorCode == WellKnownSetupCodeErrorCodes.AlreadyExists)
        {
            // Another writer won the race for this fresh database and already issued a code; this
            // boot simply has no plaintext to print.
            return null;
        }

        if (!issued.IsIssued)
        {
            throw new ServiceInstallationStoreException(
                "installation.storage_error",
                $"The pending installation was created but its setup code could not be issued ({issued.ErrorCode}).");
        }

        return new IssuedSetupCode(
            issued.SetupCode!.Reveal(),
            new DateTimeOffset(issued.ExpiresAtUtc!.Value));
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
