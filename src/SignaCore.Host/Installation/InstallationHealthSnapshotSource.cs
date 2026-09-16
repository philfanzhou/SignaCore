using Microsoft.EntityFrameworkCore;
using ServiceMantle.AspNetCore.Health;
using ServiceMantle.Health;
using ServiceMantle.Installation;
using SignaCore.Database;

namespace SignaCore.Host.Installation;

/// <summary>
/// Feeds the ServiceMantle phase gate from the shared installation state
/// (<c>service_installations</c>), which is the runtime authority for the installation phase.
/// </summary>
/// <remarks>
/// The normal host only runs after the bootstrap phase migrated the database and resolved the
/// installation as <c>Completed</c>, so a reachable database with a completed row maps to
/// <c>Completed + Succeeded + Reachable</c> — the only admission the management session entries
/// accept. Any other phase is reported as-is and the gate rejects the request. A database failure
/// propagates and the gate fails closed; it is never disguised as readiness.
/// </remarks>
internal sealed class InstallationHealthSnapshotSource(IdentityDbContext db) : IServiceHealthSnapshotSource
{
    public async ValueTask<ServiceHealthSnapshot> GetSnapshotAsync(
        CancellationToken cancellationToken = default)
    {
        var installationStore = InstallationStores.CreateInstallationStore(db);
        var state = await installationStore.FindAsync(InstallationStores.ServiceId, cancellationToken);

        // A missing row in the normal host means the installation authority was lost; that is a
        // not-ready observation, not a crash.
        if (SharedInstallationPhase.Resolve(state) != ServiceStartupPhase.Completed)
        {
            return new ServiceHealthSnapshot(
                ServiceStartupPhase.PendingSetup,
                ServiceMigrationReadinessState.Succeeded,
                ServiceDatabaseReadinessState.Reachable);
        }

        return new ServiceHealthSnapshot(
            ServiceStartupPhase.Completed,
            ServiceMigrationReadinessState.Succeeded,
            ServiceDatabaseReadinessState.Reachable);
    }
}
