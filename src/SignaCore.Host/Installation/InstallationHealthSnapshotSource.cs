using Microsoft.EntityFrameworkCore;
using ServiceMantle.AspNetCore.Health;
using ServiceMantle.Health;
using ServiceMantle.Diagnostics;
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
internal sealed class InstallationHealthSnapshotSource(IdentityDbContext db, ServiceMetrics? metrics = null) : IServiceHealthSnapshotSource
{
    public async ValueTask<ServiceHealthSnapshot> GetSnapshotAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            var installationStore = InstallationStores.CreateInstallationStore(db);
            var state = await installationStore.FindAsync(InstallationStores.ServiceId, cancellationToken);
            var phase = SharedInstallationPhase.Resolve(state);
            // A missing row is not evidence of a committed phase. Keep the existing not-ready
            // health result, but clear the metrics observation instead of claiming PendingSetup.
            if (state is null) metrics?.SetUnknown();
            else metrics?.SetPhase(phase);

            return new ServiceHealthSnapshot(
                phase,
                ServiceMigrationReadinessState.Succeeded,
                ServiceDatabaseReadinessState.Reachable);
        }
        catch
        {
            // Failure and caller cancellation both invalidate the observation. Their original
            // exception/token still reaches the phase gate; metrics never decide admission.
            metrics?.SetUnknown();
            throw;
        }
    }
}
