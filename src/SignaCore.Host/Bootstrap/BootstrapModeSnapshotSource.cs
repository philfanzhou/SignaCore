using ServiceMantle.AspNetCore.Health;
using ServiceMantle.Health;
using ServiceMantle.Installation;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// The single phase observation Bootstrap Configuration Mode can make: no database is known, so
/// migration has not started and the database is honestly unreachable.
/// </summary>
internal sealed class BootstrapModeSnapshotSource : IServiceHealthSnapshotSource
{
    private static readonly ServiceHealthSnapshot Snapshot = new(
        ServiceStartupPhase.BootstrapConfiguration,
        ServiceMigrationReadinessState.NotStarted,
        ServiceDatabaseReadinessState.Unreachable);

    public ValueTask<ServiceHealthSnapshot> GetSnapshotAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Snapshot);
    }
}
