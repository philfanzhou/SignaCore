using ServiceMantle.Bootstrap;
using SignaCore.Host.Models;

namespace SignaCore.Host.Bootstrap;

internal enum BootstrapOutcome
{
    Succeeded,

    /// <summary>The submitted provider, version, or connection details failed validation.</summary>
    InvalidRequest,

    /// <summary>The target database could not be reached with the supplied credentials.</summary>
    TargetUnreachable
}

internal sealed record BootstrapOperationResult(
    BootstrapOutcome Outcome,
    string Message,
    BootstrapTargetInspection? Inspection = null);

/// <summary>
/// The retained target probe of the former bootstrap editor: it classifies a candidate database
/// without writing anything, so the operator sees what they are about to point at before they
/// commit to it.
/// </summary>
/// <remarks>
/// Writing the file — creation and replacement — moved to the shared ServiceMantle bootstrap
/// entries; this service keeps only what those entries cannot offer: the SignaCore target
/// classification and key-compatibility probe shared by the anonymous first-install test and the
/// administrator test entry.
/// </remarks>
internal sealed class BootstrapConfigurationService(BootstrapFileStore store)
{
    /// <summary>Where this instance reads and writes its bootstrap file.</summary>
    public string FilePath => store.FilePath;

    /// <summary>
    /// Classifies a candidate database without writing anything, so the operator sees what they are
    /// about to point at before they commit to it.
    /// </summary>
    public async Task<BootstrapOperationResult> TestAsync(
        BootstrapDatabaseRequest request,
        string? candidateMasterKey,
        CancellationToken cancellationToken = default)
    {
        if (!BootstrapDatabaseRequestBinder.TryBind(request, out var database, out var error))
        {
            return new BootstrapOperationResult(BootstrapOutcome.InvalidRequest, error);
        }

        var inspection = await BootstrapTargetInspector.InspectAsync(
            database,
            candidateMasterKey,
            cancellationToken);

        return new BootstrapOperationResult(
            inspection.CanConnect ? BootstrapOutcome.Succeeded : BootstrapOutcome.TargetUnreachable,
            DescribeTarget(inspection),
            inspection);
    }

    private static string DescribeTarget(BootstrapTargetInspection inspection) => inspection.Kind switch
    {
        BootstrapTargetKind.Unreachable =>
            $"The database at {inspection.Endpoint} could not be opened: " +
            $"{inspection.FailureReason ?? "the server did not accept the connection."}",
        BootstrapTargetKind.Empty =>
            $"{inspection.Endpoint} is empty. SignaCore will create its schema and then run first-run setup.",
        BootstrapTargetKind.PendingInstallation =>
            $"{inspection.Endpoint} holds a SignaCore installation that has not completed first-run setup.",
        BootstrapTargetKind.CompletedInstallation =>
            $"{inspection.Endpoint} holds a completed SignaCore installation.",
        BootstrapTargetKind.LegacyData =>
            $"{inspection.Endpoint} holds SignaCore data from before database-backed configuration. " +
            "Startup will run the protected legacy import.",
        _ => inspection.Endpoint
    };
}
