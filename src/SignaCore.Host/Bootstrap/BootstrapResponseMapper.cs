using SignaCore.Host.Models;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// Projects an inspection onto the wire model shared by the unauthenticated bootstrap surface and
/// the authenticated editor, so both describe a target the same way.
/// </summary>
internal static class BootstrapResponseMapper
{
    public static BootstrapTestResponse Describe(BootstrapOperationResult result)
    {
        var inspection = result.Inspection;
        if (inspection is null)
        {
            return new BootstrapTestResponse
            {
                Target = "unreachable",
                MasterKey = "not_applicable",
                Message = result.Message
            };
        }

        return new BootstrapTestResponse
        {
            Target = inspection.Kind switch
            {
                BootstrapTargetKind.Empty => "empty",
                BootstrapTargetKind.PendingInstallation => "pending_installation",
                BootstrapTargetKind.CompletedInstallation => "completed_installation",
                BootstrapTargetKind.LegacyData => "legacy_data",
                _ => "unreachable"
            },
            Endpoint = inspection.Endpoint,
            CanConnect = inspection.CanConnect,
            HasProtectedData = inspection.HasProtectedData,
            MasterKey = inspection.KeyCompatibility switch
            {
                MasterKeyCompatibility.Compatible => "compatible",
                MasterKeyCompatibility.Incompatible => "incompatible",
                _ => "not_applicable"
            },
            InstallationId = inspection.InstallationId?.ToString(),
            Message = result.Message
        };
    }
}
