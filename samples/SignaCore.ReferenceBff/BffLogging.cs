using ServiceMantle;
using ServiceMantle.AspNetCore;
using ServiceMantle.AspNetCore.Logging;
using ServiceMantle.Logging;
using SignaCore.ReferenceBff.Database;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SignaCore.ReferenceBff;

internal static class BffLogging
{
    // Registration only: the optional Setup composition still owns every shared HTTP middleware.
    internal static ServiceMantleBuilder AddServices(IServiceCollection services)
    {
        var mantle = services.AddServiceMantle(ReferenceBffServiceMantle.ServiceId,
            InstanceId.Parse("reference-bff-local"));
        services.TryAddSingleton<BffOperationLog>();
        return mantle;
    }
}

internal enum BffLogOperation { WebHost, Login, UserInfo, Authorization, Setup, Logout }
internal enum BffLogOutcome { Started, Succeeded, Rejected }

/// <summary>
/// Projects only finite operation/outcome fields through the shared fail-closed sanitizer before
/// opening a shared identity scope. Never accepts message text, exceptions, identities or tokens.
/// </summary>
internal sealed class BffOperationLog(ILogger<BffOperationLog> logger, ServiceLogContext context)
{
    // This consumer projection does not replace the DI sanitizer or the shared sensitive-header
    // registry. The shared Serilog host independently sanitizes its complete output properties.
    private static readonly StructuredLogSanitizer Sanitizer = new(new StructuredLogSanitizerOptions
    {
        AllowedFieldNames = ["Operation", "Outcome"],
        AllowUnlistedFields = false,
        AllowUnlistedHeaders = false
    });

    internal void Record(BffLogOperation operation, Enum outcome, CancellationToken cancellationToken) =>
        WriteFields(new Dictionary<string, object?>
        {
            ["Operation"] = operation.ToString(),
            ["Outcome"] = outcome.ToString()
        }, cancellationToken);

    internal void WriteFields(IEnumerable<KeyValuePair<string, object?>> fields, CancellationToken cancellationToken)
    {
        var safe = Sanitizer.SanitizeFields(fields);
        cancellationToken.ThrowIfCancellationRequested();
        using var scope = context.BeginScope(logger, safe.Where(field => field.Value is not null));
        logger.LogInformation("Reference BFF operation completed.");
    }
}
