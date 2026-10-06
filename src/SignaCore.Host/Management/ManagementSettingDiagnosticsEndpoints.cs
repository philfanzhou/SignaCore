using System.Buffers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;
using ServiceMantle.Configuration;

namespace SignaCore.Host.Management;

/// <summary>
/// The product settings diagnostics endpoint on the shared management API v1 group:
/// <c>GET /management/v1/settings/diagnostics</c>.
/// </summary>
/// <remarks>
/// The answer is built from exactly one complete tolerant materialization of the stored aggregate
/// — the same isolated management loader the current-values query uses, never the runtime
/// authority — plus the fixed startup <see cref="InstallationRuntimeState"/>. It answers
/// <c>{version, runningVersion, issues}</c> only when that materialization fully succeeded:
/// <c>version</c> is the version the complete save was observed at, <c>runningVersion</c> is what
/// this process activated at bootstrap, and <c>issues</c> names the saved version's unusable
/// optional rules as closed key + error-code pairs. Issues make no claim about the running sink:
/// a saved version may be healthy while the process still runs an older snapshot. Any load,
/// decrypt, or critical failure is the shared fixed 503 with no partial or stale result, and no
/// endpoint, credential, exception, or arbitrary value is ever returned. The endpoint has no
/// query parameters; any query string is a fixed 400. Caller cancellation propagates the request
/// token instead of a success or error classification.
/// </remarks>
internal static class ManagementSettingDiagnosticsEndpoints
{
    internal const string DiagnosticsPath = "/settings/diagnostics";

    private static readonly FixedJsonResult InvalidRequest = FixedJsonResult.Create(
        """{"errorCode":"management.request.invalid"}""", StatusCodes.Status400BadRequest);

    private static readonly FixedJsonResult Unavailable = FixedJsonResult.Create(
        """{"errorCode":"management.settings.unavailable"}""", StatusCodes.Status503ServiceUnavailable);

    internal static void Map(RouteGroupBuilder managementApi)
    {
        // The handler is assigned to an explicit Func first: passing the method group directly
        // binds it as a plain RequestDelegate whose Task<IResult> result would be discarded.
        Func<HttpContext, Task<IResult>> handler = GetDiagnosticsAsync;
        managementApi.MapGet(DiagnosticsPath, handler);
    }

    private static async Task<IResult> GetDiagnosticsAsync(HttpContext context)
    {
        try
        {
            context.RequestAborted.ThrowIfCancellationRequested();
            // This endpoint has no query parameters; an unknown or malformed one is a fixed 400.
            if (context.Request.QueryString.HasValue)
                return InvalidRequest;

            var snapshot = context.RequestServices.GetRequiredService<ManagementSettingQuerySnapshot>();
            var runtimeState = context.RequestServices.GetRequiredService<InstallationRuntimeState>();
            var diagnostics = await snapshot.GetDiagnosticsAsync(context.RequestAborted);
            context.RequestAborted.ThrowIfCancellationRequested();
            if (!diagnostics.Succeeded)
                return Unavailable;

            return FixedJsonResult.Create(
                BuildBody(diagnostics, runtimeState.ConfigurationVersion),
                StatusCodes.Status200OK);
        }
        catch (Exception exception) when (
            exception is OperationCanceledException
            || (exception is System.IO.IOException or ObjectDisposedException
                && context.RequestAborted.IsCancellationRequested))
        {
            // The caller's own cancellation stays an unclassified abort wherever it is observed.
            throw new OperationCanceledException(
                "The settings diagnostics request was cancelled by the caller.",
                context.RequestAborted);
        }
        catch
        {
            // Nothing about an unexpected failure is safe to classify or echo: fixed 503 only.
            return Unavailable;
        }
    }

    /// <summary>
    /// Renders the closed diagnostics body. Keys come from the product validator's registered
    /// optional keys and codes from its fixed closed set — neither is assembled from request input.
    /// </summary>
    private static string BuildBody(ManagementSettingDiagnostics diagnostics, int runningVersion)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("version", diagnostics.Version);
            writer.WriteNumber("runningVersion", runningVersion);
            writer.WriteStartArray("issues");
            foreach (var issue in diagnostics.Issues)
            {
                writer.WriteStartObject();
                if (issue.Key is null) writer.WriteNull("key");
                else writer.WriteString("key", issue.Key);
                writer.WriteString("errorCode", issue.ErrorCode);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }
}
