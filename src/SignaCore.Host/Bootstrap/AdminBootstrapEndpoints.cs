using Microsoft.AspNetCore.Http;
using ServiceMantle.AspNetCore.Management;
using ServiceMantle.AspNetCore.ManagementApi;
using ServiceMantle.AspNetCore.ManagementApi.Entries;
using ServiceMantle.AspNetCore.RateLimiting;
using ServiceMantle.Bootstrap;
using SignaCore.Host.Models;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// Maps the authenticated bootstrap overview and target probe of the installed host:
/// <c>GET /api/admin/bootstrap</c> and <c>POST /api/admin/bootstrap/test</c>.
/// </summary>
/// <remarks>
/// The write path moved to the shared update entry <c>PUT {v1}/bootstrap</c>; what remains here is
/// what that entry deliberately does not offer — the current file's safe overview and the
/// classification of a candidate target before anything is committed. Both entries keep the fixed
/// management cookie session plus the administrator permission and the shared management
/// rate-limit policy, and the probe carries the shared unsafe-request guard header. Neither entry
/// writes anything: no file, no audit row, no target database.
/// </remarks>
internal static class AdminBootstrapEndpoints
{
    private const string OverviewPath = "/api/admin/bootstrap";
    private const string TestPath = "/api/admin/bootstrap/test";

    private const string ScopeNotice =
        "This edits the bootstrap file of the instance that served the request. Distributing the " +
        "file to other instances and restarting them are orchestrator responsibilities.";

    public static void Map(WebApplication app)
    {
        app.MapGet(OverviewPath, (HttpContext context) =>
        {
            var bootstrap = context.RequestServices.GetRequiredService<BootstrapConfiguration>();
            var service = context.RequestServices.GetRequiredService<BootstrapConfigurationService>();

            return Results.Json(new BootstrapSettingsResponse
            {
                Provider = bootstrap.Database.Provider,
                ServerVersion = bootstrap.Database.ServerVersion,
                Endpoint = BootstrapDiagnostics.DescribeEndpoint(bootstrap.Database),
                FilePath = service.FilePath,
                // The key is never read back out of the file by any API; the console only learns it is set.
                MasterKeyConfigured = true,
                Editable = bootstrap.SourcePath is not null,
                SingleInstanceOnly = string.Equals(
                    bootstrap.Database.Provider,
                    "SQLite",
                    StringComparison.OrdinalIgnoreCase),
                ScopeNotice = ScopeNotice
            });
        })
        .RequireAuthorization(
            ManagementAuthorizationDefaults.AdminPolicyName,
            ManagementAuthorizationDefaults.SessionPolicyName)
        .RequireRateLimiting(RateLimitingDefaults.ManagementPolicyName);

        app.MapPost(TestPath, async (HttpContext context) =>
        {
            var guard = context.Request.Headers[ManagementEntryDefaults.UnsafeRequestHeaderName];
            if (guard.Count != 1 || !string.Equals(
                    guard[0],
                    ManagementEntryDefaults.UnsafeRequestHeaderValue,
                    StringComparison.Ordinal))
            {
                return ManagementApiResults.InvalidRequest();
            }

            BootstrapTestRequest? request;
            try
            {
                request = await context.Request.ReadFromJsonAsync<BootstrapTestRequest>(
                    cancellationToken: context.RequestAborted);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return ManagementApiResults.InvalidRequest();
            }

            if (request is null)
            {
                return ManagementApiResults.InvalidRequest();
            }

            // A blank key keeps the running one, exactly like the editor this replaces: the probe
            // answers "would this target work" against the key the instance would keep.
            var bootstrap = context.RequestServices.GetRequiredService<BootstrapConfiguration>();
            var candidateKey = string.IsNullOrWhiteSpace(request.MasterKey)
                ? bootstrap.MasterKey
                : request.MasterKey.Trim();

            var service = context.RequestServices.GetRequiredService<BootstrapConfigurationService>();
            var result = await service.TestAsync(request.Database, candidateKey, context.RequestAborted);
            if (result.Outcome == BootstrapOutcome.InvalidRequest)
            {
                return ManagementApiResults.InvalidRequest();
            }

            return Results.Json(BootstrapResponseMapper.Describe(result));
        })
        .RequireAuthorization(
            ManagementAuthorizationDefaults.AdminPolicyName,
            ManagementAuthorizationDefaults.SessionPolicyName)
        .RequireRateLimiting(RateLimitingDefaults.ManagementPolicyName);
    }
}
