using Microsoft.AspNetCore.Http;
using ServiceMantle.AspNetCore.ManagementApi;
using ServiceMantle.AspNetCore.ManagementApi.Entries;
using ServiceMantle.AspNetCore.RateLimiting;
using ServiceMantle.Bootstrap;
using ServiceMantle.Installation;
using SignaCore.Host.Models;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// Maps the read-only target probe <c>POST /api/bootstrap/test</c> of Bootstrap Configuration
/// Mode.
/// </summary>
/// <remarks>
/// The entry is admitted only in <c>BootstrapConfiguration</c> and carries the shared setup
/// rate-limit policy. It requires the unsafe-request guard header and the one-time bootstrap
/// credential, verifies the credential without consuming it, and only then opens the target
/// through the retained inspector, answering with the same five-state classification and key
/// compatibility the product contract documents. It never writes anything.
/// </remarks>
internal static class BootstrapTestEndpoint
{
    private const string Path = "/api/bootstrap/test";
    private const string CredentialHeaderName = "X-ServiceMantle-Bootstrap-Credential";

    public static void Map(WebApplication app)
    {
        app.MapPost(Path, async (HttpContext context) =>
        {
            var guard = context.Request.Headers[ManagementEntryDefaults.UnsafeRequestHeaderName];
            if (guard.Count != 1 || !string.Equals(
                    guard[0],
                    ManagementEntryDefaults.UnsafeRequestHeaderValue,
                    StringComparison.Ordinal))
            {
                return ManagementApiResults.InvalidRequest();
            }

            var candidate = context.Request.Headers[CredentialHeaderName];
            if (candidate.Count != 1 || !BootstrapCredential.TryParse(candidate[0], out _))
            {
                return CredentialInvalid();
            }

            var verifier = context.RequestServices.GetRequiredService<IBootstrapCredentialVerifier>();
            BootstrapCredentialVerificationResult verification;
            try
            {
                verification = await verifier.VerifyAsync(candidate[0], context.RequestAborted);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return Unavailable();
            }

            if (verification.State == BootstrapCredentialVerificationState.Invalid)
            {
                // Refused before any database is opened: the probe must not become an
                // unauthenticated network reachability oracle.
                return CredentialInvalid();
            }

            if (verification.State == BootstrapCredentialVerificationState.Unavailable)
            {
                return Unavailable();
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

            var service = context.RequestServices.GetRequiredService<BootstrapConfigurationService>();
            var result = await service.TestAsync(
                request.Database,
                string.IsNullOrWhiteSpace(request.MasterKey) ? null : request.MasterKey.Trim(),
                context.RequestAborted);

            if (result.Outcome == BootstrapOutcome.InvalidRequest)
            {
                return ManagementApiResults.InvalidRequest();
            }

            return Results.Json(BootstrapResponseMapper.Describe(result));
        })
        .WithServiceMantlePhaseAdmission(ServiceStartupPhase.BootstrapConfiguration)
        .RequireRateLimiting(RateLimitingDefaults.SetupPolicyName);
    }

    private static IResult CredentialInvalid() => Results.Json(
        new { errorCode = "management.bootstrap.credential_invalid" },
        statusCode: StatusCodes.Status401Unauthorized);

    private static IResult Unavailable() => Results.Json(
        new { errorCode = "management.bootstrap.unavailable" },
        statusCode: StatusCodes.Status503ServiceUnavailable);
}
