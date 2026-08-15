using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SignaCore.Host.Installation;
using SignaCore.Host.Models;

namespace SignaCore.Host.Controllers;

/// <summary>
/// First-run setup API.
/// <para>
/// The same controller is mapped by both hosts, because MVC discovers controllers from the assembly
/// and a second "closed" controller on the same route would be an ambiguous match. What differs is
/// the composition: <see cref="InstallationSetupService"/> is registered only by the setup-mode
/// host, so once installation is complete the endpoints exist but can only report that — they can
/// never reinitialize.
/// </para>
/// </summary>
[ApiController]
[Route("api/setup")]
public sealed class SetupController : ControllerBase
{
    internal const string RateLimitPolicy = "setup";

    private readonly InstallationRuntimeState? _runtimeState;
    private readonly InstallationSetupService? _setupService;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger<SetupController> _logger;

    // Resolved through the request scope rather than declared as constructor parameters: the setup
    // types are internal, and the normal host deliberately does not register them at all.
    public SetupController(
        IServiceProvider services,
        IHostApplicationLifetime lifetime,
        ILogger<SetupController> logger)
    {
        _lifetime = lifetime;
        _logger = logger;
        _runtimeState = services.GetService<InstallationRuntimeState>();
        _setupService = services.GetService<InstallationSetupService>();
    }

    private bool IsSetupMode => _setupService is not null && _runtimeState is not null;

    [HttpGet("status")]
    public ActionResult<SetupStatusResponse> GetStatus()
    {
        if (!IsSetupMode || _runtimeState!.SetupCompleted)
        {
            return Ok(new SetupStatusResponse
            {
                Status = "completed",
                InstallationId = _runtimeState?.InstallationId.ToString() ?? string.Empty,
                Restarting = _runtimeState?.SetupCompleted ?? false
            });
        }

        return Ok(new SetupStatusResponse
        {
            Status = "pending",
            InstallationId = _runtimeState!.InstallationId.ToString(),
            Restarting = false
        });
    }

    [HttpPost("complete")]
    [EnableRateLimiting(RateLimitPolicy)]
    public async Task<ActionResult<SetupCompleteResponse>> CompleteAsync(
        [FromBody] SetupCompleteRequest request,
        CancellationToken cancellationToken)
    {
        if (!IsSetupMode || _runtimeState!.SetupCompleted)
        {
            return Conflict(new SetupCompleteResponse
            {
                Status = "already_completed",
                Message = "Installation has already been completed and cannot be reinitialized."
            });
        }

        if (!string.Equals(request.Password, request.ConfirmPassword, StringComparison.Ordinal))
        {
            return BadRequest(new SetupCompleteResponse
            {
                Status = "invalid_request",
                Message = "The password and its confirmation do not match."
            });
        }

        var result = await _setupService!.CompleteAsync(
            new SetupRequest(
                request.PublicBaseUrl,
                request.AllowNonHttpsIssuer,
                request.JwtAudience,
                request.Username,
                request.Password,
                request.SetupCode),
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            cancellationToken);

        switch (result.Outcome)
        {
            case SetupOutcome.InvalidSetupCode:
                _logger.LogWarning(
                    "Rejected first-run setup: invalid or expired setup code. ClientIp={ClientIp}",
                    HttpContext.Connection.RemoteIpAddress);
                return StatusCode(StatusCodes.Status403Forbidden, new SetupCompleteResponse
                {
                    Status = "invalid_setup_code",
                    Message = "The setup code is invalid or has expired."
                });

            case SetupOutcome.InvalidRequest:
                return BadRequest(new SetupCompleteResponse
                {
                    Status = "invalid_request",
                    Message = result.Error ?? "The request is invalid."
                });

            case SetupOutcome.AlreadyCompleted:
                // Another instance won the race. Nothing was changed by this request.
                _runtimeState.MarkSetupCompleted();
                ScheduleRestart();
                return Conflict(new SetupCompleteResponse
                {
                    Status = "already_completed",
                    Message = "Installation was completed by another instance."
                });

            default:
                _runtimeState.MarkSetupCompleted();
                ScheduleRestart();
                return Ok(new SetupCompleteResponse
                {
                    Status = "completed",
                    Message = "Configuration saved. The service is restarting."
                });
        }
    }

    /// <summary>
    /// Restarts the process rather than rebuilding JWT, CORS, LDAP, SMS, telemetry, and
    /// key-management singletons inside an already running container. The response has to finish
    /// first, otherwise the browser never learns that setup succeeded.
    /// </summary>
    private void ScheduleRestart()
    {
        HttpContext.Response.OnCompleted(() =>
        {
            _logger.LogInformation(
                "Stopping the setup-mode host so a supervisor can restart it into the normal host.");
            _lifetime.StopApplication();
            return Task.CompletedTask;
        });
    }
}
