using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Models;

namespace SignaCore.Host.Controllers;

/// <summary>
/// Bootstrap Configuration Mode API: the surface that exists when SignaCore has no bootstrap file
/// and therefore no database to talk to.
/// <para>
/// MVC discovers controllers from the assembly, so this one is mapped by every host. What differs is
/// the composition: <see cref="BootstrapConfigurationService"/> and
/// <see cref="BootstrapCodeAuthority"/> are registered only while the bootstrap file is missing, so
/// a configured instance can report its state but can never rewrite the file from here — that is the
/// authenticated <see cref="AdminBootstrapController"/>'s job.
/// </para>
/// </summary>
[ApiController]
[Route("api/bootstrap")]
public sealed class BootstrapController : ControllerBase
{
    internal const string RateLimitPolicy = "bootstrap";

    private readonly BootstrapConfigurationService? _service;
    private readonly BootstrapCodeAuthority? _codeAuthority;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger<BootstrapController> _logger;

    // Resolved through the request scope rather than as constructor parameters: the bootstrap types
    // are internal, and a configured host deliberately does not register them at all.
    public BootstrapController(
        IServiceProvider services,
        IHostApplicationLifetime lifetime,
        ILogger<BootstrapController> logger)
    {
        _service = services.GetService<BootstrapConfigurationService>();
        _codeAuthority = services.GetService<BootstrapCodeAuthority>();
        _lifetime = lifetime;
        _logger = logger;
    }

    private bool IsBootstrapMode => _service is not null && _codeAuthority is not null;

    /// <summary>
    /// Whether this instance still needs a bootstrap file. Unauthenticated by necessity — nothing
    /// exists yet to authenticate against — so it discloses only the state and the file path.
    /// </summary>
    [HttpGet("status")]
    public ActionResult<BootstrapStatusResponse> GetStatus()
    {
        if (!IsBootstrapMode)
        {
            // A configured instance discloses nothing further here: the file path is only useful to
            // whoever is about to write it, and this endpoint has no caller to authenticate.
            return Ok(new BootstrapStatusResponse { Status = "configured" });
        }

        return Ok(new BootstrapStatusResponse
        {
            Status = _codeAuthority!.IsConsumed ? "restarting" : "required",
            FilePath = _service!.FilePath,
            SupportedProviders = BootstrapProviderCatalog.Descriptors
        });
    }

    /// <summary>
    /// Opens the candidate database and reports what is in it, without writing anything. Gated by
    /// the same one-time code as the save so it cannot be used as an unauthenticated network probe.
    /// </summary>
    [HttpPost("test")]
    [EnableRateLimiting(RateLimitPolicy)]
    public async Task<ActionResult<BootstrapTestResponse>> TestAsync(
        [FromBody] BootstrapTestRequest request,
        CancellationToken cancellationToken)
    {
        if (!IsBootstrapMode)
        {
            return Conflict(new BootstrapSaveResponse
            {
                Status = "already_configured",
                Message = "This instance already has a bootstrap configuration."
            });
        }

        if (!_codeAuthority!.Verify(request.BootstrapCode))
        {
            return RejectCode();
        }

        var result = await _service!.TestAsync(request.Database, request.MasterKey, cancellationToken);
        if (result.Outcome == BootstrapOutcome.InvalidRequest)
        {
            return BadRequest(new BootstrapSaveResponse
            {
                Status = "invalid_request",
                Message = result.Message
            });
        }

        return Ok(BootstrapResponseMapper.Describe(result));
    }

    [HttpPost("save")]
    [EnableRateLimiting(RateLimitPolicy)]
    public async Task<ActionResult<BootstrapSaveResponse>> SaveAsync(
        [FromBody] BootstrapSaveRequest request,
        CancellationToken cancellationToken)
    {
        if (!IsBootstrapMode)
        {
            return Conflict(new BootstrapSaveResponse
            {
                Status = "already_configured",
                Message = "This instance already has a bootstrap configuration and cannot recreate it here."
            });
        }

        using var saveLease = await _codeAuthority!.AcquireSaveLeaseAsync(cancellationToken);

        if (!_codeAuthority.Verify(request.BootstrapCode))
        {
            return RejectCode();
        }

        var result = await _service!.CreateAsync(request, cancellationToken);

        switch (result.Outcome)
        {
            case BootstrapOutcome.Succeeded:
                _codeAuthority.Consume();
                ScheduleRestart();
                return Ok(new BootstrapSaveResponse
                {
                    Status = "saved",
                    Message = result.Message
                });

            case BootstrapOutcome.TargetUnreachable:
                return BadRequest(new BootstrapSaveResponse
                {
                    Status = "database_unreachable",
                    Message = result.Message
                });

            case BootstrapOutcome.MasterKeyMismatch:
                return BadRequest(new BootstrapSaveResponse
                {
                    Status = "master_key_mismatch",
                    Message = result.Message
                });

            case BootstrapOutcome.WriteFailed:
                return StatusCode(StatusCodes.Status500InternalServerError, new BootstrapSaveResponse
                {
                    Status = "write_failed",
                    Message = result.Message
                });

            default:
                return BadRequest(new BootstrapSaveResponse
                {
                    Status = "invalid_request",
                    Message = result.Message
                });
        }
    }

    private ActionResult RejectCode()
    {
        _logger.LogWarning(
            "Rejected bootstrap configuration: invalid or already used bootstrap code. ClientIp={ClientIp}",
            HttpContext.Connection.RemoteIpAddress);

        return StatusCode(StatusCodes.Status403Forbidden, new BootstrapSaveResponse
        {
            Status = "invalid_bootstrap_code",
            Message = "The bootstrap code is invalid, expired, or has already been used. " +
                      "Restart SignaCore to have a new one printed to standard output."
        });
    }

    /// <summary>
    /// Restarts the process rather than composing an identity service around a database that was
    /// unknown a moment ago. The response has to finish first, or the browser never learns that the
    /// configuration was accepted.
    /// </summary>
    private void ScheduleRestart()
    {
        HttpContext.Response.OnCompleted(() =>
        {
            _logger.LogInformation(
                "Stopping the bootstrap-mode host so a supervisor can restart it with the new bootstrap file.");
            _lifetime.StopApplication();
            return Task.CompletedTask;
        });
    }
}
