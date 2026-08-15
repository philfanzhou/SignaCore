using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SignaCore.Database;
using SignaCore.Domain.Services;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Http;
using SignaCore.Host.Models;

namespace SignaCore.Host.Controllers;

/// <summary>
/// Authenticated editing of the bootstrap file after installation.
/// <para>
/// This surface is deliberately narrower than <see cref="AdminSettingsController"/>. Database-backed
/// settings are cluster-wide, transactional, and versioned; the bootstrap file is a local file on one
/// instance's disk. A write here changes the instance that served the request and nothing else, and
/// the response says so rather than implying the cluster was updated.
/// </para>
/// </summary>
[ApiController]
[Route("api/admin/bootstrap")]
[Authorize(Policy = "AdminSession")]
public sealed class AdminBootstrapController : ControllerBase
{
    private const string ScopeNotice =
        "This edits the bootstrap file of the instance that served the request. Distributing the " +
        "file to other instances and restarting them are orchestrator responsibilities.";

    private readonly BootstrapConfiguration? _bootstrap;
    private readonly BootstrapConfigurationService? _service;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger<AdminBootstrapController> _logger;

    // The bootstrap types are internal, so they are resolved from the request scope rather than
    // declared as constructor parameters — MVC activates controllers through a public constructor.
    public AdminBootstrapController(
        IServiceProvider services,
        IHostApplicationLifetime lifetime,
        ILogger<AdminBootstrapController> logger)
    {
        _bootstrap = services.GetService<BootstrapConfiguration>();
        _service = services.GetService<BootstrapConfigurationService>();
        _lifetime = lifetime;
        _logger = logger;
    }

    [HttpGet]
    public ActionResult<BootstrapSettingsResponse> Get()
    {
        if (_bootstrap is null || _service is null)
        {
            return Conflict(new ErrorResponse(
                "This instance is not running from a bootstrap file, so there is nothing to edit."));
        }

        return Ok(new BootstrapSettingsResponse
        {
            Provider = _bootstrap.Database.Provider,
            ServerVersion = _bootstrap.Database.ServerVersion,
            Endpoint = _bootstrap.DatabaseEndpointForDiagnostics,
            FilePath = _service.FilePath,
            // The key is never read back out of the file by any API; the console only learns it is set.
            MasterKeyConfigured = true,
            Editable = IsFileBacked(),
            SingleInstanceOnly = _bootstrap.Database.ProviderKind == DatabaseProvider.Sqlite,
            ScopeNotice = ScopeNotice,
            SupportedProviders = BootstrapProviderCatalog.Descriptors
        });
    }

    /// <summary>
    /// Classifies a candidate database without changing anything, so the operator sees whether they
    /// are about to point this instance at its own installation, an empty database, or a database
    /// holding incompatible SignaCore data.
    /// </summary>
    [HttpPost("test")]
    public async Task<ActionResult<BootstrapTestResponse>> TestAsync(
        [FromBody] UpdateBootstrapRequest request,
        CancellationToken cancellationToken)
    {
        if (_bootstrap is null || _service is null)
        {
            return Conflict(new ErrorResponse("This instance is not running from a bootstrap file."));
        }

        var candidateKey = string.IsNullOrWhiteSpace(request.MasterKey)
            ? _bootstrap.RootSecret
            : request.MasterKey.Trim();

        var result = await _service.TestAsync(request.Database, candidateKey, cancellationToken);
        if (result.Outcome == BootstrapOutcome.InvalidRequest)
        {
            return BadRequest(new ErrorResponse(result.Message));
        }

        return Ok(BootstrapResponseMapper.Describe(result));
    }

    [HttpPut]
    public async Task<ActionResult<BootstrapSaveResponse>> UpdateAsync(
        [FromBody] UpdateBootstrapRequest request,
        [FromServices] IAuditService auditService,
        CancellationToken cancellationToken)
    {
        if (_bootstrap is null || _service is null)
        {
            return Conflict(new ErrorResponse("This instance is not running from a bootstrap file."));
        }

        if (!IsFileBacked())
        {
            return Conflict(new ErrorResponse(
                "This instance loaded its bootstrap from a Development fallback rather than the " +
                "bootstrap file, so writing the file here would not describe what it is running."));
        }

        if (!request.Confirm)
        {
            return BadRequest(new ErrorResponse(
                "Changing the database target requires explicit confirmation and restarts this instance."));
        }

        // A blank key means "keep the current one". Direct replacement of a live key is refused:
        // rotation has to rewrap every stored signing key and secret setting first, which is a
        // transactional data operation and not a configuration edit.
        var replacementKey = string.IsNullOrWhiteSpace(request.MasterKey) ? null : request.MasterKey.Trim();
        if (replacementKey is not null &&
            !string.Equals(replacementKey, _bootstrap.RootSecret, StringComparison.Ordinal))
        {
            var candidate = await _service.TestAsync(request.Database, replacementKey, cancellationToken);
            if (candidate.Outcome == BootstrapOutcome.InvalidRequest)
            {
                return BadRequest(new ErrorResponse(candidate.Message));
            }

            // Accepting a different key is only safe when it is the key the *target* already uses.
            if (candidate.Inspection is { KeyCompatibility: not MasterKeyCompatibility.Compatible })
            {
                return BadRequest(new ErrorResponse(
                    "The master key cannot be replaced from here. It may only be supplied when it is " +
                    "the key the target database's existing data was protected with. Rotating a live " +
                    "key requires rewrapping every stored signing key and secret setting first."));
            }
        }

        var result = await _service.ReplaceDatabaseAsync(
            request.Database,
            _bootstrap.RootSecret,
            replacementKey,
            cancellationToken);

        switch (result.Outcome)
        {
            case BootstrapOutcome.Succeeded:
                break;

            case BootstrapOutcome.TargetUnreachable:
                return BadRequest(new ErrorResponse(result.Message));

            case BootstrapOutcome.MasterKeyMismatch:
                return BadRequest(new ErrorResponse(result.Message));

            case BootstrapOutcome.WriteFailed:
                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse(result.Message));

            default:
                return BadRequest(new ErrorResponse(result.Message));
        }

        var actorId = Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : (Guid?)null;
        // Provider and endpoint only. Recording the connection string here would put the database
        // password into the audit trail.
        await auditService.RecordActionAsync(
            "bootstrap_updated",
            "Bootstrap",
            _service.FilePath,
            actorId,
            User.Identity?.Name,
            $"Bootstrap database target changed to {result.Inspection?.Endpoint} " +
            $"({request.Database.Provider}) on this instance.",
            HttpContext.GetClientIp());

        ScheduleRestart();

        return Ok(new BootstrapSaveResponse
        {
            Status = "saved",
            Message = result.Message + " " + ScopeNotice
        });
    }

    /// <summary>
    /// True when this process actually loaded the file it would be writing. A Development fallback
    /// host runs from appsettings, so writing the file would silently disagree with what it runs.
    /// </summary>
    private bool IsFileBacked()
    {
        if (_bootstrap is null || _service is null)
        {
            return false;
        }

        try
        {
            return string.Equals(
                Path.GetFullPath(_bootstrap.Origin),
                Path.GetFullPath(_service.FilePath),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (ArgumentException)
        {
            // The fallback origin is a description, not a path.
            return false;
        }
    }

    private void ScheduleRestart()
    {
        HttpContext.Response.OnCompleted(() =>
        {
            _logger.LogInformation(
                "Stopping so a supervisor can restart this instance against the new bootstrap target.");
            _lifetime.StopApplication();
            return Task.CompletedTask;
        });
    }
}
