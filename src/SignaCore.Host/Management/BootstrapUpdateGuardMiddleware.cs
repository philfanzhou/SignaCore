using ServiceMantle.Bootstrap;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Http;

namespace SignaCore.Host.Management;

/// <summary>
/// The SignaCore-side guard and consequence hook around the shared bootstrap update entry
/// <c>PUT /management/v1/bootstrap</c>.
/// </summary>
/// <remarks>
/// The shared entry owns parsing, candidate validation, publication, and the restart latch; two
/// SignaCore rules cannot be expressed in its request shape and therefore run here, in the
/// pipeline after the shared authorization: this host writes the file only when it actually
/// loaded it from the file (a Development fallback host would otherwise write a file that
/// disagrees with what it runs), and a database change must carry the explicit confirmation
/// header the console maps its confirmation checkbox onto. Both refusals answer before the
/// shared handler is reached, so an unauthorized or unconfirmed request never opens the target.
/// <para>
/// After the shared handler ran, the response decides the consequences: a published update
/// (including saving the identical target again) writes the <c>bootstrap_updated</c> audit row
/// with the operator of the shared management session and stops the process once the response
/// completed; a caller-aborted request audits and stops when the file changed; everything else
/// — refused, unavailable, or unchanged-and-aborted — leaves no audit row and keeps the process
/// running. The audit description names the provider and the redacted endpoint only, never the
/// connection string or the master key.
/// </para>
/// </remarks>
internal sealed class BootstrapUpdateGuardMiddleware(
    RequestDelegate next,
    ILogger<BootstrapUpdateGuardMiddleware> logger)
{
    private const string UpdatePath = "/management/v1/bootstrap";
    private const string ConfirmHeaderName = "X-SignaCore-Confirm-Database-Change";

    private const string NotFileBackedErrorCode = "signacore.bootstrap.not_file_backed";
    private const string ConfirmationRequiredErrorCode = "signacore.bootstrap.confirmation_required";

    public async Task InvokeAsync(HttpContext context)
    {
        if (!HttpMethods.IsPut(context.Request.Method) ||
            !string.Equals(context.Request.Path.Value, UpdatePath, StringComparison.Ordinal))
        {
            await next(context);
            return;
        }

        // Authorization has already run in the shared pipeline, so an unauthenticated or
        // unauthorized caller never reaches these host rules; an authenticated operator meets the
        // fallback and confirmation checks in that order.
        var bootstrap = context.RequestServices.GetRequiredService<BootstrapConfiguration>();
        if (bootstrap.SourcePath is null)
        {
            logger.LogInformation(
                "Refused a bootstrap update because this host runs from a Development fallback, " +
                "not from the bootstrap file.");
            context.Response.StatusCode = StatusCodes.Status409Conflict;
            await context.Response.WriteAsJsonAsync(new { errorCode = NotFileBackedErrorCode });
            return;
        }

        var confirmation = context.Request.Headers[ConfirmHeaderName];
        if (confirmation.Count != 1 ||
            !string.Equals(confirmation[0], "1", StringComparison.Ordinal))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsJsonAsync(new { errorCode = ConfirmationRequiredErrorCode });
            return;
        }

        var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
        var before = TryLoad(configuration);
        try
        {
            await next(context);
        }
        finally
        {
            // The decision never masks the outcome it observes: every path here is exception-safe.
            try
            {
                await DecideConsequencesAsync(context, configuration, before);
            }
            catch (Exception exception)
            {
                // The exception detail is deliberately absent: a persistence failure may name the
                // database target, and the fixed line stays free of connection strings and keys.
                logger.LogError(
                    "Deciding the consequences of a bootstrap update failed. The restart latch " +
                    "the shared entry set still reports whether a restart is required. Failure: {FailureType}",
                    exception.GetType().Name);
            }
        }
    }

    private async Task DecideConsequencesAsync(
        HttpContext context,
        IConfiguration configuration,
        BootstrapConfiguration? before)
    {
        if (context.Response.StatusCode == StatusCodes.Status200OK &&
            context.Response.HasStarted)
        {
            // Published — even when the candidate equalled the running file: the shared manager
            // still replaces it and latches the restart, so the audit row and the stop follow.
            var published = TryLoad(configuration);
            if (published is null)
            {
                logger.LogError(
                    "The bootstrap file was published but can no longer be read, so no " +
                    "bootstrap_updated audit row was written. The instance is still stopping; the " +
                    "restart path owns reporting the unreadable file.");
                StopOnceTheResponseCompleted(context);
                return;
            }

            if (!await TryWriteAuditAsync(context, published))
            {
                logger.LogError(
                    "The bootstrap_updated audit row could not be written. The bootstrap change " +
                    "itself is not affected and the instance is still stopping.");
            }

            StopOnceTheResponseCompleted(context);
            return;
        }

        if (context.RequestAborted.IsCancellationRequested)
        {
            // The status code is unusable: the file decides. An unchanged file under an aborted
            // request is a documented non-guarantee — nothing is audited and nothing stops.
            if (before is null)
            {
                return;
            }

            var after = TryLoad(configuration);
            if (after is null || SameTarget(before, after))
            {
                return;
            }

            if (!await TryWriteAuditAsync(context, after))
            {
                logger.LogError(
                    "The bootstrap_updated audit row could not be written. The bootstrap change " +
                    "itself is not affected and the instance is still stopping.");
            }

            logger.LogInformation(
                "A bootstrap update was published but its response was aborted; stopping so a " +
                "supervisor can restart this instance against the new bootstrap target.");
            context.RequestServices.GetRequiredService<IHostApplicationLifetime>()
                .StopApplication();
            return;
        }

        // Refused or unavailable: no audit row, no stop.
    }

    private async Task<bool> TryWriteAuditAsync(HttpContext context, BootstrapConfiguration published)
    {
        try
        {
            var operatorReader = context.RequestServices.GetRequiredService<ManagementOperatorReader>();
            var (actorId, actorName) = operatorReader.Read(context.User);
            // Provider and redacted endpoint only. Recording the connection string here would put
            // the database password into the audit trail.
            await context.RequestServices.GetRequiredService<IAuditService>().RecordActionAsync(
                "bootstrap_updated",
                "Bootstrap",
                context.RequestServices.GetRequiredService<BootstrapConfigurationService>().FilePath,
                actorId,
                actorName,
                $"Bootstrap database target changed to " +
                $"{BootstrapDiagnostics.DescribeEndpoint(published.Database)} " +
                $"({published.Database.Provider}) on this instance.",
                context.GetClientIp(),
                cancellationToken: CancellationToken.None);
            await context.RequestServices.GetRequiredService<IUnitOfWork>()
                .SaveChangesAsync(CancellationToken.None);
            return true;
        }
        catch (Exception exception)
        {
            // Fixed line without the exception detail: a persistence failure message may name the
            // database target, and no connection string or key may reach the log.
            logger.LogError(
                "Writing the bootstrap_updated audit row failed. Failure: {FailureType}",
                exception.GetType().Name);
            return false;
        }
    }

    private void StopOnceTheResponseCompleted(HttpContext context)
    {
        // Resolved while the request scope still exists: OnCompleted runs after the response
        // completed, when the request's service scope may already be gone.
        var lifetime = context.RequestServices.GetRequiredService<IHostApplicationLifetime>();
        try
        {
            context.Response.OnCompleted(() =>
            {
                logger.LogInformation(
                    "Stopping so a supervisor can restart this instance against the new bootstrap " +
                    "target.");
                lifetime.StopApplication();
                return Task.CompletedTask;
            });
        }
        catch (InvalidOperationException)
        {
            // The response already completed before the callback could be registered; the stop is
            // still owed.
            lifetime.StopApplication();
        }
    }

    private static BootstrapConfiguration? TryLoad(IConfiguration configuration)
    {
        try
        {
            return SignaCoreBootstrapStore.Create(configuration).Load();
        }
        catch (ServiceMantle.Bootstrap.BootstrapException)
        {
            return null;
        }
    }

    private static bool SameTarget(BootstrapConfiguration before, BootstrapConfiguration after) =>
        string.Equals(before.Database.Provider, after.Database.Provider, StringComparison.Ordinal) &&
        string.Equals(before.Database.ServerVersion, after.Database.ServerVersion, StringComparison.Ordinal) &&
        string.Equals(before.Database.ConnectionString, after.Database.ConnectionString, StringComparison.Ordinal) &&
        string.Equals(before.MasterKey, after.MasterKey, StringComparison.Ordinal);
}
