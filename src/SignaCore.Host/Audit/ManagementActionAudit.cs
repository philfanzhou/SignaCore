using System.Net;
using ServiceMantle.Audit;

namespace SignaCore.Host.Audit;

/// <summary>
/// The single projection of SignaCore's action-audit call shape onto the shared
/// <see cref="ManagementAuditEvent"/> model, staged through the shared
/// <see cref="IManagementAuditWriter"/> (the EF Core writer onto <c>service_audit_logs</c>).
/// </summary>
/// <remarks>
/// The staged row participates in the caller's unit of work: the caller's single
/// <c>SaveChangesAsync</c> (and explicit transaction, when one is open) persists the business
/// change and the audit row together, and an audit refusal fails the business action instead of
/// being swallowed. The legacy before/after JSON snapshots are deliberately not reproduced: the
/// shared model carries the closed description and, where a caller has security-relevant counts,
/// folds them into the description text. A forwarded client IP that is not a parseable address
/// degrades to "no client IP" rather than failing the action.
/// </remarks>
internal static class ManagementActionAudit
{
    /// <summary>An administrator acting through the interactive management session.</summary>
    internal static readonly ManagementAuditOperatorSource AdminSource =
        WellKnownManagementAuditOperatorSources.InteractiveAdmin;

    /// <summary>An authenticated end-user account (profile and interactive-login flows).</summary>
    internal static readonly ManagementAuditOperatorSource AccountSource =
        ManagementAuditOperatorSource.Parse("signacore.account");

    /// <summary>The service itself, with no human operator involved.</summary>
    internal static readonly ManagementAuditOperatorSource SystemSource =
        WellKnownManagementAuditOperatorSources.System;

    internal static async ValueTask RecordAsync(
        IManagementAuditWriter writer,
        ManagementAuditOperatorSource operatorSource,
        string action,
        string targetType,
        string targetId,
        Guid? actorId,
        string? actorName,
        string? description,
        string? clientIp = null,
        string? correlationId = null,
        ManagementAuditOutcome outcome = ManagementAuditOutcome.Success,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(operatorSource);

        string? parsedClientIp = null;
        if (clientIp is not null && IPAddress.TryParse(clientIp, out var address))
        {
            parsedClientIp = address.ToString();
        }

        var auditEvent = ManagementAuditEvent.Create(
            ManagementAuditOperator.Create(
                operatorSource,
                actorId?.ToString("D"),
                actorName),
            ManagementAuditAction.Parse(action),
            ManagementAuditTarget.Create(ManagementAuditTargetType.Parse(targetType), targetId),
            outcome,
            clientIp: parsedClientIp,
            correlationId: correlationId,
            securityDescription: description);
        await writer.RecordAsync(auditEvent, cancellationToken);
    }
}
