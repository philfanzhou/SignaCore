using ServiceMantle.Audit;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Host.Installation;

/// <summary>
/// The closed projection from the shared installation-completed audit event onto SignaCore's
/// existing <c>audit_logs</c> row.
/// <para>
/// It accepts exactly one event shape — the shared <c>installation.completed</c> action on the
/// <c>signacore</c> service target with a successful outcome, a <c>setup_code</c> operator whose
/// identifier is the account this setup created, and no metadata — and rejects everything else
/// before staging anything. The operator source means the installation was authorized by the
/// one-time setup code, not that an administrative session already existed.
/// </para>
/// <para>
/// The product username is identity data the existing audit row keeps, so it is supplied by the
/// caller through the constructor instead of travelling through the shared event. This writer is
/// not a general-purpose adapter: it never receives passwords, setup codes, root keys, or
/// settings values, and no caller-supplied free text reaches the staged row beyond the shared
/// event's already-sanitized description and client IP.
/// </para>
/// </summary>
internal sealed class SetupAuditWriter : IManagementAuditWriter
{
    internal const string LegacyAction = "installation.setup.completed";
    internal const string LegacyTargetType = "Installation";

    /// <summary>
    /// The operator source that means "authorized by the one-time setup code". A consumer-defined
    /// source; the shared well-known set has no installation-code entry.
    /// </summary>
    internal static readonly ManagementAuditOperatorSource OperatorSource =
        ManagementAuditOperatorSource.Parse("setup_code");

    private static readonly ManagementAuditAction AcceptedAction =
        WellKnownManagementAuditActions.InstallationCompleted;

    private static readonly ManagementAuditTargetType AcceptedTargetType =
        WellKnownManagementAuditTargetTypes.Service;

    private readonly IdentityDbContext _db;
    private readonly string _actorName;

    internal SetupAuditWriter(IdentityDbContext db, string actorName)
    {
        _db = db;
        _actorName = actorName;
    }

    public ValueTask<ManagementAuditRecord> RecordAsync(
        ManagementAuditEvent auditEvent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);
        cancellationToken.ThrowIfCancellationRequested();

        if (!IsAcceptedShape(auditEvent))
        {
            throw new InvalidOperationException(
                "The setup audit writer only accepts the fixed installation-completed event.");
        }

        var id = Guid.NewGuid();
        _db.AuditLogs.Add(new AuditLogEntity
        {
            Id = id,
            Action = LegacyAction,
            TargetType = LegacyTargetType,
            TargetId = auditEvent.Target.Id,
            ActorId = Guid.ParseExact(auditEvent.Operator.OperatorId!, "D"),
            ActorName = _actorName,
            // Deliberately no before/after snapshots: they would carry setting values, and some of
            // those settings are secrets.
            BeforeSnapshot = null,
            AfterSnapshot = null,
            Description = auditEvent.SecurityDescription,
            ClientIp = auditEvent.ClientIp,
            CorrelationId = auditEvent.CorrelationId,
            CreatedAt = auditEvent.OccurredAtUtc
        });

        // The returned record shares the staged row's identifier and the shared event's fields; it
        // does not claim the row was saved.
        return ValueTask.FromResult(new ManagementAuditRecord(
            id,
            auditEvent.Operator,
            auditEvent.Action,
            auditEvent.Target,
            auditEvent.Outcome,
            auditEvent.OccurredAtUtc,
            auditEvent.ClientIp,
            auditEvent.CorrelationId,
            auditEvent.SecurityDescription,
            auditEvent.Metadata));
    }

    private static bool IsAcceptedShape(ManagementAuditEvent auditEvent) =>
        auditEvent.Action.Equals(AcceptedAction)
        && auditEvent.Target.Type.Equals(AcceptedTargetType)
        && string.Equals(auditEvent.Target.Id, InstallationStores.ServiceIdValue, StringComparison.Ordinal)
        && auditEvent.Outcome == ManagementAuditOutcome.Success
        && auditEvent.Operator.Source.Equals(OperatorSource)
        && auditEvent.Operator.OperatorId is not null
        && Guid.TryParseExact(auditEvent.Operator.OperatorId, "D", out _)
        && auditEvent.Operator.DisplayName is null
        && auditEvent.Metadata.Count == 0;
}
