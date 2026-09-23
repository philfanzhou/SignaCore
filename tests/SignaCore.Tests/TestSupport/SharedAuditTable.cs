using Microsoft.EntityFrameworkCore;
using SignaCore.Database;

namespace SignaCore.Tests.TestSupport;

/// <summary>
/// Reads the shared <c>service_audit_logs</c> table, whose entity type is internal to the
/// ServiceMantle persistence assembly, through a portable quoted SQL projection that works on both
/// the SQLite test provider and PostgreSQL.
/// </summary>
internal static class SharedAuditTable
{
    public sealed record Row(
        string Id,
        string Action,
        string TargetType,
        string TargetId,
        string? OperatorId,
        string? OperatorDisplayName,
        string OperatorSource,
        string Outcome,
        string? SecurityDescription,
        string? ClientIp,
        string? CorrelationId,
        DateTime OccurredAtUtc);

    public static async Task<List<Row>> ReadAsync(
        IdentityDbContext context,
        CancellationToken cancellationToken = default) =>
        await context.Database
            .SqlQuery<Row>($"""
                SELECT "id" AS "Id",
                       "action" AS "Action",
                       "target_type" AS "TargetType",
                       "target_id" AS "TargetId",
                       "operator_id" AS "OperatorId",
                       "operator_display_name" AS "OperatorDisplayName",
                       "operator_source" AS "OperatorSource",
                       "outcome" AS "Outcome",
                       "security_description" AS "SecurityDescription",
                       "client_ip" AS "ClientIp",
                       "correlation_id" AS "CorrelationId",
                       "occurred_at_utc" AS "OccurredAtUtc"
                FROM service_audit_logs
                """)
            .ToListAsync(cancellationToken);

    public static async Task<bool> AnyAsync(
        IdentityDbContext context,
        CancellationToken cancellationToken = default) =>
        await context.Database
            .SqlQuery<int>($"""
                SELECT (CASE WHEN EXISTS (SELECT 1 FROM service_audit_logs) THEN 1 ELSE 0 END) AS "Value"
                """)
            .SingleAsync(cancellationToken) == 1;
}
