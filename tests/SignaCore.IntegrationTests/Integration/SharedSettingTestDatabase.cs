using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Host.Installation;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Provider-neutral reads of the shared setting aggregate and the shared audit projection for
/// integration tests, mirroring the raw-SQL access the production bootstrap uses.
/// </summary>
internal static class SharedSettingTestDatabase
{
    /// <summary>Reads the shared aggregate row for SignaCore through provider-neutral SQL.</summary>
    public sealed class AggregateRow
    {
        public long Version { get; set; }

        public string ValuesJson { get; set; } = string.Empty;

        public string? UpdatedBy { get; set; }
    }

    /// <summary>
    /// Whether the retired <c>system_settings</c> table still exists in the target schema — the
    /// retirement-era form of the old "the legacy table stays empty" assertions.
    /// </summary>
    public static async Task<bool> LegacyTableExistsAsync(
        IdentityDbContext context,
        CancellationToken cancellationToken = default)
    {
        var isSqlite = string.Equals(
            context.Database.ProviderName,
            "Microsoft.EntityFrameworkCore.Sqlite",
            StringComparison.Ordinal);
        var sql = isSqlite
            ? """SELECT COUNT(*) AS "Value" FROM sqlite_master WHERE type = 'table' AND name = 'system_settings'"""
            : """
              SELECT COUNT(*) AS "Value" FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE c.relname = 'system_settings' AND n.nspname = current_schema()
              """;
        var count = await context.Database
            .SqlQueryRaw<long>(sql)
            .ToListAsync(cancellationToken);
        return count.Single() > 0;
    }

    /// <summary>Loads the shared aggregate row for SignaCore, or null when it does not exist.</summary>
    public static async Task<AggregateRow?> LoadAggregateAsync(
        IdentityDbContext context,
        CancellationToken cancellationToken = default) =>
        await context.Database
            .SqlQuery<AggregateRow>($"""
                SELECT "version" AS "Version", "values_json" AS "ValuesJson", "updated_by" AS "UpdatedBy"
                FROM service_settings WHERE service_id = {InstallationStores.ServiceIdValue}
                """)
            .SingleOrDefaultAsync(cancellationToken);

    /// <summary>Parses the aggregate's persisted values object into a plain dictionary.</summary>
    public static Dictionary<string, string> ParseValues(AggregateRow aggregate)
    {
        using var document = System.Text.Json.JsonDocument.Parse(aggregate.ValuesJson);
        return document.RootElement.EnumerateObject()
            .ToDictionary(
                property => property.Name,
                property => property.Value.GetString()!,
                StringComparer.Ordinal);
    }

    /// <summary>Deletes the aggregate row so a test can recreate the pre-migration state.</summary>
    public static Task DeleteAggregateAsync(
        IdentityDbContext context,
        CancellationToken cancellationToken = default) =>
        context.Database.ExecuteSqlAsync(
            $"""DELETE FROM service_settings WHERE service_id = {InstallationStores.ServiceIdValue}""",
            cancellationToken);

    /// <summary>
    /// Loads one value-free text projection per shared audit row (action and key metadata), so
    /// tests can count rows and assert no submitted value reached the audit store.
    /// </summary>
    /// <summary>One row of the shared service_audit_logs table, read through provider-neutral SQL.</summary>
    public sealed class SharedAuditRow
    {
        public string Id { get; set; } = string.Empty;

        public string Action { get; set; } = string.Empty;

        public string TargetType { get; set; } = string.Empty;

        public string TargetId { get; set; } = string.Empty;

        public string? OperatorId { get; set; }

        public string? OperatorDisplayName { get; set; }

        public string OperatorSource { get; set; } = string.Empty;

        public string Outcome { get; set; } = string.Empty;

        public string? SecurityDescription { get; set; }

        public string? ClientIp { get; set; }

        public string? CorrelationId { get; set; }
    }

    /// <summary>
    /// Reads the shared audit rows whose entity type is internal to the library. Filters are
    /// applied in memory so both the SQLite and the PostgreSQL provider paths share one projection.
    /// </summary>
    public static async Task<List<SharedAuditRow>> LoadSharedAuditRowsAsync(
        IdentityDbContext context,
        CancellationToken cancellationToken = default) =>
        await context.Database
            .SqlQuery<SharedAuditRow>($"""
                SELECT "id" AS "Id",
                       "action" AS "Action",
                       "target_type" AS "TargetType",
                       "target_id" AS "TargetId",
                       "operator_id" AS "OperatorId",
                       "operator_display_name" AS "OperatorDisplayName",
                       "operator_source" AS "OperatorSource",
                       CASE "outcome" WHEN 0 THEN 'unknown' WHEN 1 THEN 'success'
                            WHEN 2 THEN 'failure' WHEN 3 THEN 'denied' ELSE 'unknown' END AS "Outcome",
                       "security_description" AS "SecurityDescription",
                       "client_ip" AS "ClientIp",
                       "correlation_id" AS "CorrelationId"
                FROM service_audit_logs
                """)
            .ToListAsync(cancellationToken);

    public static async Task<List<string>> LoadSharedAuditJsonAsync(
        IdentityDbContext context,
        CancellationToken cancellationToken = default) =>
        await context.Database
            .SqlQuery<SharedSettingAuditTextRow>($"""
                SELECT "action" AS "Action", COALESCE("metadata_json", '') AS "MetadataJson"
                FROM service_audit_logs
                """)
            .Select(row => $"{row.Action}|{row.MetadataJson}")
            .ToListAsync(cancellationToken);

    private sealed record SharedSettingAuditTextRow(string Action, string MetadataJson);
}
