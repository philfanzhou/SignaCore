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
