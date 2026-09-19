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
    /// <summary>Loads the shared aggregate row for SignaCore, or null when it does not exist.</summary>
    public static async Task<SharedSettingAggregateRow?> LoadAggregateAsync(
        IdentityDbContext context,
        CancellationToken cancellationToken = default) =>
        await context.Database
            .SqlQuery<SharedSettingAggregateRow>($"""
                SELECT "version" AS "Version", "values_json" AS "ValuesJson", "updated_by" AS "UpdatedBy"
                FROM service_settings WHERE service_id = {InstallationStores.ServiceIdValue}
                """)
            .SingleOrDefaultAsync(cancellationToken);

    /// <summary>Parses the aggregate's persisted values object into a plain dictionary.</summary>
    public static Dictionary<string, string> ParseValues(SharedSettingAggregateRow aggregate)
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
