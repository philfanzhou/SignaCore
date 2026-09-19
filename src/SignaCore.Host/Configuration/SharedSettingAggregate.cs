using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Host.Installation;

namespace SignaCore.Host.Configuration;

/// <summary>
/// Provider-neutral reads of the shared <c>service_settings</c> aggregate row.
/// </summary>
/// <remarks>
/// The aggregate entity type is internal to the shared persistence package, so consumers reach
/// the row through fixed SQL — the same provider-neutral access pattern the database contract
/// tests use. Only metadata is ever read here; values are loaded through the shared store.
/// </remarks>
internal static class SharedSettingAggregate
{
    /// <summary>
    /// Reads the persisted aggregate version, or null when the aggregate row does not exist yet.
    /// </summary>
    public static async Task<long?> ReadVersionAsync(
        IdentityDbContext database,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(database);
        return await database.Database
            .SqlQuery<long?>(
                $"""
                 SELECT "version" AS "Value" FROM service_settings
                 WHERE service_id = {InstallationStores.ServiceIdValue}
                 """)
            .SingleOrDefaultAsync(cancellationToken);
    }
}
