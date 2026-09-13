using Microsoft.EntityFrameworkCore;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;

namespace SignaCore.Host.Installation;

/// <summary>
/// Serializes writers on the singleton <c>service_installations</c> row.
/// <para>
/// Both first-run setup and later settings changes publish a new configuration version, so both
/// have to take the same lock; otherwise two concurrent writers could publish the same version
/// number over different snapshots.
/// </para>
/// </summary>
internal static class InstallationStateLock
{
    public static async Task<ServiceInstallationEntity?> LoadLockedAsync(
        IdentityDbContext db,
        DatabaseOptions databaseOptions,
        CancellationToken cancellationToken = default)
    {
        db.ChangeTracker.Clear();

        if (databaseOptions.ProviderKind == DatabaseProvider.Sqlite)
        {
            // SQLite serializes writers at the file level; a plain read inside the transaction is
            // already exclusive once the transaction upgrades to a write.
            return await db.ServiceInstallations
                .FirstOrDefaultAsync(
                    row => row.ServiceId == InstallationStores.ServiceIdValue,
                    cancellationToken);
        }

        var rows = await db.ServiceInstallations
            .FromSqlInterpolated(
                $"SELECT * FROM service_installations WHERE service_id = {InstallationStores.ServiceIdValue} FOR UPDATE")
            .ToListAsync(cancellationToken);

        return rows.FirstOrDefault();
    }
}
