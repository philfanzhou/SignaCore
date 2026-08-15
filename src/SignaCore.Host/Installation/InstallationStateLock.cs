using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Host.Installation;

/// <summary>
/// Serializes writers on the singleton installation row.
/// <para>
/// Both first-run setup and later settings changes bump <c>configuration_version</c>, so both have
/// to take the same lock; otherwise two concurrent writers could publish the same version number
/// over different snapshots.
/// </para>
/// </summary>
internal static class InstallationStateLock
{
    public static async Task<InstallationStateEntity?> LoadLockedAsync(
        IdentityDbContext db,
        DatabaseOptions databaseOptions,
        CancellationToken cancellationToken = default)
    {
        db.ChangeTracker.Clear();

        if (databaseOptions.ProviderKind == DatabaseProvider.Sqlite)
        {
            // SQLite serializes writers at the file level; a plain read inside the transaction is
            // already exclusive once the transaction upgrades to a write.
            return await db.InstallationStates
                .FirstOrDefaultAsync(row => row.Id == InstallationStateEntity.SingletonId, cancellationToken);
        }

        var rows = await db.InstallationStates
            .FromSqlRaw(
                $"SELECT * FROM installation_state WHERE id = {InstallationStateEntity.SingletonId} FOR UPDATE")
            .ToListAsync(cancellationToken);

        return rows.FirstOrDefault();
    }
}
