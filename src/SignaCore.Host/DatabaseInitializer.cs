using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Domain.Services;

namespace SignaCore.Host;

/// <summary>
/// Bootstrap-phase data repair that has to run before the application starts serving requests.
/// <para>
/// Provisioning, migrations, and installation-state resolution belong to the bootstrap phase
/// (<c>Startup/BootstrapPhase</c>), which runs before any application configuration exists. The
/// optional bootstrap-apps.json pre-seed is a product capability and lives in
/// <see cref="Provisioning.BootstrapAppSeeder"/>.
/// </para>
/// </summary>
internal static class DatabaseInitializer
{
    internal static async Task ProtectLegacyRefreshTokensAsync(
        IdentityDbContext db,
        ILogger logger)
    {
        const int batchSize = 500;
        var protectedCount = 0;
        while (true)
        {
            var legacyTokens = await db.RefreshTokens
                .Where(token =>
                    !token.TokenValue.StartsWith(RefreshTokenDigest.Prefix) ||
                    token.TokenValue.Length != RefreshTokenDigest.EncodedLength)
                .OrderBy(token => token.Id)
                .Take(batchSize)
                .ToListAsync();
            if (legacyTokens.Count == 0)
            {
                break;
            }

            foreach (var token in legacyTokens)
            {
                token.TokenValue = RefreshTokenDigest.Compute(token.TokenValue);
            }

            await db.SaveChangesAsync();
            protectedCount += legacyTokens.Count;
            db.ChangeTracker.Clear();
        }

        if (protectedCount > 0)
        {
            logger.LogInformation(
                "Protected {Count} legacy refresh tokens with one-way digests.",
                protectedCount);
        }
    }
}
