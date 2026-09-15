using System.Net;
using SignaCore.Database;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The one remaining legacy-console observation after the session switch: the forward drop
/// migration removed the legacy <c>data_protection_keys</c> table — the shared ServiceMantle key
/// ring is the only key store.
/// </summary>
public sealed class LegacyAdminConsoleCoexistenceTests : IClassFixture<IdentityServerFixture>
{
    private readonly IdentityServerFixture _fixture;

    public LegacyAdminConsoleCoexistenceTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task TheLegacyKeyStore_IsDroppedByMigration()
    {
        using var client = await _fixture.CreateAdminHttpClientAsync();

        // The forward drop migration removed the legacy data_protection_keys table; the shared
        // ServiceMantle ring is the only key store and holds the ring's rows.
        using var scope = _fixture.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var legacyTableExists = await db.Database.SqlQuery<int>(
                $"""
                SELECT COUNT(*) AS Value FROM sqlite_master
                WHERE type = 'table' AND name = 'data_protection_keys'
                """)
            .ToListAsync(TestContext.Current.CancellationToken);
        Assert.Equal(0, legacyTableExists.Single());

        var sharedKeys = await db.Database.SqlQuery<int>(
                $"SELECT COUNT(*) AS Value FROM service_data_protection_keys")
            .ToListAsync(TestContext.Current.CancellationToken);
        Assert.True(sharedKeys.Single() > 0);
    }
}
