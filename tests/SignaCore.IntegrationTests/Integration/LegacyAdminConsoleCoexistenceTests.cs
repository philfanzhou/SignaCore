using System.Net;
using SignaCore.Database;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The one remaining legacy-console observation after the session switch: the legacy
/// <c>data_protection_keys</c> store receives nothing new, because the shared ServiceMantle key
/// ring is the active ring. The table's removal is tracked separately.
/// </summary>
public sealed class LegacyAdminConsoleCoexistenceTests : IClassFixture<IdentityServerFixture>
{
    private readonly IdentityServerFixture _fixture;

    public LegacyAdminConsoleCoexistenceTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task TheLegacyKeyStore_IsNoLongerWrittenByTheSharedRing()
    {
        using var client = await _fixture.CreateAdminHttpClientAsync();

        using var scope = _fixture.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        // The switch moved the active ring to the shared ServiceMantle table; the legacy table
        // keeps whatever was written before the switch and receives nothing new.
        var legacyKeys = await db.DataProtectionKeys.AsNoTracking()
            .CountAsync(TestContext.Current.CancellationToken);
        var sharedKeys = await db.Database.SqlQuery<int>(
                $"SELECT COUNT(*) AS Value FROM service_data_protection_keys")
            .ToListAsync(TestContext.Current.CancellationToken);
        Assert.True(sharedKeys.Single() > 0);
        Assert.Equal(0, legacyKeys);
    }
}
