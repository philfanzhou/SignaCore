using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host;

public class LegacyRefreshTokenProtectionTests
{
    [Fact]
    public async Task ProtectLegacyRefreshTokensAsync_RewritesPlaintextAndKeepsExistingDigests()
    {
        const string legacyToken = "legacy-bearer-secret";
        const string currentToken = "already-protected-secret";
        await using var context = CreateContext();
        var accountId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        context.RefreshTokens.AddRange(
            CreateToken(accountId, legacyToken),
            CreateToken(accountId, "sha256:not-a-real-digest"),
            CreateToken(accountId, RefreshTokenDigest.Compute(currentToken)));
        await context.SaveChangesAsync();

        await DatabaseInitializer.ProtectLegacyRefreshTokensAsync(
            context,
            NullLogger.Instance);

        var stored = await context.RefreshTokens
            .AsNoTracking()
            .Select(token => token.TokenValue)
            .ToListAsync();
        Assert.Contains(RefreshTokenDigest.Compute(legacyToken), stored);
        Assert.Contains(RefreshTokenDigest.Compute(currentToken), stored);
        Assert.Contains(RefreshTokenDigest.Compute("sha256:not-a-real-digest"), stored);
        Assert.DoesNotContain(legacyToken, stored);
    }

    [Fact]
    public async Task ProtectLegacyRefreshTokensAsync_ProcessesMoreThanOneBatch()
    {
        await using var context = CreateContext();
        var accountId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        context.RefreshTokens.AddRange(Enumerable.Range(0, 501)
            .Select(index => CreateToken(accountId, $"legacy-token-{index}")));
        await context.SaveChangesAsync();

        await DatabaseInitializer.ProtectLegacyRefreshTokensAsync(
            context,
            NullLogger.Instance);

        var stored = await context.RefreshTokens
            .AsNoTracking()
            .Select(token => token.TokenValue)
            .ToListAsync();
        Assert.Equal(501, stored.Count);
        Assert.All(stored, value => Assert.True(RefreshTokenDigest.IsDigest(value)));
    }

    private static IdentityDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new IdentityDbContext(options);
    }

    private static RefreshTokenEntity CreateToken(Guid accountId, string value) => new()
    {
        Id = Guid.NewGuid(),
        AccountId = accountId,
        TokenValue = value,
        AppId = "legacy-protection-test",
        CreatedAt = DateTimeOffset.UtcNow,
        ExpiresAt = DateTimeOffset.UtcNow.AddDays(1)
    };
}
