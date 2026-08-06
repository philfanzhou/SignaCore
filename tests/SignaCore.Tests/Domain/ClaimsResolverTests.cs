using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Database.Entity;
using SignaCore.Domain;
using Xunit;

using SignaCore.Database;

namespace SignaCore.Tests.Domain;

public class ClaimsResolverTests
{
    private static ILogger<ClaimsResolver> CreateLogger() => NullLogger<ClaimsResolver>.Instance;

    [Fact]
    public void ResolveBasicClaims_ReturnsAccountIdentifier()
    {
        // Arrange
        var account = new AccountEntity
        {
            Id = Guid.NewGuid(),
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };

        var resolver = new ClaimsResolver(CreateLogger());

        // Act
        var claims = resolver.ResolveBasicClaims(account, "testuser");

        // Assert
        Assert.Contains(claims, c => c.Type == IdentityConstants.ClaimSubject && c.Value == account.Id.ToString());
        Assert.Contains(claims, c => c.Type == IdentityConstants.ClaimName && c.Value == "testuser");
    }

    [Fact]
    public void ResolveBasicClaims_OmitsNameIfDisplayNameNull()
    {
        // Arrange
        var account = new AccountEntity
        {
            Id = Guid.NewGuid(),
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };

        var resolver = new ClaimsResolver(CreateLogger());

        // Act
        var claims = resolver.ResolveBasicClaims(account);

        // Assert
        Assert.Contains(claims, c => c.Type == IdentityConstants.ClaimSubject && c.Value == account.Id.ToString());
        Assert.DoesNotContain(claims, c => c.Type == IdentityConstants.ClaimName);
    }

    [Fact]
    public void ResolveBasicClaims_IncludesJtiAndIat()
    {
        // Arrange
        var account = new AccountEntity
        {
            Id = Guid.NewGuid(),
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };

        var resolver = new ClaimsResolver(CreateLogger());

        // Act
        var claims = resolver.ResolveBasicClaims(account);

        // Assert
        Assert.Contains(claims, c => c.Type == "jti");
        Assert.Contains(claims, c => c.Type == "iat");
    }
}