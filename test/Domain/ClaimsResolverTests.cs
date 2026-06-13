using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Domain;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain;

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
        Assert.Contains(claims, c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" && c.Value == account.Id.ToString());
        Assert.Contains(claims, c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" && c.Value == "testuser");
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
        Assert.Contains(claims, c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" && c.Value == account.Id.ToString());
        Assert.DoesNotContain(claims, c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name");
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