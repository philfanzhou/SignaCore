using QuantumZhou.Identity.Domain.Services;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain.Services;

public class BCryptPasswordHasherTests
{
    private static IPasswordHasher CreateHasher(int workFactor = 4) => new BCryptPasswordHasher(new PasswordHasherOptions { WorkFactor = workFactor });

    [Fact]
    public void HashPassword_ReturnsNonNullHash()
    {
        var hasher = CreateHasher();

        var hash = hasher.HashPassword("mypassword");

        Assert.NotNull(hash);
        Assert.NotEmpty(hash);
        Assert.NotEqual("mypassword", hash);
    }

    [Fact]
    public void VerifyPassword_WithCorrectPassword_ReturnsTrue()
    {
        var hasher = CreateHasher();
        var hash = hasher.HashPassword("mypassword");

        var result = hasher.VerifyPassword("mypassword", hash);

        Assert.True(result);
    }

    [Fact]
    public void VerifyPassword_WithWrongPassword_ReturnsFalse()
    {
        var hasher = CreateHasher();
        var hash = hasher.HashPassword("mypassword");

        var result = hasher.VerifyPassword("wrongpassword", hash);

        Assert.False(result);
    }

    [Fact]
    public void HashPassword_GeneratesDifferentHashesForSamePassword()
    {
        var hasher = CreateHasher();

        var hash1 = hasher.HashPassword("mypassword");
        var hash2 = hasher.HashPassword("mypassword");

        Assert.NotEqual(hash1, hash2);
    }
}
