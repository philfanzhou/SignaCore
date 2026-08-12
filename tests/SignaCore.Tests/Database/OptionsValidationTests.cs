using SignaCore.Database;
using Xunit;

namespace SignaCore.Tests.Database;

public class OptionsValidationTests
{
    [Fact]
    public void JwtOptions_DefaultsAreValid()
    {
        new JwtOptions().Validate();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void JwtOptions_RejectsMissingIssuer(string? issuer)
    {
        var options = new JwtOptions { Issuer = issuer! };

        var exception = Assert.Throws<InvalidOperationException>(options.Validate);

        Assert.Contains("Issuer", exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void JwtOptions_RejectsMissingAudience(string? audience)
    {
        var options = new JwtOptions { Audience = audience! };

        var exception = Assert.Throws<InvalidOperationException>(options.Validate);

        Assert.Contains("Audience", exception.Message);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void JwtOptions_RejectsNonPositiveExpiration(int hours)
    {
        var options = new JwtOptions { TokenExpirationHours = hours };

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void RefreshTokenOptions_RejectsNonPositiveExpiration(int days)
    {
        var options = new RefreshTokenOptions { RefreshTokenExpirationDays = days };

        Assert.Throws<InvalidOperationException>(options.Validate);
    }
}
