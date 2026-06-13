using QuantumZhou.Identity.Domain.Validators;
using Xunit;

namespace QuantumZhou.Identity.Tests;

public class PasswordPolicyTests
{
    private readonly IPasswordPolicy _policy = new DefaultPasswordPolicy();

    [Theory]
    [InlineData("Password1")]
    [InlineData("StrongP@ss1")]
    [InlineData("MyS3cureP@ssword")]
    public void Validate_WithValidPassword_ReturnsSuccess(string password)
    {
        var result = _policy.Validate(password, out var errorMessage);

        Assert.True(result);
        Assert.Equal(string.Empty, errorMessage);
    }

    [Fact]
    public void Validate_WithTooShortPassword_ReturnsFailure()
    {
        var result = _policy.Validate("Ab1", out var errorMessage);

        Assert.False(result);
        Assert.Contains("at least 8 characters", errorMessage);
    }

    [Fact]
    public void Validate_WithMissingUppercase_ReturnsFailure()
    {
        var result = _policy.Validate("password1", out var errorMessage);

        Assert.False(result);
        Assert.Contains("uppercase letter", errorMessage);
    }

    [Fact]
    public void Validate_WithMissingLowercase_ReturnsFailure()
    {
        var result = _policy.Validate("PASSWORD1", out var errorMessage);

        Assert.False(result);
        Assert.Contains("lowercase letter", errorMessage);
    }

    [Fact]
    public void Validate_WithMissingDigit_ReturnsFailure()
    {
        var result = _policy.Validate("Password", out var errorMessage);

        Assert.False(result);
        Assert.Contains("number", errorMessage);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Validate_WithEmptyPassword_ReturnsFailure(string? password)
    {
        var result = _policy.Validate(password!, out var errorMessage);

        Assert.False(result);
        Assert.Contains("cannot be empty", errorMessage);
    }
}
