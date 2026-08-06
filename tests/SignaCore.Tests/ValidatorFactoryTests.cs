using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.Tests;

public class ValidatorFactoryTests
{
    private static ILogger<ValidatorFactory> CreateLogger() => NullLogger<ValidatorFactory>.Instance;

    [Fact]
    public void GetSupportedGrantTypes_ReturnsAllRegisteredTypes()
    {
        var validators = new IIdentityValidator[]
        {
            new MockValidator("password"),
            new MockValidator("sms"),
            new MockValidator("refresh_token")
        };
        var factory = new ValidatorFactory(validators, CreateLogger());

        var types = factory.GetSupportedGrantTypes().ToList();

        Assert.Contains("password", types);
        Assert.Contains("sms", types);
        Assert.Contains("refresh_token", types);
    }

    [Fact]
    public void IsSupportedGrantType_WithValidType_ReturnsTrue()
    {
        var validators = new IIdentityValidator[] { new MockValidator("password") };
        var factory = new ValidatorFactory(validators, CreateLogger());

        Assert.True(factory.IsSupportedGrantType("password"));
    }

    [Fact]
    public void IsSupportedGrantType_WithInvalidType_ReturnsFalse()
    {
        var validators = new IIdentityValidator[] { new MockValidator("password") };
        var factory = new ValidatorFactory(validators, CreateLogger());

        Assert.False(factory.IsSupportedGrantType("invalid"));
    }

    [Fact]
    public void GetValidator_WithValidType_ReturnsValidator()
    {
        var validators = new IIdentityValidator[] { new MockValidator("password") };
        var factory = new ValidatorFactory(validators, CreateLogger());

        var validator = factory.GetValidator("password");

        Assert.NotNull(validator);
        Assert.Equal("password", validator.GrantType);
    }

    [Fact]
    public void GetValidator_WithInvalidType_ThrowsKeyNotFoundException()
    {
        var validators = new IIdentityValidator[] { new MockValidator("password") };
        var factory = new ValidatorFactory(validators, CreateLogger());

        var ex = Assert.Throws<KeyNotFoundException>(() => factory.GetValidator("invalid"));
        Assert.Contains("invalid", ex.Message);
    }

    private class MockValidator : IIdentityValidator
    {
        public MockValidator(string grantType) => GrantType = grantType;
        public string GrantType { get; }
        public Task<ValidationResult> ValidateAsync(ValidationRequest request) =>
            Task.FromResult(ValidationResult.Failure("mock"));
    }
}
