using System.Threading.Tasks;
using QuantumZhou.Identity.Domain;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain;

public class CallbackUrlValidatorTests
{
    private readonly CallbackUrlValidator _validator = new();

    [Fact]
    public void Validate_WithValidHttpsUrl_ReturnsValid()
    {
        var result = _validator.Validate("https://example.com/callback");

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_WithValidHttpUrl_ReturnsValid()
    {
        var result = _validator.Validate("http://example.com/callback");

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_WithInvalidUrl_ReturnsInvalid()
    {
        var result = _validator.Validate("not-a-url");

        Assert.False(result.IsValid);
        Assert.Contains("not a valid absolute URL", result.ErrorMessage);
    }

    [Fact]
    public void Validate_WithFtpScheme_ReturnsInvalid()
    {
        var result = _validator.Validate("ftp://example.com/callback");

        Assert.False(result.IsValid);
        Assert.Contains("HTTP or HTTPS", result.ErrorMessage);
    }

    [Fact]
    public void Validate_WithIpAddress_ReturnsInvalid()
    {
        var result = _validator.Validate("http://192.168.1.1/callback");

        Assert.False(result.IsValid);
        Assert.Contains("private/internal IP address", result.ErrorMessage);
    }

    [Fact]
    public void Validate_WithAllowedDomain_ReturnsValid()
    {
        var validator = new CallbackUrlValidator(new[] { "trusted.example.com" });
        var result = validator.Validate("https://trusted.example.com/callback");

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_WithDisallowedDomain_ReturnsInvalid()
    {
        var validator = new CallbackUrlValidator(new[] { "trusted.example.com" });
        var result = validator.Validate("https://untrusted.example.com/callback");

        Assert.False(result.IsValid);
        Assert.Contains("not in the allowed domains list", result.ErrorMessage);
    }

    [Fact]
    public void Validate_WithEmptyAllowedDomains_AcceptsAnyDomain()
    {
        var validator = new CallbackUrlValidator();
        var result = validator.Validate("https://any-domain.example.com/callback");

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_WithRelativeUrl_ReturnsInvalid()
    {
        var result = _validator.Validate("/callback");

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_WithAllowPrivateAddresses_AcceptsIpAddress()
    {
        var validator = new CallbackUrlValidator(allowPrivateAddresses: true);
        var result = validator.Validate("http://192.168.1.1/callback");

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_WithAllowPrivateAddresses_AcceptsPrivateDomain()
    {
        var validator = new CallbackUrlValidator(allowPrivateAddresses: true);
        var result = validator.Validate("http://teacher-portal:5004/api/auth/callback");

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_WithAllowPrivateAddresses_AcceptsLocalhost()
    {
        var validator = new CallbackUrlValidator(allowPrivateAddresses: true);
        var result = validator.Validate("http://localhost:5004/api/auth/callback");

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_WithAllowPrivateAddresses_StillRejectsInvalidUrl()
    {
        var validator = new CallbackUrlValidator(allowPrivateAddresses: true);
        var result = validator.Validate("not-a-url");

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_WithAllowPrivateAddresses_StillRejectsFtpScheme()
    {
        var validator = new CallbackUrlValidator(allowPrivateAddresses: true);
        var result = validator.Validate("ftp://192.168.1.1/callback");

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_WithAllowPrivateAddresses_StillRejectsDisallowedDomain()
    {
        var validator = new CallbackUrlValidator(new[] { "trusted.example.com" }, allowPrivateAddresses: true);
        var result = validator.Validate("http://untrusted.local/callback");

        Assert.False(result.IsValid);
        Assert.Contains("not in the allowed domains list", result.ErrorMessage);
    }

    // ========== ValidateAsync 测试 ==========

    [Fact]
    public async Task ValidateAsync_WithValidHttpsUrl_ReturnsValid()
    {
        var result = await _validator.ValidateAsync("https://example.com/callback");
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task ValidateAsync_WithInvalidUrl_ReturnsInvalid()
    {
        var result = await _validator.ValidateAsync("not-a-url");
        Assert.False(result.IsValid);
        Assert.Contains("not a valid absolute URL", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithFtpScheme_ReturnsInvalid()
    {
        var result = await _validator.ValidateAsync("ftp://example.com/callback");
        Assert.False(result.IsValid);
        Assert.Contains("HTTP or HTTPS", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithAllowedDomain_ReturnsValid()
    {
        var validator = new CallbackUrlValidator(new[] { "trusted.example.com" });
        var result = await validator.ValidateAsync("https://trusted.example.com/callback");
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task ValidateAsync_WithDisallowedDomain_ReturnsInvalid()
    {
        var validator = new CallbackUrlValidator(new[] { "trusted.example.com" });
        var result = await validator.ValidateAsync("https://untrusted.example.com/callback");
        Assert.False(result.IsValid);
        Assert.Contains("not in the allowed domains list", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithAllowPrivateAddresses_AcceptsIpAddress()
    {
        var validator = new CallbackUrlValidator(allowPrivateAddresses: true);
        var result = await validator.ValidateAsync("http://192.168.1.1/callback");
        Assert.True(result.IsValid);
    }
}
