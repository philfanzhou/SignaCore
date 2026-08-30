using System.Net;
using System.Threading.Tasks;
using SignaCore.Domain;
using Xunit;

namespace SignaCore.Tests.Domain;

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
    public void Validate_WhenHttpsIsRequired_RejectsHttp()
    {
        var validator = new CallbackUrlValidator(requireHttps: true);

        var result = validator.Validate("http://example.com/callback");

        Assert.False(result.IsValid);
        Assert.Contains("HTTPS", result.ErrorMessage);
    }

    [Fact]
    public void Validate_WithUserInformation_RejectsUrl()
    {
        var result = _validator.Validate("https://user:secret@example.com/callback");

        Assert.False(result.IsValid);
        Assert.Contains("user information", result.ErrorMessage);
    }

    [Fact]
    public void Validate_WithIpAddress_ReturnsInvalid()
    {
        var validator = new CallbackUrlValidator(allowPrivateAddresses: false);
        var result = validator.Validate("http://192.168.1.1/callback");

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
        var result = validator.Validate("http://business-portal:5004/api/auth/callback");

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

    // ========== ValidateAsync tests ==========

    [Fact]
    public async Task ValidateAsync_WithValidHttpsUrl_ReturnsValid()
    {
        var result = await _validator.ValidateAsync("https://example.com/callback", TestContext.Current.CancellationToken);
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task ValidateAsync_WithInvalidUrl_ReturnsInvalid()
    {
        var result = await _validator.ValidateAsync("not-a-url", TestContext.Current.CancellationToken);
        Assert.False(result.IsValid);
        Assert.Contains("not a valid absolute URL", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithFtpScheme_ReturnsInvalid()
    {
        var result = await _validator.ValidateAsync("ftp://example.com/callback", TestContext.Current.CancellationToken);
        Assert.False(result.IsValid);
        Assert.Contains("HTTP or HTTPS", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithAllowedDomain_ReturnsValid()
    {
        var validator = new CallbackUrlValidator(new[] { "trusted.example.com" });
        var result = await validator.ValidateAsync("https://trusted.example.com/callback", TestContext.Current.CancellationToken);
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task ValidateAsync_WithDisallowedDomain_ReturnsInvalid()
    {
        var validator = new CallbackUrlValidator(new[] { "trusted.example.com" });
        var result = await validator.ValidateAsync("https://untrusted.example.com/callback", TestContext.Current.CancellationToken);
        Assert.False(result.IsValid);
        Assert.Contains("not in the allowed domains list", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithAllowPrivateAddresses_AcceptsIpAddress()
    {
        var validator = new CallbackUrlValidator(allowPrivateAddresses: true);
        var result = await validator.ValidateAsync("http://192.168.1.1/callback", TestContext.Current.CancellationToken);
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task ValidateAsync_WhenHttpsIsRequired_RejectsHttp()
    {
        var validator = new CallbackUrlValidator(requireHttps: true);

        var result = await validator.ValidateAsync("http://example.com/callback", TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Contains("HTTPS", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WithUserInformation_RejectsUrl()
    {
        var result = await _validator.ValidateAsync(
            "https://user:secret@example.com/callback",
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Contains("user information", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WhenPublicAddressIsRequired_RejectsUnresolvableHost()
    {
        var resolver = new StubCallbackHostResolver([]);
        var validator = CreatePublicAddressValidator(resolver);

        var result = await validator.ValidateAsync("https://callback.example.test/claims", TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Contains("could not be resolved", result.ErrorMessage);
        Assert.Equal("callback.example.test", resolver.ResolvedHost);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("100.64.0.1")]
    [InlineData("10.0.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.1.1")]
    [InlineData("192.0.2.1")]
    [InlineData("198.18.0.1")]
    [InlineData("198.51.100.1")]
    [InlineData("203.0.113.1")]
    [InlineData("224.0.0.1")]
    [InlineData("::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("fc00::1")]
    [InlineData("ff02::1")]
    [InlineData("2001:db8::1")]
    public async Task ValidateAsync_WhenPublicAddressIsRequired_RejectsRestrictedResolvedAddress(string value)
    {
        var resolver = new StubCallbackHostResolver([IPAddress.Parse(value)]);
        var validator = CreatePublicAddressValidator(resolver);

        var result = await validator.ValidateAsync(
            "https://callback.example.test/claims",
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Contains("must not resolve to a private/internal IP address", result.ErrorMessage);
    }

    [Fact]
    public async Task ValidateAsync_WhenPublicAddressIsRequired_AcceptsPublicResolvedAddress()
    {
        var resolver = new StubCallbackHostResolver([IPAddress.Parse("8.8.8.8")]);
        var validator = CreatePublicAddressValidator(resolver);

        var result = await validator.ValidateAsync(
            "https://callback.example.test/claims",
            TestContext.Current.CancellationToken);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task ValidateAsync_WhenResolutionIsCanceled_PropagatesCancellationToken()
    {
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.Cancel();
        var resolver = new StubCallbackHostResolver(
            (_, cancellationToken) => Task.FromCanceled<IPAddress[]?>(cancellationToken));
        var validator = CreatePublicAddressValidator(resolver);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            validator.ValidateAsync(
                "https://callback.example.test/claims",
                cancellationTokenSource.Token));

        Assert.Equal(cancellationTokenSource.Token, resolver.CancellationToken);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("100.64.0.1")]
    [InlineData("10.0.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.168.1.1")]
    [InlineData("192.0.2.1")]
    [InlineData("198.18.0.1")]
    [InlineData("198.51.100.1")]
    [InlineData("203.0.113.1")]
    [InlineData("224.0.0.1")]
    [InlineData("::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("fc00::1")]
    [InlineData("ff02::1")]
    [InlineData("2001:db8::1")]
    public void IsNonPublicAddress_RejectsLocalReservedAndMetadataRanges(string value)
    {
        Assert.True(CallbackUrlValidator.IsNonPublicAddress(IPAddress.Parse(value)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("100.128.0.1")]
    [InlineData("172.32.0.1")]
    [InlineData("192.1.1.1")]
    [InlineData("2606:4700:4700::1111")]
    public void IsNonPublicAddress_AcceptsPublicAddresses(string value)
    {
        Assert.False(CallbackUrlValidator.IsNonPublicAddress(IPAddress.Parse(value)));
    }

    private static CallbackUrlValidator CreatePublicAddressValidator(
        StubCallbackHostResolver hostResolver) =>
        new(
            allowedDomains: null,
            allowPrivateAddresses: false,
            requireHttps: false,
            resolveHostAddressesAsync: hostResolver.ResolveAsync);

    private sealed class StubCallbackHostResolver
    {
        private readonly Func<string, CancellationToken, Task<IPAddress[]?>> _resolveAsync;

        internal StubCallbackHostResolver(IPAddress[] addresses)
            : this((_, _) => Task.FromResult<IPAddress[]?>(addresses))
        {
        }

        internal StubCallbackHostResolver(
            Func<string, CancellationToken, Task<IPAddress[]?>> resolveAsync)
        {
            _resolveAsync = resolveAsync;
        }

        internal string? ResolvedHost { get; private set; }
        internal CancellationToken CancellationToken { get; private set; }

        internal Task<IPAddress[]?> ResolveAsync(
            string host,
            CancellationToken cancellationToken)
        {
            ResolvedHost = host;
            CancellationToken = cancellationToken;
            return _resolveAsync(host, cancellationToken);
        }
    }
}
