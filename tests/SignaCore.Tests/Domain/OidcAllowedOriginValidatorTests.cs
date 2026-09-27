using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.Tests.Domain;

public sealed class OidcAllowedOriginValidatorTests
{
    [Theory]
    [InlineData("HTTPS://EXAMPLE.COM:443", "https://example.com")]
    [InlineData("https://Example.COM:8443", "https://example.com:8443")]
    [InlineData("http://127.0.0.1:80", "http://127.0.0.1")]
    [InlineData("http://[::1]:8080", "http://[::1]:8080")]
    public void Registration_CanonicalizesOnlySchemeHostAndDefaultPort(string value, string expected)
    {
        Assert.Equal([expected], OidcAllowedOriginValidator.ValidateAndCanonicalize([value], true));
    }

    [Theory]
    [InlineData("")]
    [InlineData("null")]
    [InlineData("https://example.com/")]
    [InlineData("https://example.com/path")]
    [InlineData("https://example.com?x=1")]
    [InlineData("https://example.com#fragment")]
    [InlineData("https://user@example.com")]
    [InlineData("https://*.example.com")]
    [InlineData("https://ex%61mple.com")]
    [InlineData("https://exämple.com")]
    [InlineData("https://example.com:99999")]
    [InlineData("http://example.com")]
    [InlineData("http://localhost:8080")]
    public void Registration_RejectsNonOriginInput(string value)
    {
        var exception = Assert.Throws<OidcClientConfigurationException>(() =>
            OidcAllowedOriginValidator.ValidateAndCanonicalize([value], true));
        if (value.Length > 0)
        {
            Assert.DoesNotContain(value, exception.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Production_RejectsLoopbackHttp()
    {
        Assert.Throws<OidcClientConfigurationException>(() =>
            OidcAllowedOriginValidator.ValidateAndCanonicalize(["http://127.0.0.1:8080"], false));
    }

    [Fact]
    public void Registration_RejectsCanonicalDuplicatesAndExcessEntries()
    {
        Assert.Throws<OidcClientConfigurationException>(() =>
            OidcAllowedOriginValidator.ValidateAndCanonicalize(
                ["HTTPS://EXAMPLE.COM:443", "https://example.com"], false));
        Assert.Throws<OidcClientConfigurationException>(() =>
            OidcAllowedOriginValidator.ValidateAndCanonicalize(
                Enumerable.Range(0, 11).Select(index => $"https://{index}.example.com"), false));
    }
}
