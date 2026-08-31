using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.Tests.Domain;

public sealed class OidcRedirectUriValidatorTests
{
    [Theory]
    [InlineData("HTTPS://EXAMPLE.COM", "https://example.com/")]
    [InlineData("https://EXAMPLE.COM:443/callback", "https://example.com/callback")]
    [InlineData("http://127.0.0.1:80", "http://127.0.0.1/")]
    [InlineData("http://[::1]:80/callback", "http://[::1]/callback")]
    [InlineData("https://example.com?source=one", "https://example.com/?source=one")]
    public void ValidateAndCanonicalize_NormalizesOnlyRegistrationComponents(
        string value,
        string expected)
    {
        var result = OidcRedirectUriValidator.ValidateAndCanonicalize(
            value,
            isDevelopment: true);

        Assert.Equal(expected, result.Value);
    }

    [Theory]
    [InlineData("https://example.com/Path/%2f?Value=%2a")]
    [InlineData("https://example.com:8443/callback")]
    [InlineData("https://example.com/callback/")]
    public void ValidateAndCanonicalize_PreservesRequestSignificantText(string value)
    {
        var result = OidcRedirectUriValidator.ValidateAndCanonicalize(
            value,
            isDevelopment: false);

        Assert.Equal(value, result.Value);
    }

    [Theory]
    [InlineData("")]
    [InlineData("https://example.com/\u00E9")]
    [InlineData("/relative")]
    [InlineData("mailto:admin@example.com")]
    [InlineData("ftp://example.com/callback")]
    [InlineData("http://example.com/callback")]
    [InlineData("http://localhost/callback")]
    [InlineData("https://localhost/callback")]
    [InlineData("https://localhost./callback")]
    [InlineData("https://user@example.com/callback")]
    [InlineData("https://example.com/callback#fragment")]
    [InlineData("https://*.example.com/callback")]
    [InlineData("https://example.com\\callback")]
    [InlineData("https://example.com/call back")]
    [InlineData("https://example.com/%invalid")]
    [InlineData("https:///callback")]
    [InlineData("https://example.com:99999/callback")]
    public void ValidateAndCanonicalize_RejectsInvalidRegistrations(string value)
    {
        var exception = Assert.Throws<OidcClientConfigurationException>(() =>
            OidcRedirectUriValidator.ValidateAndCanonicalize(
                value,
                isDevelopment: false));

        if (value.Length > 0)
        {
            Assert.DoesNotContain(value, exception.Message, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("http://127.0.0.1/callback")]
    [InlineData("http://[::1]/callback")]
    public void ValidateAndCanonicalize_AllowsLiteralLoopbackHttpOnlyInDevelopment(string value)
    {
        var result = OidcRedirectUriValidator.ValidateAndCanonicalize(
            value,
            isDevelopment: true);

        Assert.Equal(value, result.Value);
        Assert.Throws<OidcClientConfigurationException>(() =>
            OidcRedirectUriValidator.ValidateAndCanonicalize(
                value,
                isDevelopment: false));
    }

    [Fact]
    public void ValidateAndCanonicalize_RejectsCanonicalDuplicates()
    {
        Assert.Throws<OidcClientConfigurationException>(() =>
            OidcRedirectUriValidator.ValidateAndCanonicalize(
                ["https://example.com", "HTTPS://EXAMPLE.COM:443/"],
                isDevelopment: false));
    }

    [Fact]
    public void ValidateAndCanonicalize_DoesNotMergeRequestSignificantDifferences()
    {
        var values = new[]
        {
            "https://example.com/Path",
            "https://example.com/path",
            "https://example.com/%2f",
            "https://example.com/%2F",
            "https://example.com/callback",
            "https://example.com/callback/",
            "https://example.com/callback?source=one",
            "https://example.com:8443/callback"
        };

        var result = OidcRedirectUriValidator.ValidateAndCanonicalize(
            values,
            isDevelopment: false);

        Assert.Equal(values, result.Select(uri => uri.Value));
    }

    [Fact]
    public void ValidateAndCanonicalize_AcceptsTenValuesAndRejectsEleven()
    {
        var ten = Enumerable.Range(0, 10)
            .Select(index => $"https://example.com/callback/{index}")
            .ToArray();

        Assert.Equal(
            10,
            OidcRedirectUriValidator.ValidateAndCanonicalize(
                ten,
                isDevelopment: false).Count);
        Assert.Throws<OidcClientConfigurationException>(() =>
            OidcRedirectUriValidator.ValidateAndCanonicalize(
                [.. ten, "https://example.com/callback/10"],
                isDevelopment: false));
    }

    [Fact]
    public void ValidateAndCanonicalize_RejectsValuesOverFiveHundredCharacters()
    {
        var value = "https://example.com/" + new string('a', 481);

        Assert.Equal(501, value.Length);
        Assert.Throws<OidcClientConfigurationException>(() =>
            OidcRedirectUriValidator.ValidateAndCanonicalize(
                value,
                isDevelopment: false));
    }
}
