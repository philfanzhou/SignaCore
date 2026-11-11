using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.Tests.Host.Services;

/// <summary>
/// The untrusted single-<c>aud</c> read of the shared logout-hint validator: it accepts exactly
/// one non-empty <c>aud</c> claim of a parseable compact JWS and nothing else, because the
/// standard <c>end_session_endpoint</c> resolves the application from this value before the full
/// signature validation re-checks the same audience.
/// </summary>
public class OidcLogoutHintValidatorTests
{
    private static readonly RsaSecurityKey Key = new(System.Security.Cryptography.RSA.Create(2048)) { KeyId = "unit-key" };

    private static string Mint(params Claim[] claims) =>
        new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            new JwtHeader(new SigningCredentials(Key, SecurityAlgorithms.RsaSha256)),
            new JwtPayload(claims)));

    [Fact]
    public void TryReadAudience_AcceptsExactlyOneNonEmptyAudience()
    {
        var token = Mint(new Claim("aud", "known-client"));

        Assert.True(OidcLogoutHintValidator.TryReadAudience(token, out var audience));
        Assert.Equal("known-client", audience);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void TryReadAudience_RejectsAnEmptyAudience(string value)
    {
        var token = Mint(new Claim("aud", value));

        Assert.False(OidcLogoutHintValidator.TryReadAudience(token, out var audience));
        Assert.Null(audience);
    }

    [Fact]
    public void TryReadAudience_RejectsAMissingAudience()
    {
        var token = Mint(new Claim("sub", "d3b1a2c4-0000-0000-0000-000000000001"));

        Assert.False(OidcLogoutHintValidator.TryReadAudience(token, out var audience));
        Assert.Null(audience);
    }

    [Fact]
    public void TryReadAudience_RejectsDuplicatedAudiences()
    {
        // Hand-built compact JWS: the payload carries a two-element aud array, which the claim
        // enumeration must surface as more than one audience.
        var token = MintCompact("{\"aud\":[\"known-client\",\"known-client\"]}");

        Assert.False(OidcLogoutHintValidator.TryReadAudience(token, out var audience));
        Assert.Null(audience);
    }

    [Theory]
    [InlineData("not-a-jwt")]
    [InlineData("")]
    [InlineData("e30.e30.e30")] // parseable JWS with an empty payload: no aud claim
    public void TryReadAudience_RejectsUnusableInput(string candidate)
    {
        Assert.False(OidcLogoutHintValidator.TryReadAudience(candidate, out var audience));
        Assert.Null(audience);
    }

    /// <summary>
    /// Builds a signed compact JWS around a literal payload JSON, for the shapes the
    /// claim-oriented token API cannot express.
    /// </summary>
    private static string MintCompact(string payloadJson)
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var header = Base64UrlEncode("{\"alg\":\"RS256\",\"kid\":\"unit-key\",\"typ\":\"JWT\"}");
        var payload = Base64UrlEncode(payloadJson);
        var signature = Base64UrlEncode(rsa.SignData(
            Encoding.UTF8.GetBytes($"{header}.{payload}"),
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1));
        return $"{header}.{payload}.{signature}";
    }

    private static string Base64UrlEncode(string value) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static string Base64UrlEncode(byte[] value) =>
        Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
