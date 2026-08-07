using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

public class JwtAudienceTests
{
    private static readonly JwtOptions Options = new()
    {
        Issuer = "https://id.example.com",
        Audience = "SignaCore.Services",
        TokenExpirationHours = 2
    };

    /// <summary>默认模式保持历史行为：所有应用共用部署级 audience。</summary>
    [Fact]
    public void ResolveAudience_SharedMode_UsesTheDeploymentAudience()
    {
        var app = new AppRegistrationEntity { AppId = "orders", AudienceMode = AudienceMode.Shared };

        Assert.Equal("SignaCore.Services", JwtTokenService.ResolveAudience(app, Options));
    }

    /// <summary>
    /// 隔离模式下 aud 是应用自己的 AppId——这正是"给 A 签的 token 在 B 也能用"这一问题的修复点。
    /// </summary>
    [Fact]
    public void ResolveAudience_PerApplicationMode_UsesTheApplicationIdentifier()
    {
        var app = new AppRegistrationEntity { AppId = "orders", AudienceMode = AudienceMode.PerApplication };

        Assert.Equal("orders", JwtTokenService.ResolveAudience(app, Options));
    }

    [Fact]
    public void GenerateJwtToken_WritesTheRequestedAudience()
    {
        var token = ReadToken(GenerateToken(audience: "orders"));

        Assert.Equal("orders", Assert.Single(token.Audiences));
    }

    [Fact]
    public void GenerateJwtToken_WithoutAudience_FallsBackToTheDeploymentAudience()
    {
        var token = ReadToken(GenerateToken(audience: null));

        Assert.Equal("SignaCore.Services", Assert.Single(token.Audiences));
    }

    /// <summary>RFC 9068 §2.1：access token 必须带 typ: at+jwt。</summary>
    [Fact]
    public void GenerateJwtToken_MarksTheTokenAsAnAccessToken()
    {
        var token = ReadToken(GenerateToken(audience: null));

        Assert.Equal(JwtTokenService.AccessTokenType, token.Header.Typ);
    }

    [Fact]
    public void GenerateJwtToken_KeepsIssuerAndLifetime()
    {
        var token = ReadToken(GenerateToken(audience: null));

        Assert.Equal("https://id.example.com", token.Issuer);
        Assert.True(token.ValidTo > token.ValidFrom);
    }

    private static string GenerateToken(string? audience)
    {
        using var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa) { KeyId = "test-key" };
        return new JwtTokenService(Options).GenerateJwtToken(
            [new Claim(IdentityConstants.ClaimSubject, Guid.NewGuid().ToString())],
            key,
            Options.TokenExpirationHours,
            audience);
    }

    private static JwtSecurityToken ReadToken(string token) => new JwtSecurityTokenHandler().ReadJwtToken(token);
}
