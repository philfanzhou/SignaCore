using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Domain.Services;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

/// <summary>
/// The <c>PS-12</c> constructor as a unit: the closed claim set and header, the exact nonce and
/// session authentication facts, the profile-conditional name/nickname sources, the 5-minute
/// lifetime, the serialized-length bound, and validation through a standard JWT validator —
/// including that every tampered dimension (issuer, audience, signature, type, lifetime) fails.
/// </summary>
public sealed class InteractiveIdTokenFactoryTests
{
    private const string Issuer = "https://id-token-unit.test";
    private const string ClientId = "id-token-unit-client";
    private const string Nonce = "id-token-unit-nonce-0123456789";
    private const long AuthTimeSeconds = 1_700_000_000;
    private const long NowSeconds = 1_750_000_000;

    private readonly InteractiveIdTokenFactory _factory = new(new JwtOptions { Issuer = Issuer });
    private readonly RsaSecurityKey _key = new(RSA.Create(2048)) { KeyId = "unit-key-1" };

    private static InteractiveIdTokenDescriptor Descriptor(
        string scope = "openid profile",
        string? nonce = Nonce,
        string? passwordUsername = "bound_username",
        string? nickname = null) => new(
        Guid.NewGuid(),
        ClientId,
        Guid.NewGuid(),
        IdentityConstants.AuthMethodPassword,
        scope,
        nonce!,
        DateTimeOffset.FromUnixTimeSeconds(AuthTimeSeconds),
        passwordUsername,
        nickname);

    private InteractiveIdTokenResult.Issued Create(InteractiveIdTokenDescriptor descriptor) =>
        Assert.IsType<InteractiveIdTokenResult.Issued>(
            _factory.Create(descriptor, _key, DateTimeOffset.FromUnixTimeSeconds(NowSeconds)));

    [Fact]
    public void Create_ProducesTheClosedHeaderAndClaimSet()
    {
        var descriptor = Descriptor();
        var issued = Create(descriptor);
        var token = new JwtSecurityTokenHandler().ReadJwtToken(issued.IdToken);

        Assert.Equal("RS256", token.Header.Alg);
        Assert.Equal(_key.KeyId, token.Header.Kid);
        Assert.Equal("JWT", token.Header.Typ);

        Assert.Equal(Issuer, token.Issuer);
        Assert.Equal(ClientId, token.Audiences.Single());
        Assert.Equal(descriptor.AccountId.ToString("D"), token.Claims.Single(c => c.Type == "sub").Value);
        Assert.Equal(descriptor.SessionId.ToString("D"), token.Claims.Single(c => c.Type == "sid").Value);
        Assert.Equal(Nonce, token.Claims.Single(c => c.Type == "nonce").Value);
        Assert.Equal("pwd", token.Claims.Single(c => c.Type == "amr").Value);
        Assert.Equal(
            AuthTimeSeconds,
            long.Parse(
                token.Claims.Single(c => c.Type == "auth_time").Value,
                System.Globalization.CultureInfo.InvariantCulture));

        // The closed PS-12 set admits no access-token binding claim and no enrichment.
        var claimTypes = token.Claims.Select(claim => claim.Type).ToHashSet(StringComparer.Ordinal);
        Assert.False(claimTypes.Overlaps(
        [
            "scope", "client_id", "auth_method", "role", "Permission", "jti", "nbf", "azp", "acr"
        ]));

        // exp is exactly the 5-minute lifetime after iat.
        Assert.Equal(
            ((DateTimeOffset)token.IssuedAt).ToUnixTimeSeconds() + IdentityConstants.InteractiveIdTokenLifetimeSeconds,
            ((DateTimeOffset)token.ValidTo).ToUnixTimeSeconds());
    }

    [Fact]
    public void Create_SerializesAmrAsAJsonArrayAndAuthTimeAsANumber()
    {
        var issued = Create(Descriptor());
        var payloadSegment = issued.IdToken.Split('.')[1];
        var padded = payloadSegment.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');

        using var payload = JsonDocument.Parse(Convert.FromBase64String(padded));
        var root = payload.RootElement;

        var amr = root.GetProperty("amr");
        Assert.Equal(JsonValueKind.Array, amr.ValueKind);
        var members = amr.EnumerateArray().ToList();
        Assert.Single(members);
        Assert.Equal("pwd", members[0].GetString());

        Assert.Equal(JsonValueKind.Number, root.GetProperty("auth_time").ValueKind);
        Assert.Equal(AuthTimeSeconds, root.GetProperty("auth_time").GetInt64());
    }

    [Fact]
    public void Create_AddsProfileClaimsOnlyWhenProfileWasGranted()
    {
        var withProfile = Create(Descriptor(nickname: "nick"));
        var token = new JwtSecurityTokenHandler().ReadJwtToken(withProfile.IdToken);
        Assert.Equal("bound_username", token.Claims.Single(c => c.Type == "name").Value);
        Assert.Equal("nick", token.Claims.Single(c => c.Type == "nickname").Value);

        // openid alone: no name and no nickname, even though both sources exist.
        var withoutProfile = Create(Descriptor(scope: "openid", nickname: "nick"));
        var bare = new JwtSecurityTokenHandler().ReadJwtToken(withoutProfile.IdToken);
        Assert.DoesNotContain(bare.Claims, claim => claim.Type is "name" or "nickname");
    }

    [Fact]
    public void Create_FailsWhenTheSerializedTokenExceedsTheBound()
    {
        // A canonical scope stays short, so the length is forced through the profile sources: the
        // bound username is the one free-text input this phase admits.
        var oversized = Descriptor(passwordUsername: new string('u', IdentityConstants.InteractiveTokenMaxSerializedLength));

        Assert.IsType<InteractiveIdTokenResult.ExceedsMaximumLength>(
            _factory.Create(oversized, _key, DateTimeOffset.FromUnixTimeSeconds(NowSeconds)));
    }

    public static TheoryData<string, Func<InteractiveIdTokenDescriptor>> InvalidDescriptors => new()
    {
        { "empty account", () => Descriptor() with { AccountId = Guid.Empty } },
        { "empty session", () => Descriptor() with { SessionId = Guid.Empty } },
        { "empty client", () => Descriptor() with { ClientId = "" } },
        { "empty nonce", () => Descriptor(nonce: "") },
        { "unmapped auth method", () => Descriptor() with { AuthMethod = "SMS" } },
        { "non-canonical scope", () => Descriptor(scope: "profile") }
    };

    [Theory]
    [MemberData(nameof(InvalidDescriptors))]
    public void Create_RejectsProgrammingErrorsWithoutEchoingValues(
        string name,
        Func<InteractiveIdTokenDescriptor> descriptor)
    {
        _ = name;
        var exception = Assert.ThrowsAny<ArgumentException>(
            () => _factory.Create(descriptor(), _key, DateTimeOffset.FromUnixTimeSeconds(NowSeconds)));

        // DF-07: the message names the concept, never the value.
        Assert.DoesNotContain(ClientId, exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Nonce, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_RejectsAKeyWithoutAKid()
    {
        var keyWithoutKid = new RsaSecurityKey(RSA.Create(2048));

        Assert.ThrowsAny<ArgumentException>(
            () => _factory.Create(
                Descriptor(),
                keyWithoutKid,
                DateTimeOffset.FromUnixTimeSeconds(NowSeconds)));
    }

    [Fact]
    public void Create_ProducesATokenAStandardValidatorAccepts()
    {
        var descriptor = Descriptor();
        var issued = Create(descriptor);
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };

        var principal = handler.ValidateToken(
            issued.IdToken,
            new TokenValidationParameters
            {
                ValidIssuer = Issuer,
                ValidAudience = ClientId,
                IssuerSigningKey = _key,
                ValidTypes = ["JWT"],
                ValidateLifetime = false
            },
            out _);

        Assert.Equal(descriptor.AccountId.ToString("D"), principal.FindFirst("sub")!.Value);
        Assert.Equal(Nonce, principal.FindFirst("nonce")!.Value);
    }

    [Fact]
    public void Create_ProducesATokenAStandardValidatorRejectsWhenAnyDimensionIsWrong()
    {
        var issued = Create(Descriptor());
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };

        Assert.ThrowsAny<SecurityTokenValidationException>(() =>
            handler.ValidateToken(issued.IdToken, new TokenValidationParameters
            {
                ValidIssuer = "https://attacker.test",
                ValidAudience = ClientId,
                IssuerSigningKey = _key,
                ValidateLifetime = false
            }, out _));

        Assert.ThrowsAny<SecurityTokenValidationException>(() =>
            handler.ValidateToken(issued.IdToken, new TokenValidationParameters
            {
                ValidIssuer = Issuer,
                ValidAudience = "other-client",
                IssuerSigningKey = _key,
                ValidateLifetime = false
            }, out _));

        var otherKey = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "unit-key-1" };
        Assert.ThrowsAny<SecurityTokenValidationException>(() =>
            handler.ValidateToken(issued.IdToken, new TokenValidationParameters
            {
                ValidIssuer = Issuer,
                ValidAudience = ClientId,
                IssuerSigningKey = otherKey,
                ValidateLifetime = false
            }, out _));

        Assert.ThrowsAny<SecurityTokenValidationException>(() =>
            handler.ValidateToken(issued.IdToken, new TokenValidationParameters
            {
                ValidIssuer = Issuer,
                ValidAudience = ClientId,
                IssuerSigningKey = _key,
                ValidTypes = ["at+jwt"],
                ValidateLifetime = false
            }, out _));

        // The access token's typ never validates as an ID token.
        var accessToken = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            new JwtHeader(new SigningCredentials(_key, SecurityAlgorithms.RsaSha256))
            {
                [JwtHeaderParameterNames.Typ] = JwtTokenService.AccessTokenType
            },
            new JwtPayload(Issuer, ClientId, null, null, DateTime.UtcNow.AddMinutes(5))));
        Assert.ThrowsAny<SecurityTokenValidationException>(() =>
            handler.ValidateToken(accessToken, new TokenValidationParameters
            {
                ValidIssuer = Issuer,
                ValidAudience = ClientId,
                IssuerSigningKey = _key,
                ValidTypes = ["JWT"],
                ValidateLifetime = false
            }, out _));

        // Lifetime: a token from the past is expired to a validator with a live clock.
        var expired = Assert.IsType<InteractiveIdTokenResult.Issued>(_factory.Create(
            Descriptor(),
            _key,
            DateTimeOffset.UtcNow.AddMinutes(-IdentityConstants.InteractiveIdTokenLifetimeSeconds - 1)));
        Assert.ThrowsAny<SecurityTokenValidationException>(() =>
            handler.ValidateToken(expired.IdToken, new TokenValidationParameters
            {
                ValidIssuer = Issuer,
                ValidAudience = ClientId,
                IssuerSigningKey = _key,
                ValidateLifetime = true
            }, out _));
    }
}
