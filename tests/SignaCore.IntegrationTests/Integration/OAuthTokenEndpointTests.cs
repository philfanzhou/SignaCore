using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// <c>/oauth2/token</c> 的 RFC 6749 线格式契约：form-encoded 入参、Basic/post 客户端认证、
/// <c>access_token</c>/<c>token_type</c>/<c>expires_in</c> 出参、失败用 4xx + <c>error</c> 码。
/// 与历史的 <c>/api/auth/token</c>（JSON、失败 200）并存，两条路共用同一套发 token 流程。
/// </summary>
public class OAuthTokenEndpointTests : IClassFixture<IdentityServerFixture>
{
    private readonly IdentityServerFixture _fixture;

    public OAuthTokenEndpointTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Token_WithBasicClientAuthentication_ReturnsAStandardTokenResponse()
    {
        using var http = CreateClientWithBasicAuth();

        var response = await http.PostAsync("/oauth2/token", PasswordGrant(), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.True(body.GetProperty("expires_in").GetInt64() > 0);
        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("access_token").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("refresh_token").GetString()));
    }

    [Fact]
    public async Task Token_WithFormClientAuthentication_IsAccepted()
    {
        using var http = _fixture.CreateHttpClient();

        var response = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = IdentityConstants.GrantTypePassword,
            ["username"] = IdentityServerFixture.AdminUsername,
            ["password"] = IdentityServerFixture.AdminPassword,
            ["client_id"] = IdentityServerFixture.GatewayAppId,
            ["client_secret"] = IdentityServerFixture.GatewayAppSecret
        }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    /// <summary>RFC 9068 §2.1 + 每客户端 aud：签出的 token 头是 at+jwt，默认仍是共享 audience。</summary>
    [Fact]
    public async Task Token_IssuesAnAccessTokenMarkedAsAtJwt()
    {
        using var http = CreateClientWithBasicAuth();

        var response = await http.PostAsync("/oauth2/token", PasswordGrant(), TestContext.Current.CancellationToken);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        var token = new JwtSecurityTokenHandler().ReadJwtToken(body.GetProperty("access_token").GetString());

        Assert.Equal(JwtTokenService.AccessTokenType, token.Header.Typ);
        Assert.Contains(token.Claims, claim =>
            claim.Type == IdentityConstants.ClaimClientId && claim.Value == IdentityServerFixture.GatewayAppId);
    }

    /// <summary>RFC 6749 §5.2：客户端认证失败是 401 + WWW-Authenticate + invalid_client。</summary>
    [Fact]
    public async Task Token_WithoutClientCredentials_Returns401InvalidClient()
    {
        using var http = _fixture.CreateHttpClient();

        var response = await http.PostAsync("/oauth2/token", PasswordGrant(), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, header => header.Scheme == "Basic");
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_client", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Token_WithWrongClientSecret_Returns401InvalidClient()
    {
        using var http = CreateClientWithBasicAuth(secret: "wrong-secret");

        var response = await http.PostAsync("/oauth2/token", PasswordGrant(), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>失败必须是 400 + error 码，而不是历史端点的 200 + success=false。</summary>
    [Fact]
    public async Task Token_WithWrongPassword_Returns400InvalidGrant()
    {
        using var http = CreateClientWithBasicAuth();

        var response = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = IdentityConstants.GrantTypePassword,
            ["username"] = IdentityServerFixture.AdminUsername,
            ["password"] = "definitely-not-the-password"
        }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("error_description").GetString()));
    }

    [Fact]
    public async Task Token_WithMissingGrantType_Returns400InvalidRequest()
    {
        using var http = CreateClientWithBasicAuth();

        var response = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = IdentityServerFixture.AdminUsername
        }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_request", body.GetProperty("error").GetString());
    }

    /// <summary>历史短名在标准端点上不被接受，必须用 URN。</summary>
    [Theory]
    [InlineData("sms")]
    [InlineData("wechat_code")]
    [InlineData("no_such_grant")]
    public async Task Token_WithANonStandardGrantName_Returns400UnsupportedGrantType(string grantType)
    {
        using var http = CreateClientWithBasicAuth();

        var response = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = grantType
        }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("unsupported_grant_type", body.GetProperty("error").GetString());
    }

    /// <summary>URN 名字被识别；本应用没开短信，所以走到策略拒绝而不是"不认识这个 grant"。</summary>
    [Fact]
    public async Task Token_WithTheSmsUrnGrant_ReachesThePolicyCheck()
    {
        using var http = CreateClientWithBasicAuth();

        var response = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = OAuthGrantTypes.Sms,
            ["phone"] = "13800138000",
            ["code"] = "123456"
        }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("unauthorized_client", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Token_WithAScopeRequest_Returns400InvalidScope()
    {
        using var http = CreateClientWithBasicAuth();

        var response = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = IdentityConstants.GrantTypePassword,
            ["username"] = IdentityServerFixture.AdminUsername,
            ["password"] = IdentityServerFixture.AdminPassword,
            ["scope"] = "openid profile"
        }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_scope", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task RefreshTokenGrant_RotatesTheRefreshToken()
    {
        using var http = CreateClientWithBasicAuth();
        var first = await (await http.PostAsync("/oauth2/token", PasswordGrant(), TestContext.Current.CancellationToken))
            .Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        var refreshToken = first.GetProperty("refresh_token").GetString()!;

        var response = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = IdentityConstants.GrantTypeRefreshToken,
            ["refresh_token"] = refreshToken
        }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.NotEqual(refreshToken, body.GetProperty("refresh_token").GetString());

        // 旧 token 已被消费，重放必须失败。
        var replay = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = IdentityConstants.GrantTypeRefreshToken,
            ["refresh_token"] = refreshToken
        }), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }

    /// <summary>RFC 7009 §2.2：撤销对已存在和不存在的 token 都返回 200，不泄露 token 是否有效。</summary>
    [Fact]
    public async Task Revoke_ReturnsOkForBothKnownAndUnknownTokens()
    {
        using var http = CreateClientWithBasicAuth();
        var issued = await (await http.PostAsync("/oauth2/token", PasswordGrant(), TestContext.Current.CancellationToken))
            .Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);

        var known = await http.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = issued.GetProperty("refresh_token").GetString()!,
            ["token_type_hint"] = "refresh_token"
        }), TestContext.Current.CancellationToken);
        var unknown = await http.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = "this-token-never-existed"
        }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, known.StatusCode);
        Assert.Equal(HttpStatusCode.OK, unknown.StatusCode);
    }

    /// <summary>
    /// RFC 7009 §2.1：只能撤销签发给自己的 token。持有别的客户端的 refresh token 不足以
    /// 终止对方的会话——响应仍是 200，不泄露 token 归属，但对方的 token 必须还能用。
    /// </summary>
    [Fact]
    public async Task Revoke_DoesNotRevokeATokenIssuedToAnotherClient()
    {
        var otherAppId = $"other-{Guid.NewGuid():N}";
        const string otherSecret = "other-secret";
        await _fixture.SeedGatewayAppAsync(otherAppId, otherSecret);

        using var victim = CreateClientWithBasicAuth();
        var issued = await (await victim.PostAsync("/oauth2/token", PasswordGrant(), TestContext.Current.CancellationToken))
            .Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        var refreshToken = issued.GetProperty("refresh_token").GetString()!;

        using var attacker = _fixture.CreateHttpClient();
        attacker.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{otherAppId}:{otherSecret}")));
        var revoke = await attacker.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(
            new Dictionary<string, string> { ["token"] = refreshToken }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);

        // 受害者的 token 必须仍然可用。
        var refresh = await victim.PostAsync("/oauth2/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = IdentityConstants.GrantTypeRefreshToken,
                ["refresh_token"] = refreshToken
            }), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
    }

    [Fact]
    public async Task Revoke_WithoutClientCredentials_Returns401()
    {
        using var http = _fixture.CreateHttpClient();

        var response = await http.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = "irrelevant"
        }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>撤销后，用同一张 refresh token 再换 token 必须失败。</summary>
    [Fact]
    public async Task Revoke_InvalidatesTheRefreshToken()
    {
        using var http = CreateClientWithBasicAuth();
        var issued = await (await http.PostAsync("/oauth2/token", PasswordGrant(), TestContext.Current.CancellationToken))
            .Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        var refreshToken = issued.GetProperty("refresh_token").GetString()!;

        await http.PostAsync("/oauth2/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = refreshToken
        }), TestContext.Current.CancellationToken);

        var response = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = IdentityConstants.GrantTypeRefreshToken,
            ["refresh_token"] = refreshToken
        }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// 受众隔离：默认（Shared）所有应用拿到同一个部署级 aud——这正是"给 A 签的 token 在 B 也过"
    /// 的成因；切到 PerApplication 后 aud 变成该应用自己的 AppId，受众才真正成为边界。
    /// </summary>
    [Fact]
    public async Task AccessTokenAudience_FollowsTheApplicationAudienceMode()
    {
        var isolatedAppId = $"isolated-{Guid.NewGuid():N}";
        const string isolatedSecret = "isolated-secret";
        await _fixture.SeedGatewayAppAsync(isolatedAppId, isolatedSecret, AudienceMode.PerApplication);

        var sharedAudiences = await IssueAndReadAudiencesAsync(
            IdentityServerFixture.GatewayAppId, IdentityServerFixture.GatewayAppSecret);
        var isolatedAudiences = await IssueAndReadAudiencesAsync(isolatedAppId, isolatedSecret);

        Assert.Equal(_fixture.SharedAudience, Assert.Single(sharedAudiences));
        Assert.Equal(isolatedAppId, Assert.Single(isolatedAudiences));
        Assert.DoesNotContain(_fixture.SharedAudience, isolatedAudiences);
    }

    private async Task<IReadOnlyList<string>> IssueAndReadAudiencesAsync(string appId, string appSecret)
    {
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{appId}:{appSecret}")));

        var response = await http.PostAsync("/oauth2/token", PasswordGrant());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return new JwtSecurityTokenHandler()
            .ReadJwtToken(body.GetProperty("access_token").GetString())
            .Audiences
            .ToList();
    }

    private static FormUrlEncodedContent PasswordGrant() => new(new Dictionary<string, string>
    {
        ["grant_type"] = IdentityConstants.GrantTypePassword,
        ["username"] = IdentityServerFixture.AdminUsername,
        ["password"] = IdentityServerFixture.AdminPassword
    });

    private HttpClient CreateClientWithBasicAuth(string? secret = null)
    {
        var http = _fixture.CreateHttpClient();
        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            $"{IdentityServerFixture.GatewayAppId}:{secret ?? IdentityServerFixture.GatewayAppSecret}"));
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);
        return http;
    }
}
