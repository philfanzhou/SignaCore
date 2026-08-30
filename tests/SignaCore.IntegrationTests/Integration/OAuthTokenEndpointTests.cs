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
/// RFC 6749 wire contract for <c>/oauth2/token</c>: form-encoded input, Basic/post client
/// authentication, <c>access_token</c>/<c>token_type</c>/<c>expires_in</c> output, and 4xx failures with
/// an <c>error</c> code. It coexists with the legacy <c>/api/auth/token</c> JSON endpoint, which returns
/// 200 for failures, and both routes share the same token issuance pipeline.
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

    /// <summary>
    /// RFC 9068 §2.1 plus per-application audiences: issued tokens use a typ of at+jwt and retain the
    /// shared audience by default.
    /// </summary>
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

    /// <summary>
    /// RFC 6749 §5.2: client authentication failures return 401 with WWW-Authenticate and invalid_client.
    /// </summary>
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

    /// <summary>Failures return 400 with an error code, not the legacy endpoint's 200 with success=false.</summary>
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

    /// <summary>Legacy short names are not accepted at the standards endpoint; a URN is required.</summary>
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

    /// <summary>
    /// The URN is recognized; because SMS is disabled for this application, policy rejects it instead
    /// of treating the grant as unknown.
    /// </summary>
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

        // The old token has been consumed, so replay must fail.
        var replay = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = IdentityConstants.GrantTypeRefreshToken,
            ["refresh_token"] = refreshToken
        }), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
    }

    /// <summary>
    /// RFC 7009 §2.2: revocation returns 200 for known and unknown tokens without revealing validity.
    /// </summary>
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
    /// RFC 7009 §2.1: a client can revoke only its own tokens. Possessing another client's refresh
    /// token is not enough to terminate that client's session. The response remains 200 to avoid
    /// revealing ownership, and the other client's token must remain usable.
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

        // The victim's token must remain usable.
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

    /// <summary>After revocation, exchanging the same refresh token again must fail.</summary>
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
    /// Audience isolation: in the default Shared mode every application receives the same deployment-wide
    /// aud, so a token issued to one application also validates at another. In PerApplication mode, aud is
    /// the application's AppId and becomes an actual boundary.
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
