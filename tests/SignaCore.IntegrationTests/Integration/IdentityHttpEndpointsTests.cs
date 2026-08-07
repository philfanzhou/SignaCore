using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Database.Entity;
using Xunit;

namespace SignaCore.Tests.Integration;

public class IdentityHttpEndpointsTests : IClassFixture<IdentityServerFixture>
{
    private readonly IdentityServerFixture _fixture;

    public IdentityHttpEndpointsTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task HealthCheckEndpoint_ReturnsHealthy()
    {
        using var http = _fixture.CreateHttpClient();
        var response = await http.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        Assert.Equal("Healthy", content);
    }

    [Fact]
    public async Task JwksEndpoint_ReturnsValidJwks()
    {
        using var http = _fixture.CreateHttpClient();
        var response = await http.GetAsync("/.well-known/jwks");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("RSA", content);
        Assert.Contains("keys", content);
    }

    /// <summary>
    /// 发现文档挂在 OIDC 与 RFC 8414 两个标准路径上，且两处返回同一份内容。
    /// </summary>
    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-authorization-server")]
    public async Task DiscoveryEndpoints_DescribeTheEndpointsThatActuallyExist(string path)
    {
        using var http = _fixture.CreateHttpClient();

        var response = await http.GetAsync(path);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var document = await response.Content.ReadFromJsonAsync<JsonElement>();
        var origin = $"{http.BaseAddress!.Scheme}://{http.BaseAddress.Authority}";

        Assert.Equal($"{origin}/.well-known/jwks", document.GetProperty("jwks_uri").GetString());
        Assert.Equal($"{origin}/oauth2/token", document.GetProperty("token_endpoint").GetString());
        Assert.Equal($"{origin}/oauth2/revoke", document.GetProperty("revocation_endpoint").GetString());
        Assert.Empty(document.GetProperty("response_types_supported").EnumerateArray());

        var grantTypes = document.GetProperty("grant_types_supported")
            .EnumerateArray().Select(item => item.GetString()!).ToList();
        Assert.Contains(IdentityConstants.GrantTypePassword, grantTypes);
        Assert.Contains(IdentityConstants.GrantTypeRefreshToken, grantTypes);

        // 广播的每个 grant 名字都必须被 token 端点真正认识：任何一个换回
        // unsupported_grant_type，说明发现文档和端点已经对不上了。
        using var oauth = CreateOAuthClient();
        foreach (var grantType in grantTypes)
        {
            var probe = await oauth.PostAsync("/oauth2/token", new FormUrlEncodedContent(
                new Dictionary<string, string> { ["grant_type"] = grantType }));
            var error = (await probe.Content.ReadFromJsonAsync<JsonElement>())
                .GetProperty("error").GetString();
            Assert.NotEqual("unsupported_grant_type", error);
        }
    }

    private HttpClient CreateOAuthClient()
    {
        var http = _fixture.CreateHttpClient();
        var credentials = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(
            $"{IdentityServerFixture.GatewayAppId}:{IdentityServerFixture.GatewayAppSecret}"));
        http.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", credentials);
        return http;
    }

    /// <summary>
    /// 发现文档的 issuer 必须与真实签发 token 的 iss 完全一致，否则任何按标准校验
    /// issuer 的客户端都会拒掉本服务签发的 token。
    /// </summary>
    [Fact]
    public async Task DiscoveryIssuer_MatchesTheIssuerClaimOfAnIssuedToken()
    {
        using var http = _fixture.CreateHttpClient();
        var document = await http.GetFromJsonAsync<JsonElement>("/.well-known/openid-configuration");
        var advertisedIssuer = document.GetProperty("issuer").GetString();

        using var gateway = _fixture.CreateGatewayHttpClient();
        var response = await gateway.PostAsJsonAsync("/api/auth/token", new
        {
            grantType = IdentityConstants.GrantTypePassword,
            username = IdentityServerFixture.AdminUsername,
            password = IdentityServerFixture.AdminPassword
        });
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("success").GetBoolean(), body.ToString());

        var accessToken = body.GetProperty("accessToken").GetString()!;
        var payload = JsonSerializer.Deserialize<JsonElement>(DecodeSegment(accessToken.Split('.')[1]));

        Assert.Equal(advertisedIssuer, payload.GetProperty("iss").GetString());
    }

    private static byte[] DecodeSegment(string segment)
    {
        var padded = segment.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '='));
    }

    /// <summary>
    /// 锁定对外 HTTP 路由清单。/api/auth 下四个端点原本在同一个 AuthController 上，
    /// 后来按职责拆成四个 controller——路由必须一个不多、一个不少、也不能重复注册
    /// （重复注册在 ASP.NET Core 里要到实际请求时才会抛 AmbiguousMatchException）。
    /// </summary>
    [Theory]
    [InlineData("POST", "api/auth/token")]
    [InlineData("POST", "api/auth/sms-code")]
    [InlineData("POST", "api/auth/revoke")]
    [InlineData("POST", "api/auth/callback/register")]
    [InlineData("GET", "api/gateway/users/search")]
    [InlineData("POST", "api/gateway/users/batch")]
    [InlineData("POST", "oauth2/token")]
    [InlineData("POST", "oauth2/revoke")]
    [InlineData("GET", "api/profile/wechat")]
    [InlineData("POST", "api/profile/wechat")]
    [InlineData("DELETE", "api/profile/wechat")]
    public void PublicRoutes_AreRegisteredExactlyOnce(string httpMethod, string routeTemplate)
    {
        var endpoints = _fixture.Services
            .GetRequiredService<Microsoft.AspNetCore.Routing.EndpointDataSource>()
            .Endpoints
            .OfType<Microsoft.AspNetCore.Routing.RouteEndpoint>()
            .Where(endpoint =>
                string.Equals(endpoint.RoutePattern.RawText, routeTemplate, StringComparison.OrdinalIgnoreCase)
                && (endpoint.Metadata
                        .GetMetadata<Microsoft.AspNetCore.Routing.IHttpMethodMetadata>()
                        ?.HttpMethods.Contains(httpMethod, StringComparer.OrdinalIgnoreCase) ?? false))
            .ToList();

        Assert.Single(endpoints);
    }

    [Fact]
    public async Task TokenEndpoint_WithUnsupportedGrantType_ReturnsHttp200WithFailureBody()
    {
        using var http = _fixture.CreateGatewayHttpClient();

        var response = await http.PostAsJsonAsync("/api/auth/token", new { grantType = "no_such_grant" });

        // 失败也返回 200 + Success=false 是对外契约，见 docs/modules/Auth/GetToken/06-CONVENTIONS.md
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("unsupported_grant_type", body);
    }

    [Fact]
    public async Task SmsCodeEndpoint_WithEmptyPhone_ReturnsHttp200WithFailureBody()
    {
        using var http = _fixture.CreateGatewayHttpClient();

        var response = await http.PostAsJsonAsync("/api/auth/sms-code", new { phone = "" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Phone number is required", body);
    }

    [Fact]
    public async Task RevokeEndpoint_WithEmptyToken_ReturnsHttp200WithFailureBody()
    {
        using var http = _fixture.CreateHttpClient();

        var response = await http.PostAsJsonAsync("/api/auth/revoke", new { refreshToken = "" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("false", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GatewayFacingEndpoints_WithoutCredentials_ReturnUnauthorized()
    {
        using var http = _fixture.CreateHttpClient();

        var responses = new[]
        {
            await http.PostAsJsonAsync("/api/auth/token", new { grantType = "password" }),
            await http.PostAsJsonAsync("/api/auth/sms-code", new { phone = "13800138000" }),
            await http.PostAsJsonAsync("/api/auth/callback/register",
                new { callbackUrl = "http://example.com/cb", ttlSeconds = 3600 }),
            await http.GetAsync("/api/gateway/users/search")
        };

        Assert.All(responses, response => Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode));
    }

    [Fact]
    public async Task TokenEndpoint_WithInvalidGatewayCredentials_ReturnsUnauthorized()
    {
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Add("X-Admin-AppId", "unknown-app");
        http.DefaultRequestHeaders.Add("X-Admin-AppSecret", "wrong-secret");

        var response = await http.PostAsJsonAsync("/api/auth/token", new { grantType = "password" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ConsulOperationsEndpoints_WithoutAdminSession_ReturnUnauthorized()
    {
        using var http = _fixture.CreateHttpClient();

        var statusResponse = await http.GetAsync("/consul/status");
        var invalidateResponse = await http.PostAsync("/consul/cache/invalidate", content: null);

        Assert.Equal(HttpStatusCode.Unauthorized, statusResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, invalidateResponse.StatusCode);
    }

    [Fact]
    public async Task ConsulStatusEndpoint_WithAdminSession_ReturnsOk()
    {
        using var http = await _fixture.CreateAdminHttpClientAsync();

        var response = await http.GetAsync("/consul/status");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task GatewayUserQueries_SearchAndBatchReturnSameUsers()
    {
        var appId = $"gateway_app_{Guid.NewGuid():N}";
        var appSecret = "gateway_secret_123";
        var username = $"linked_user_{Guid.NewGuid():N}";
        var phone = $"138{Guid.NewGuid():N}".Substring(0, 11);
        var accountId = Guid.NewGuid();

        await _fixture.SeedGatewayAppAsync(appId, appSecret);
        await _fixture.SeedGatewayUserAsync(accountId, username, phone, "managed");

        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Add("X-Admin-AppId", appId);
        http.DefaultRequestHeaders.Add("X-Admin-AppSecret", appSecret);

        var searchResponse = await http.GetAsync($"/api/gateway/users/search?username={username}&page=1&pageSize=20");
        Assert.Equal(HttpStatusCode.OK, searchResponse.StatusCode);

        var searchPayload = await searchResponse.Content.ReadFromJsonAsync<TestPagedResponse<TestUserItem>>();
        Assert.NotNull(searchPayload);
        var searchedUser = Assert.Single(searchPayload!.Items);
        Assert.Equal(accountId.ToString(), searchedUser.UserId);
        Assert.Equal(username, searchedUser.Username);
        Assert.Equal(phone, searchedUser.Phone);
        Assert.Equal(username, searchedUser.DisplayName);

        var batchResponse = await http.PostAsJsonAsync("/api/gateway/users/batch", new[] { accountId.ToString() });
        Assert.Equal(HttpStatusCode.OK, batchResponse.StatusCode);

        var batchPayload = await batchResponse.Content.ReadFromJsonAsync<List<TestUserItem>>();
        Assert.NotNull(batchPayload);
        var batchUser = Assert.Single(batchPayload!);
        Assert.Equal(searchedUser.UserId, batchUser.UserId);
        Assert.Equal(searchedUser.Username, batchUser.Username);
        Assert.Equal(searchedUser.Phone, batchUser.Phone);
        Assert.Equal(searchedUser.DisplayName, batchUser.DisplayName);
    }
}

public class IdentityServerFixture : IAsyncLifetime
{
    public const string GatewayAppId = "http-contract-app";
    public const string GatewayAppSecret = "http-contract-secret";
    public const string AdminUsername = "http_contract_admin";
    public const string AdminPassword = "HttpContract123";
    private WebApplicationFactory<Program>? _factory;
    private string? _previousMasterKey;
    private string? _databasePath;

    public async Task InitializeAsync()
    {
        _previousMasterKey = Environment.GetEnvironmentVariable("RSA_MASTER_KEY");
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", "test-master-key-for-e2e-testing-only");
        _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-http-{Guid.NewGuid():N}.db");
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath
        }.ConnectionString;

        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("AdminBootstrap:Username", AdminUsername);
                builder.UseSetting("AdminBootstrap:Password", AdminPassword);
                builder.UseSetting("Database:Provider", "SQLite");
                builder.UseSetting("Database:ServerVersion", "");
                builder.UseSetting("Database:ConnectionString", connectionString);

                // 测试宿主不向 Consul 注册服务实例。本机没有 Consul，注册与注销都会失败，
                // 而注销发生在 host 关停期间——异常会从 _factory.Dispose() 冒出去，
                // 被 xUnit 记为 "Test Class Cleanup Failure"，把本类所有测试染成失败
                // （即使断言全部通过）。这曾是一个偶发的假失败。
                builder.UseSetting("Consul:Discovery:Enabled", "false");
                builder.UseSetting("Consul:Discovery:Register", "false");
                builder.UseSetting("Consul:Discovery:Deregister", "false");
            });

        _factory.CreateClient();
        await SeedGatewayAppAsync(GatewayAppId, GatewayAppSecret);
    }

    public HttpClient CreateHttpClient()
    {
        return _factory!.CreateClient();
    }

    public HttpClient CreateGatewayHttpClient()
    {
        var http = CreateHttpClient();
        http.DefaultRequestHeaders.Add("X-Admin-AppId", GatewayAppId);
        http.DefaultRequestHeaders.Add("X-Admin-AppSecret", GatewayAppSecret);
        return http;
    }

    public async Task<HttpClient> CreateAdminHttpClientAsync()
    {
        var http = CreateHttpClient();
        var loginResponse = await http.PostAsJsonAsync("/api/admin/session/login", new
        {
            username = AdminUsername,
            password = AdminPassword,
            rememberMe = false
        });
        loginResponse.EnsureSuccessStatusCode();
        return http;
    }

    public IServiceProvider Services => _factory!.Services;

    public async Task SeedGatewayAppAsync(
        string appId,
        string appSecret,
        AudienceMode audienceMode = AudienceMode.Shared)
    {
        using var scope = _factory!.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();

        dbContext.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = appId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(appSecret),
            AppName = "Gateway Test App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = audienceMode
        });

        await dbContext.SaveChangesAsync();
    }

    public string SharedAudience =>
        _factory!.Services.GetRequiredService<JwtOptions>().Audience;

    public async Task SeedGatewayUserAsync(Guid accountId, string username, string phone, string? remark)
    {
        using var scope = _factory!.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();

        dbContext.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            Remark = remark
        });

        dbContext.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("SecurePassword123!"),
            CreatedAt = DateTimeOffset.UtcNow
        });

        dbContext.UserLogins.Add(new UserLoginEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            ProviderName = "Sms",
            ProviderUserId = phone
        });

        await dbContext.SaveChangesAsync();
    }

    public Task DisposeAsync()
    {
        _factory?.Dispose();
        SqliteConnection.ClearAllPools();
        if (_databasePath != null && File.Exists(_databasePath))
        {
            File.Delete(_databasePath);
        }
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", _previousMasterKey);
        return Task.CompletedTask;
    }
}

internal sealed record TestPagedResponse<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);

internal sealed record TestUserItem(
    string UserId,
    string Username,
    string Phone,
    bool IsActive,
    string Remark,
    long CreatedAt,
    string DisplayName);
