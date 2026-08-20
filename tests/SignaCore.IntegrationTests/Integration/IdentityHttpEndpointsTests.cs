using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host;
using SignaCore.Host.Startup;
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
        var response = await http.GetAsync("/health", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal("Healthy", content);
    }

    /// <summary>
    /// Both JWKS routes answer. The <c>.json</c> alias is not decoration: it is the path operators,
    /// probes and hand-configured validators try first, and a 404 there is read as "this service
    /// publishes no signing keys".
    /// </summary>
    [Theory]
    [InlineData(WellKnownEndpoints.Jwks)]
    [InlineData(WellKnownEndpoints.JwksJson)]
    public async Task JwksEndpoint_ReturnsValidJwks(string path)
    {
        using var http = _fixture.CreateHttpClient();
        var response = await http.GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("RSA", content);
        Assert.Contains("keys", content);
    }

    /// <summary>
    /// The alias must stay an alias. If the two routes ever drifted onto different handlers, a
    /// consumer that picked the wrong one could validate against a stale or partial key set — the
    /// exact failure JWKS exists to prevent.
    /// </summary>
    [Fact]
    public async Task JwksAlias_ServesTheSameDocumentAsTheCanonicalRoute()
    {
        using var http = _fixture.CreateHttpClient();

        var canonical = await http.GetStringAsync(WellKnownEndpoints.Jwks, TestContext.Current.CancellationToken);
        var alias = await http.GetStringAsync(WellKnownEndpoints.JwksJson, TestContext.Current.CancellationToken);

        Assert.Equal(canonical, alias);
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

        var response = await http.GetAsync(path, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var document = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
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
                new Dictionary<string, string> { ["grant_type"] = grantType }), TestContext.Current.CancellationToken);
            var error = (await probe.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken))
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
        var document = await http.GetFromJsonAsync<JsonElement>("/.well-known/openid-configuration",
            cancellationToken: TestContext.Current.CancellationToken);
        var advertisedIssuer = document.GetProperty("issuer").GetString();

        using var gateway = _fixture.CreateGatewayHttpClient();
        var response = await gateway.PostAsJsonAsync("/api/auth/token", new
        {
            grantType = IdentityConstants.GrantTypePassword,
            username = IdentityServerFixture.AdminUsername,
            password = IdentityServerFixture.AdminPassword
        }, cancellationToken: TestContext.Current.CancellationToken);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
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

    /// <summary>
    /// 管理台 SPA 分支是终止分支：被它接走的请求到不了 MapControllers()。
    /// <para>
    /// 这里遍历**真实注册的每一条路由**，只用前缀名单这道防线去判（不设置 endpoint），
    /// 断言没有任何一条会被 SPA 吞掉。当初漏加 <c>/oauth2</c> 时这条会直接挂——
    /// 而按方法逐个写的用例只能覆盖作者当时想到的路径。
    /// </para>
    /// </summary>
    [Fact]
    public void AdminSpaBranch_NeverSwallowsAnyRegisteredRoute()
    {
        var routes = _fixture.Services
            .GetRequiredService<Microsoft.AspNetCore.Routing.EndpointDataSource>()
            .Endpoints
            .OfType<Microsoft.AspNetCore.Routing.RouteEndpoint>()
            .Select(endpoint => endpoint.RoutePattern.RawText)
            .Where(template => !string.IsNullOrWhiteSpace(template))
            .Select(template => "/" + template!.TrimStart('/'))
            // 路由参数换成占位值，得到一条可用于前缀判断的具体路径。
            .Select(path => System.Text.RegularExpressions.Regex.Replace(path, @"\{[^}]*\}", "x"))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        Assert.NotEmpty(routes);

        var swallowed = routes
            .Where(path => AdminSpaRouting.ShouldServeSpa(ContextFor(path), HostHttpPort))
            .ToList();

        Assert.True(
            swallowed.Count == 0,
            $"These registered routes would be diverted into the admin SPA branch and never reach their "
            + $"handler: {string.Join(", ", swallowed)}");
    }

    private const int HostHttpPort = 5002;

    private static DefaultHttpContext ContextFor(string path)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Features.Set<IHttpConnectionFeature>(new HttpConnectionFeature { LocalPort = HostHttpPort });
        return context;
    }

    [Fact]
    public async Task TokenEndpoint_WithUnsupportedGrantType_ReturnsHttp200WithFailureBody()
    {
        using var http = _fixture.CreateGatewayHttpClient();

        var response = await http.PostAsJsonAsync("/api/auth/token", new { grantType = "no_such_grant" },
            cancellationToken: TestContext.Current.CancellationToken);

        // 失败也返回 200 + Success=false 是对外契约，见 docs/modules/Auth/GetToken/06-CONVENTIONS.md
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("unsupported_grant_type", body);
    }

    [Fact]
    public async Task SmsCodeEndpoint_WithEmptyPhone_ReturnsHttp200WithFailureBody()
    {
        using var http = _fixture.CreateGatewayHttpClient();

        var response = await http.PostAsJsonAsync("/api/auth/sms-code", new { phone = "" }, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("Phone number is required", body);
    }

    [Fact]
    public async Task RevokeEndpoint_WithEmptyToken_ReturnsHttp200WithFailureBody()
    {
        using var http = _fixture.CreateHttpClient();

        var response = await http.PostAsJsonAsync("/api/auth/revoke", new { refreshToken = "" },
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("false", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GatewayFacingEndpoints_WithoutCredentials_ReturnUnauthorized()
    {
        using var http = _fixture.CreateHttpClient();

        var responses = new[]
        {
            await http.PostAsJsonAsync("/api/auth/token", new { grantType = "password" }, cancellationToken: TestContext.Current.CancellationToken),
            await http.PostAsJsonAsync("/api/auth/sms-code", new { phone = "13800138000" }, cancellationToken: TestContext.Current.CancellationToken),
            await http.PostAsJsonAsync("/api/auth/callback/register", new { callbackUrl = "http://example.com/cb", ttlSeconds = 3600 },
                cancellationToken: TestContext.Current.CancellationToken),
            await http.GetAsync("/api/gateway/users/search", TestContext.Current.CancellationToken)
        };

        Assert.All(responses, response => Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode));
    }

    [Fact]
    public async Task TokenEndpoint_WithInvalidGatewayCredentials_ReturnsUnauthorized()
    {
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Add("X-Admin-AppId", "unknown-app");
        http.DefaultRequestHeaders.Add("X-Admin-AppSecret", "wrong-secret");

        var response = await http.PostAsJsonAsync("/api/auth/token", new { grantType = "password" },
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    /// <summary>
    /// A completed installation must never permit reinitialization: the setup API stays routable so
    /// clients get a clear answer, but it can only ever report "already completed".
    /// </summary>
    [Fact]
    public async Task SetupEndpoints_AfterInstallation_RefuseReinitialization()
    {
        using var http = _fixture.CreateHttpClient();

        var status = await http.GetAsync("/api/setup/status", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, status.StatusCode);
        Assert.Equal(
            "completed",
            (await status.Content.ReadFromJsonAsync<JsonElement>(
                cancellationToken: TestContext.Current.CancellationToken)).GetProperty("status").GetString());

        var complete = await http.PostAsJsonAsync("/api/setup/complete", new
        {
            publicBaseUrl = "https://attacker.example",
            username = "attacker",
            password = "Attacker123",
            confirmPassword = "Attacker123",
            setupCode = "does-not-matter"
        }, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Conflict, complete.StatusCode);
    }

    /// <summary>
    /// Settings are readable only with an admin session, and secret values never leave the service.
    /// </summary>
    [Fact]
    public async Task SettingsApi_RequiresAnAdminSessionAndNeverReturnsSecretValues()
    {
        using var anonymous = _fixture.CreateHttpClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/admin/settings",
            TestContext.Current.CancellationToken)).StatusCode);

        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var response = await admin.GetAsync("/api/admin/settings", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        var items = body.GetProperty("items").EnumerateArray().ToList();
        Assert.NotEmpty(items);
        Assert.All(
            items.Where(item => item.GetProperty("isSecret").GetBoolean()),
            item => Assert.Equal(JsonValueKind.Null, item.GetProperty("value").ValueKind));

        // Non-secret values are returned so the console can render the current configuration.
        Assert.Contains(
            items,
            item => item.GetProperty("key").GetString() == "Jwt:Audience"
                && item.GetProperty("value").GetString() == _fixture.SharedAudience);
    }

    /// <summary>
    /// A settings change is validated as a whole snapshot, so a value that only becomes invalid in
    /// combination with an untouched one is refused rather than committed.
    /// </summary>
    [Fact]
    public async Task SettingsApi_RejectsAChangeThatWouldInvalidateTheSnapshot()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();

        var response = await admin.PutAsJsonAsync("/api/admin/settings", new
        {
            values = new Dictionary<string, string>
            {
                // The issuer must keep matching the public base URL.
                ["Jwt:Issuer"] = "https://somewhere.else.test"
            }
        }, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task SettingsApi_RejectsKeysThatAreNotDatabaseBacked()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();

        var response = await admin.PutAsJsonAsync("/api/admin/settings", new
        {
            values = new Dictionary<string, string> { ["Endpoints:Http"] = "9999" }
        }, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// A valid change increments the configuration version, encrypts secrets at rest, and records
    /// which keys changed without recording their values.
    /// </summary>
    [Fact]
    public async Task SettingsApi_AppliesAValidChangeTransactionally()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var before = (await (await admin.GetAsync("/api/admin/settings", TestContext.Current.CancellationToken)).Content
            .ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken)).GetProperty("configurationVersion").GetInt32();

        var response = await admin.PutAsJsonAsync("/api/admin/settings", new
        {
            values = new Dictionary<string, string>
            {
                ["Sms:MaxSendsPerHour"] = "7",
                ["Sms:OtpHmacKey"] = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
            }
        }, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(before + 1, body.GetProperty("configurationVersion").GetInt32());
        Assert.True(body.GetProperty("restartRequired").GetBoolean());

        using var scope = _fixture.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();

        var secret = await db.SystemSettings.AsNoTracking()
            .SingleAsync(setting => setting.Key == "Sms:OtpHmacKey", cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(secret.IsSecret);
        Assert.DoesNotContain("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", secret.Value, StringComparison.Ordinal);

        var audit = await db.AuditLogs.AsNoTracking()
            .Where(entry => entry.Action == "settings_updated")
            .OrderByDescending(entry => entry.CreatedAt)
            .FirstAsync(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Contains("Sms:OtpHmacKey", audit.Description ?? string.Empty, StringComparison.Ordinal);
        Assert.DoesNotContain("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", audit.Description ?? string.Empty, StringComparison.Ordinal);
    }

    /// <summary>
    /// Bootstrap metadata is an authenticated, read-only view of the instance-local file. The
    /// response exposes whether a key exists but never returns the key or connection string.
    /// </summary>
    [Fact]
    public async Task BootstrapSettingsApi_RequiresAdminAndNeverReturnsSecrets()
    {
        using var anonymous = _fixture.CreateHttpClient();
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            (await anonymous.GetAsync(
                "/api/admin/bootstrap",
                TestContext.Current.CancellationToken)).StatusCode);

        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var response = await admin.GetAsync(
            "/api/admin/bootstrap",
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var responseText = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain(IdentityServerFixture.RootSecret, responseText, StringComparison.Ordinal);
        Assert.DoesNotContain("ConnectionString", responseText, StringComparison.OrdinalIgnoreCase);

        using var body = JsonDocument.Parse(responseText);
        Assert.Equal("SQLite", body.RootElement.GetProperty("provider").GetString());
        Assert.True(body.RootElement.GetProperty("masterKeyConfigured").GetBoolean());
        Assert.True(body.RootElement.GetProperty("editable").GetBoolean());
        Assert.True(body.RootElement.GetProperty("singleInstanceOnly").GetBoolean());
    }

    [Fact]
    public async Task BootstrapSettingsApi_RefusesAnUnconfirmedDatabaseChange()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();

        var response = await admin.PutAsJsonAsync("/api/admin/bootstrap", new
        {
            database = new
            {
                provider = "SQLite",
                filePath = "replacement.db"
            },
            confirm = false
        }, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var responseText = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("explicit confirmation", responseText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(IdentityServerFixture.RootSecret, responseText, StringComparison.Ordinal);

        using var healthClient = _fixture.CreateHttpClient();
        using var health = await healthClient.GetAsync(
            "/health/ready",
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
    }

    /// <summary>Browser navigation to /setup goes to the console once installation is complete.</summary>
    [Fact]
    public async Task SetupPage_AfterInstallation_RedirectsToAdminConsole()
    {
        using var http = _fixture.CreateNonRedirectingHttpClient();

        var response = await http.GetAsync("/setup", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal("/admin", response.Headers.Location?.ToString());
    }

    /// <summary>
    /// Liveness and readiness are distinct endpoints, and /health remains an alias for readiness so
    /// existing launchers and Consul checks keep working.
    /// </summary>
    [Theory]
    [InlineData("/health")]
    [InlineData("/health/live")]
    [InlineData("/health/ready")]
    public async Task HealthEndpoints_OnCompletedInstallation_ReportHealthy(string path)
    {
        using var http = _fixture.CreateHttpClient();

        var response = await http.GetAsync(path, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
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

        var searchResponse = await http.GetAsync($"/api/gateway/users/search?username={username}&page=1&pageSize=20",
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, searchResponse.StatusCode);

        var searchPayload = await searchResponse.Content.ReadFromJsonAsync<TestPagedResponse<TestUserItem>>(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.NotNull(searchPayload);
        var searchedUser = Assert.Single(searchPayload!.Items);
        Assert.Equal(accountId.ToString(), searchedUser.UserId);
        Assert.Equal(username, searchedUser.Username);
        Assert.Equal(phone, searchedUser.Phone);
        Assert.Equal(username, searchedUser.DisplayName);

        var batchResponse = await http.PostAsJsonAsync("/api/gateway/users/batch", new[] { accountId.ToString() },
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, batchResponse.StatusCode);

        var batchPayload = await batchResponse.Content.ReadFromJsonAsync<List<TestUserItem>>(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.NotNull(batchPayload);
        var batchUser = Assert.Single(batchPayload!);
        Assert.Equal(searchedUser.UserId, batchUser.UserId);
        Assert.Equal(searchedUser.Username, batchUser.Username);
        Assert.Equal(searchedUser.Phone, batchUser.Phone);
        Assert.Equal(searchedUser.DisplayName, batchUser.DisplayName);
    }
}

/// <summary>
/// Uses a dedicated server fixture because this test intentionally exhausts a limiter partition.
/// Sharing that state with the general endpoint contract tests would make their order observable.
/// </summary>
public sealed class RateLimitingHttpTests : IClassFixture<IdentityServerFixture>
{
    private readonly IdentityServerFixture _fixture;

    public RateLimitingHttpTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task InvalidGatewayCredentials_AreRateLimitedBeforeAuthorization()
    {
        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Add("X-Admin-AppId", "rate-limit-probe-not-registered");
        http.DefaultRequestHeaders.Add("X-Admin-AppSecret", "invalid");

        var statuses = new List<HttpStatusCode>();
        for (var attempt = 0; attempt < 101; attempt++)
        {
            using var response = await http.PostAsJsonAsync(
                "/api/auth/token",
                new { GrantType = IdentityConstants.GrantTypePassword },
                TestContext.Current.CancellationToken);
            statuses.Add(response.StatusCode);
        }

        Assert.Contains(HttpStatusCode.TooManyRequests, statuses);

        using var health = await http.GetAsync("/health", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
    }
}

public class IdentityServerFixture : IAsyncLifetime
{
    public const string GatewayAppId = "http-contract-app";
    public const string GatewayAppSecret = "http-contract-secret";
    public const string AdminUsername = "http_contract_admin";
    public const string AdminPassword = "HttpContract123";
    public const string RootSecret = "test-master-key-for-e2e-testing-only";

    private WebApplicationFactory<Program>? _factory;
    private string? _databasePath;
    private string? _bootstrapDirectory;

    public async ValueTask InitializeAsync()
    {
        _bootstrapDirectory = Path.Combine(
            Path.GetTempPath(),
            $"signacore-bootstrap-{Guid.NewGuid():N}");
        _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-http-{Guid.NewGuid():N}.db");
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath
        }.ConnectionString;

        // The host no longer takes its database connection, root secret, or administrator from
        // application configuration. Install the database first — through the same migration,
        // settings-seeding, and administrator-creation components production uses — and then point
        // the host at the resulting bootstrap file.
        var bootstrapFilePath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
            _bootstrapDirectory,
            new DatabaseOptions
            {
                Provider = "SQLite",
                ConnectionString = connectionString
            },
            RootSecret,
            AdminUsername,
            AdminPassword);

        // Consul discovery defaults to disabled in the settings catalog, so the test host never
        // tries to register with a Consul that is not running. Registration failures used to surface
        // during host shutdown and poison the whole test class.
        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath));

        _factory.CreateClient();
        await SeedGatewayAppAsync(GatewayAppId, GatewayAppSecret);
    }

    public HttpClient CreateHttpClient()
    {
        return _factory!.CreateClient();
    }

    /// <summary>For asserting on a redirect itself rather than on what it points at.</summary>
    public HttpClient CreateNonRedirectingHttpClient()
    {
        return _factory!.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
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

    public ValueTask DisposeAsync()
    {
        _factory?.Dispose();
        SqliteConnection.ClearAllPools();
        if (_databasePath != null && File.Exists(_databasePath))
        {
            File.Delete(_databasePath);
        }
        if (_bootstrapDirectory != null && Directory.Exists(_bootstrapDirectory))
        {
            Directory.Delete(_bootstrapDirectory, recursive: true);
        }
        return ValueTask.CompletedTask;
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
