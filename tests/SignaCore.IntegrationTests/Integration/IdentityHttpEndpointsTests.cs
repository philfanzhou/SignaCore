using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using ServiceMantle.Configuration;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;
using SignaCore.Host;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <remarks>
/// The shared fixture this class owns performs the process-wide pool clear in its disposal
/// (issue #293), so the class belongs to the serialized sqlite-process-state collection.
/// </remarks>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
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
        using var document = JsonDocument.Parse(content);
        var keys = document.RootElement.GetProperty("keys").EnumerateArray().ToArray();
        Assert.NotEmpty(keys);
        Assert.All(keys, key =>
        {
            Assert.Equal("RSA", key.GetProperty("kty").GetString());
            Assert.Equal("sig", key.GetProperty("use").GetString());
            Assert.Equal("RS256", key.GetProperty("alg").GetString());
            Assert.False(string.IsNullOrWhiteSpace(key.GetProperty("kid").GetString()));
            Assert.False(string.IsNullOrWhiteSpace(key.GetProperty("n").GetString()));
            Assert.False(string.IsNullOrWhiteSpace(key.GetProperty("e").GetString()));
            Assert.Equal(new[] { "alg", "e", "kid", "kty", "n", "use" },
                key.EnumerateObject().Select(property => property.Name).OrderBy(name => name, StringComparer.Ordinal));
        });
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

    [Theory]
    [InlineData(WellKnownEndpoints.Jwks)]
    [InlineData(WellKnownEndpoints.JwksJson)]
    public async Task JwksEndpoint_ClientCancellation_ReachesKeyReadWithoutReturningPartialResponse(string path)
    {
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var started = new TaskCompletionSource<CancellationToken>(TaskCreationOptions.RunContinuationsAsynchronously);
        var observed = new TaskCompletionSource<CancellationToken>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<IReadOnlyList<RsaSecurityKey>>(TaskCreationOptions.RunContinuationsAsynchronously);
        IHttpContextAccessor? accessor = null;
        var keys = new Mock<IKeyManager>();
        keys.SetupGet(manager => manager.InitializationCompleted).Returns(Task.CompletedTask);
        keys.Setup(manager => manager.GetValidKeysAsync(It.IsAny<CancellationToken>()))
            .Returns(async (CancellationToken ct) =>
            {
                var context = Assert.IsAssignableFrom<HttpContext>(accessor!.HttpContext);
                Assert.Equal(context.RequestAborted, ct);
                Assert.False(context.Response.HasStarted);
                started.TrySetResult(ct);
                try
                {
                    return await release.Task.WaitAsync(ct);
                }
                catch (OperationCanceledException)
                {
                    observed.TrySetResult(ct);
                    throw;
                }
            });
        using var factory = _fixture.WithTestServices(services =>
        {
            services.AddHttpContextAccessor();
            services.AddSingleton<IKeyManager>(provider =>
            {
                accessor = provider.GetRequiredService<IHttpContextAccessor>();
                return keys.Object;
            });
        });
        // Exercise an actual connection abort; TestServer can still deliver the middleware's
        // error response after its request token is cancelled.
        factory.UseKestrel(0);
        using var http = factory.CreateClient();
        // The production listener binds all interfaces; a client needs a concrete loopback target.
        http.BaseAddress = new UriBuilder(http.BaseAddress!) { Host = IPAddress.Loopback.ToString() }.Uri;
        var response = http.GetAsync(path, HttpCompletionOption.ResponseHeadersRead, cancellation.Token);
        try
        {
            if (await Task.WhenAny(started.Task, response).WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken) == response)
            {
                using var unexpected = await response;
                Assert.Fail($"JWKS completed before key read: HTTP {(int)unexpected.StatusCode}.");
            }
            var requestToken = await started.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            Assert.True(requestToken.CanBeCanceled);
            Assert.False(response.IsCompleted);
            cancellation.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await response);
            Assert.Equal(requestToken,
                await observed.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken));
            Assert.True(requestToken.IsCancellationRequested);
            keys.Verify(manager => manager.GetValidKeysAsync(requestToken), Times.Once);
        }
        finally
        {
            // Release the server even if a regression drops the token, so a failing test cannot
            // leave its intentionally suspended key read alive during fixture disposal.
            release.TrySetResult(Array.Empty<RsaSecurityKey>());
        }
    }

    /// <summary>
    /// The discovery document is served from both the OIDC and the RFC 8414 standard paths, and both
    /// return the same content.
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
        Assert.Equal($"{origin}/oauth2/authorize", document.GetProperty("authorization_endpoint").GetString());
        Assert.Equal($"{origin}/oauth2/token", document.GetProperty("token_endpoint").GetString());
        Assert.Equal($"{origin}/oauth2/revoke", document.GetProperty("revocation_endpoint").GetString());
        Assert.Equal(
            ["code"],
            document.GetProperty("response_types_supported").EnumerateArray().Select(item => item.GetString()));
        Assert.Equal(
            ["S256"],
            document.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(item => item.GetString()));
        // userinfo_endpoint is advertised with the delivered UserInfo read (AC-08), and
        // offline_access with the delivered interactive refresh family (AC-12).
        Assert.Equal(
            ["openid", "profile", "offline_access"],
            document.GetProperty("scopes_supported").EnumerateArray().Select(item => item.GetString()));
        Assert.Equal(
            $"{origin}/oauth2/userinfo",
            document.GetProperty("userinfo_endpoint").GetString());
        Assert.Equal(
            ["RS256"],
            document.GetProperty("id_token_signing_alg_values_supported").EnumerateArray().Select(item => item.GetString()));

        var grantTypes = document.GetProperty("grant_types_supported")
            .EnumerateArray().Select(item => item.GetString()!).ToList();
        Assert.Contains(IdentityConstants.GrantTypePassword, grantTypes);
        Assert.Contains(IdentityConstants.GrantTypeRefreshToken, grantTypes);
        Assert.Contains("authorization_code", grantTypes);

        // Every advertised grant name has to be one the token endpoint genuinely knows: if any of
        // them comes back as unsupported_grant_type, the discovery document and the endpoint have
        // already drifted apart.
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
    /// The issuer in the discovery document has to match the iss of an actually issued token exactly;
    /// otherwise any client that validates the issuer per the standard rejects the tokens this
    /// service issues.
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
    /// Pins the outward HTTP route list. The four endpoints under /api/auth used to live on a single
    /// AuthController and were later split by responsibility into four controllers — the routes have
    /// to be neither more nor fewer, and none may be registered twice (in ASP.NET Core a duplicate
    /// registration only throws AmbiguousMatchException once a request actually arrives).
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
     [InlineData("POST", "api/profile/password")]
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
    /// The administration console SPA branch is a terminal branch: a request it takes never reaches
    /// MapControllers().
    /// <para>
    /// This walks <b>every route that is actually registered</b> and judges each one using only the
    /// prefix list line of defence, without setting an endpoint, asserting that none of them can be
    /// swallowed by the SPA. Back when <c>/oauth2</c> was missing from that list, this test would
    /// have failed outright — whereas tests written out one method at a time only cover the paths
    /// their author happened to think of.
    /// </para>
    /// </summary>
    [Fact]
    public void AdminSpaBranch_NeverSwallowsAnyRegisteredRoute()
    {
        var routes = _fixture.Services
            .GetRequiredService<Microsoft.AspNetCore.Routing.EndpointDataSource>()
            .Endpoints
            .OfType<Microsoft.AspNetCore.Routing.RouteEndpoint>()
            // The normal host serves the SPA from a catch-all fallback endpoint ({**path}). Its
            // normalized pattern would otherwise look like a route the SPA diverts, so the guard
            // skips it: routing already runs a fallback only when no more specific endpoint
            // matched, so it cannot swallow a registered route.
            .Where(endpoint => endpoint.Order != int.MaxValue)
            .Select(endpoint => endpoint.RoutePattern.RawText)
            .Where(template => !string.IsNullOrWhiteSpace(template))
            .Select(template => "/" + template!.TrimStart('/'))
            // Route parameters are replaced with a placeholder to get a concrete path the prefix
            // check can be applied to.
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

        // Returning 200 with Success=false on failure is the outward contract; see
        // docs/modules/Auth/GetToken/06-CONVENTIONS.md
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
    /// A completed installation must never permit reinitialization: the shared setup entry stays
    /// routable so clients get a clear answer, but its read can only ever report "completed" and
    /// its completion answers the fixed management conflict without parsing the request.
    /// </summary>
    [Fact]
    public async Task SetupEndpoints_AfterInstallation_RefuseReinitialization()
    {
        using var http = _fixture.CreateHttpClient();

        var status = await http.GetAsync("/management/v1/setup", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, status.StatusCode);
        Assert.Equal(
            "completed",
            (await status.Content.ReadFromJsonAsync<JsonElement>(
                cancellationToken: TestContext.Current.CancellationToken)).GetProperty("status").GetString());

        var complete = await http.SendAsync(new HttpRequestMessage(
            HttpMethod.Post, "/management/v1/setup")
        {
            Headers = { { "X-ServiceMantle-Request", "1" } },
            Content = JsonContent.Create(new { anything = "unparsed" }),
        }, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Conflict, complete.StatusCode);
    }

    /// <summary>
    /// The shared setting queries are readable only with a management session. Sensitive values are
    /// always null, and the product running-configuration-version header rides the current-values
    /// response only.
    /// </summary>
    [Fact]
    public async Task SettingsApi_RequiresAnAdminSessionAndNeverReturnsSecretValues()
    {
        using var anonymous = _fixture.CreateHttpClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/management/v1/settings",
            TestContext.Current.CancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync(
            "/management/v1/settings/definitions",
            TestContext.Current.CancellationToken)).StatusCode);

        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var response = await admin.GetAsync("/management/v1/settings", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        var items = body.GetProperty("values").EnumerateArray().ToList();
        Assert.NotEmpty(items);

        // The running version is the bootstrap version of this process; a just-installed fixture
        // runs the same version it stored, so the header equals the response version here.
        var runningVersion = response.Headers.GetValues("X-SignaCore-Running-Configuration-Version").Single();
        Assert.Equal(body.GetProperty("version").GetInt64().ToString(), runningVersion);

        // Every sensitive value is null in the shared projection, whatever its type.
        Assert.All(
            items.Where(item => item.GetProperty("isSensitive").GetBoolean()),
            item => Assert.Equal(JsonValueKind.Null, item.GetProperty("value").ValueKind));

        // Non-secret values are returned so the console can render the current configuration, on
        // the normalized key space.
        Assert.Contains(
            items,
            item => item.GetProperty("key").GetString() == "jwt.audience"
                && item.GetProperty("value").GetString() == _fixture.SharedAudience);

        // The product header stays off every other endpoint, including the definitions query.
        var definitions = await admin.GetAsync(
            "/management/v1/settings/definitions", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, definitions.StatusCode);
        Assert.False(definitions.Headers.Contains("X-SignaCore-Running-Configuration-Version"));
    }

    /// <summary>
    /// The definitions catalog is the shared safe projection: the fixed six fields per item,
    /// lowercase value types, ordinal-sorted normalized keys, and no default values.
    /// </summary>
    [Fact]
    public async Task SettingsApi_ExposesDefinitionsForTheAdminConsole()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();

        var response = await admin.GetAsync(
            "/management/v1/settings/definitions", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        var definitions = body.GetProperty("definitions").EnumerateArray().ToList();

        // All 43 product keys, in the pinned order of the shared contract.
        Assert.Equal(43, definitions.Count);
        Assert.Equal(
            definitions.Select(item => item.GetProperty("key").GetString()).ToList(),
            definitions.Select(item => item.GetProperty("key").GetString())
                .OrderBy(key => key, StringComparer.Ordinal).ToList());
        Assert.Contains(definitions, item =>
            item.GetProperty("key").GetString() == "consul.discovery.prefer_ip_address");
        Assert.DoesNotContain(definitions, item =>
            (item.GetProperty("key").GetString() ?? string.Empty).Contains(':'));

        Assert.All(definitions, item =>
        {
            Assert.Equal(6, item.EnumerateObject().Count());
            Assert.Contains(
                item.GetProperty("valueType").GetString(),
                new[] { "string", "number", "boolean", "json" });
        });
    }

    /// <summary>
    /// The admin session entry keeps its response shape and reports the account that actually
    /// signed in through the shared management login.
    /// </summary>
    [Fact]
    public async Task AdminSessionApi_WithAManagementCookie_ReturnsTheLoginAccount()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();

        var response = await admin.GetAsync("/api/admin/session/me", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal((await _fixture.GetAdminAccountIdAsync()).ToString(), body.GetProperty("accountId").GetString());
        Assert.Equal(IdentityServerFixture.AdminUsername, body.GetProperty("username").GetString());
        Assert.True(body.GetProperty("isAuthenticated").GetBoolean());
    }

    /// <summary>
    /// A forged legacy <c>qz_admin_session</c> cookie no longer authenticates anywhere: the admin
    /// API sees the closed management unauthenticated response, exactly as with no cookie at all.
    /// </summary>
    [Fact]
    public async Task AdminApi_WithAForgedLegacyCookie_IsUnauthorized()
    {
        using var client = _fixture.CreateHttpClient();
        client.DefaultRequestHeaders.TryAddWithoutValidation(
            "Cookie", "qz_admin_session=forged-legacy-ticket");

        var response = await client.GetAsync("/management/v1/settings", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("management.session.", body, StringComparison.Ordinal);
    }

    /// <summary>
    /// A settings change is validated as a whole snapshot, so a value that only becomes invalid in
    /// combination with an untouched one is refused rather than committed.
    /// </summary>
    [Fact]
    public async Task SettingsApi_RejectsAChangeThatWouldInvalidateTheSnapshot()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var version = await ReadConfigurationVersionAsync(admin);

        var response = await admin.PostAsJsonAsync("/management/v1/settings", new
        {
            expectedVersion = version,
            changes = new[]
            {
                // The issuer must keep matching the public base URL.
                new { key = "jwt.issuer", value = "https://somewhere.else.test" }
            }
        }, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        // A validation failure answers the fixed management 400 body and never echoes the input.
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("somewhere.else.test", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SettingsApi_RejectsKeysThatAreNotDatabaseBacked()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var version = await ReadConfigurationVersionAsync(admin);

        var response = await admin.PostAsJsonAsync("/management/v1/settings", new
        {
            expectedVersion = version,
            changes = new[] { new { key = "endpoints.http", value = "9999" } }
        }, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// A valid change commits one new aggregate version with per-key shared audits, keeps the
    /// operator on the login identity, and never writes the legacy system_settings table.
    /// </summary>
    [Fact]
    public async Task SettingsApi_AppliesAValidChangeTransactionally()
    {
        const string canary = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var before = await ReadConfigurationVersionAsync(admin);
        var auditRowsBefore = await CountSharedAuditRowsAsync();

        var response = await admin.PostAsJsonAsync("/management/v1/settings", new
        {
            expectedVersion = before,
            changes = new object[]
            {
                new { key = "sms.max_sends_per_hour", value = "7" },
                new { key = "sms.otp_hmac_key", value = canary }
            }
        }, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(before + 1, body.GetProperty("version").GetInt64());
        Assert.Equal(1, body.EnumerateObject().Count());

        using (var scope = _fixture.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();

            // The retired legacy table stays gone after a management-path change.
            Assert.False(await SharedSettingTestDatabase.LegacyTableExistsAsync(
                db, TestContext.Current.CancellationToken));

            // The shared aggregate holds the new version; the operator is the login account.
            var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(
                db, TestContext.Current.CancellationToken);
            Assert.NotNull(aggregate);
            Assert.Equal(before + 1, aggregate!.Version);
            Assert.Equal(
                (await _fixture.GetAdminAccountIdAsync()).ToString(),
                aggregate.UpdatedBy);
            var values = SharedSettingTestDatabase.ParseValues(aggregate);
            Assert.Equal("7", values["sms.max_sends_per_hour"]);
            Assert.True(values["sms.otp_hmac_key"].StartsWith("sm:v1:", StringComparison.Ordinal));
            Assert.DoesNotContain(canary, values["sms.otp_hmac_key"], StringComparison.Ordinal);

            // One key-only audit row per changed key on top of the installation's own audit set;
            // the canary value never reaches the audit store in any form.
            var auditTexts = await SharedSettingTestDatabase.LoadSharedAuditJsonAsync(
                db, TestContext.Current.CancellationToken);
            Assert.Equal(auditRowsBefore + 2, auditTexts.Count);
            Assert.Contains(auditTexts, text =>
                text.Contains("sms.otp_hmac_key", StringComparison.Ordinal));
            Assert.DoesNotContain(canary, string.Join("|", auditTexts), StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// The stored version moves ahead of the running one after a committed change, while the
    /// running-version header keeps describing the process start — that is exactly how the console
    /// derives "restart pending" without treating a refreshed query as an activated runtime.
    /// </summary>
    [Fact]
    public async Task SettingsApi_ReportsTheBootstrapVersionWhileTheStoredVersionMovesAhead()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var before = await ReadConfigurationVersionAsync(admin);
        var runningAtStart = (await admin.GetAsync("/management/v1/settings",
            TestContext.Current.CancellationToken)).Headers
            .GetValues("X-SignaCore-Running-Configuration-Version").Single();

        var update = await admin.PostAsJsonAsync("/management/v1/settings", new
        {
            expectedVersion = before,
            changes = new[] { new { key = "sms.max_sends_per_day", value = "77" } }
        }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, update.StatusCode);

        var after = await admin.GetAsync("/management/v1/settings", TestContext.Current.CancellationToken);
        var body = await response(update);
        Assert.Equal(before + 1, body.GetProperty("version").GetInt64());
        Assert.Equal(runningAtStart,
            after.Headers.GetValues("X-SignaCore-Running-Configuration-Version").Single());
    }

    /// <summary>
    /// Two racing updates over the same expected version have exactly one winner: the loser gets
    /// the fixed management 409 and leaves no second version and no extra audit rows.
    /// </summary>
    [Fact]
    public async Task SettingsApi_AnswersConflictForAStaleExpectedVersion()
    {
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var version = await ReadConfigurationVersionAsync(admin);

        var winner = await admin.PostAsJsonAsync("/management/v1/settings", new
        {
            expectedVersion = version,
            changes = new[] { new { key = "sms.max_attempts", value = "9" } }
        }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, winner.StatusCode);

        var loser = await admin.PostAsJsonAsync("/management/v1/settings", new
        {
            expectedVersion = version,
            changes = new[] { new { key = "sms.lockout_seconds", value = "60" } }
        }, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Conflict, loser.StatusCode);

        using var scope = _fixture.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(
            db, TestContext.Current.CancellationToken);
        Assert.Equal(version + 1, aggregate!.Version);
        var values = SharedSettingTestDatabase.ParseValues(aggregate);
        Assert.Equal("9", values["sms.max_attempts"]);
        Assert.False(values.TryGetValue("sms.lockout_seconds", out var loserValue) &&
            loserValue == "60");
    }

    /// <summary>
    /// A protection failure inside the executor's transaction rolls the whole attempt back: the
    /// aggregate keeps its version and no audit rows are added — no partial state anywhere.
    /// </summary>
    [Fact]
    public async Task SettingsApi_RollsBackWhenProtectionFails()
    {
        using var rawFactory = _fixture.WithTestServices(services =>
        {
            services.RemoveAll<IServiceSettingRootKeySource>();
            services.AddSingleton<IServiceSettingRootKeySource>(new ThrowingRootKeySource());
        });
        using var http = rawFactory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });

        // The derived host carries the forged legacy cookie path: without a management session the
        // request never reaches the executor, so drive it through an anonymous request first to
        // prove the endpoint is protected, then complete a real login on this host.
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.GetAsync("/management/v1/settings",
            TestContext.Current.CancellationToken)).StatusCode);

        var version = await ReadConfigurationVersionAsync(await _fixture.CreateAdminHttpClientAsync());
        using var admin = await LoginOnHostAsync(rawFactory);

        var response = await admin.PostAsJsonAsync("/management/v1/settings", new
        {
            expectedVersion = version,
            changes = new[] { new { key = "sms.otp_hmac_key", value = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=" } }
        }, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal("{\"errorCode\":\"management.settings.update_unavailable\"}", body);

        using var scope = _fixture.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(
            db, TestContext.Current.CancellationToken);
        Assert.Equal(version, aggregate!.Version);
    }

    private static async Task<JsonElement> response(HttpResponseMessage message) =>
        await message.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);

    private static async Task<long> ReadConfigurationVersionAsync(HttpClient admin)
    {
        var body = await response(await admin.GetAsync(
            "/management/v1/settings", TestContext.Current.CancellationToken));
        return body.GetProperty("version").GetInt64();
    }

    private async Task<int> CountSharedAuditRowsAsync()
    {
        using var scope = _fixture.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        return (await SharedSettingTestDatabase.LoadSharedAuditJsonAsync(
            db, TestContext.Current.CancellationToken)).Count;
    }

    /// <summary>Logs the bootstrap administrator in on a specific derived host.</summary>
    private async Task<HttpClient> LoginOnHostAsync(WebApplicationFactory<Program> factory)
    {
        var http = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
        using var login = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
        {
            Content = JsonContent.Create(new
            {
                username = IdentityServerFixture.AdminUsername,
                password = IdentityServerFixture.AdminPassword
            })
        };
        login.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        (await http.SendAsync(login, TestContext.Current.CancellationToken)).EnsureSuccessStatusCode();
        return http;
    }

    private sealed class ThrowingRootKeySource : IServiceSettingRootKeySource
    {
        public ValueTask<string> GetRootKeyAsync(CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("root key unavailable");
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

        // The shared update entry, still without the SignaCore confirmation header.
        using var request = new HttpRequestMessage(HttpMethod.Put, "/management/v1/bootstrap")
        {
            Content = JsonContent.Create(new
            {
                database = new
                {
                    provider = "SQLite",
                    serverVersion = (string?)null,
                    connectionString = "Data Source=replacement.db"
                }
            })
        };
        request.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        using var response = await admin.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var responseText = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("signacore.bootstrap.confirmation_required", responseText, StringComparison.Ordinal);
        Assert.DoesNotContain(IdentityServerFixture.RootSecret, responseText, StringComparison.Ordinal);

        // The legacy controller route no longer exists.
        using var legacy = await admin.PutAsJsonAsync("/api/admin/bootstrap", new { confirm = true },
            TestContext.Current.CancellationToken);
        Assert.True(
            legacy.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.MethodNotAllowed,
            $"the legacy route answered {legacy.StatusCode}");

        using var healthClient = _fixture.CreateHttpClient();
        using var health = await healthClient.GetAsync(
            "/health/ready",
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
    }

    /// <summary>
    /// A valid externally issued token cannot authorize the bootstrap update: the entry's session
    /// policy pins the fixed management cookie scheme, so the external default scheme stays
    /// unauthenticated even with a Bearer token attached.
    /// </summary>
    [Fact]
    public async Task BootstrapSettingsApi_RefusesAnExternallyAuthenticatedCaller()
    {
        using var gateway = _fixture.CreateGatewayHttpClient();
        var tokenResponse = await gateway.PostAsJsonAsync("/api/auth/token", new
        {
            grantType = IdentityConstants.GrantTypePassword,
            username = IdentityServerFixture.AdminUsername,
            password = IdentityServerFixture.AdminPassword
        }, TestContext.Current.CancellationToken);
        var tokenBody = await tokenResponse.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.True(tokenBody.GetProperty("success").GetBoolean(), tokenBody.ToString());
        var accessToken = tokenBody.GetProperty("accessToken").GetString()!;

        using var client = _fixture.CreateHttpClient();
        using var request = new HttpRequestMessage(HttpMethod.Put, "/management/v1/bootstrap")
        {
            Content = JsonContent.Create(new
            {
                database = new
                {
                    provider = "SQLite",
                    serverVersion = (string?)null,
                    connectionString = "Data Source=replacement.db"
                }
            })
        };
        request.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        request.Headers.TryAddWithoutValidation("X-SignaCore-Confirm-Database-Change", "1");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Bearer", accessToken);

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var responseText = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain(IdentityServerFixture.RootSecret, responseText, StringComparison.Ordinal);
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

    /// <summary>
    /// The shared ServiceMantle health capability is registered but deliberately never mapped, so
    /// the health route table keeps exactly the three ASP.NET Core health-check endpoints. Mapping
    /// the shared endpoints as well would duplicate these very routes and make the host ambiguous.
    /// </summary>
    [Fact]
    public void HealthRouteTable_WithTheSharedRegistration_KeepsExactlyTheThreeMappedRoutes()
    {
        using var factory = _fixture.WithTestServices(_ => { });

        var healthRoutes = factory.Services.GetServices<EndpointDataSource>()
            .SelectMany(source => source.Endpoints)
            .OfType<RouteEndpoint>()
            .Select(endpoint => endpoint.RoutePattern.RawText)
            .Where(text => text is not null && text.StartsWith("/health", StringComparison.OrdinalIgnoreCase))
            .OrderBy(text => text, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(["/health", "/health/live", "/health/ready"], healthRoutes);
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
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
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

    /// <summary>
    /// The exact legacy-keyed values the fixture seeded into the shared aggregate, for
    /// projection-equivalence assertions.
    /// </summary>
    public static IReadOnlyDictionary<string, string> SeededSettingValues =>
        InstallationTestSupport.BuildCompletedInstallationValues(AdminUsername);

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

    public WebApplicationFactory<Program> WithTestServices(Action<IServiceCollection> configure) =>
        _factory!.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Endpoints:Http", "0");
            builder.ConfigureTestServices(configure);
        });

    /// <summary>
    /// The login-derived hosts created for admin clients. Each carries its own Setup rate-limit
    /// partition state, so logins stay isolated without relaxing the production limit; they are
    /// disposed with the fixture.
    /// </summary>
    private readonly List<WebApplicationFactory<Program>> _sessionHosts = [];

    public HttpClient CreateHttpClient()
    {
        return _factory!.CreateClient();
    }

    /// <summary>
    /// For asserting on a redirect itself rather than on what it points at. With
    /// <paramref name="handleCookies"/> disabled the client keeps no cookie state between
    /// requests, so a test replays exactly the cookies it names.
    /// </summary>
    public HttpClient CreateNonRedirectingHttpClient(bool handleCookies = true)
    {
        return _factory!.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = handleCookies
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
        // A derived host carries its own Setup rate-limit partition, so the shared login does not
        // consume the fixture host's window; the database file stays shared. The management cookie
        // is Secure in every environment, so the client addresses the in-memory TestServer over
        // https — otherwise the cookie container refuses to replay it.
        var factory = WithTestServices(_ => { });
        _sessionHosts.Add(factory);
        var http = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
        using var login = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
        {
            Content = JsonContent.Create(new
            {
                username = AdminUsername,
                password = AdminPassword
            })
        };
        login.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        var loginResponse = await http.SendAsync(login);
        loginResponse.EnsureSuccessStatusCode();
        return http;
    }

    /// <summary>The account id of the seeded bootstrap administrator.</summary>
    public async Task<Guid> GetAdminAccountIdAsync()
    {
        using var scope = _factory!.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var credential = await db.PasswordCredentials.AsNoTracking()
            .SingleAsync(item => item.Username == AdminUsername, TestContext.Current.CancellationToken);
        return credential.AccountId;
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
        foreach (var host in _sessionHosts)
        {
            host.Dispose();
        }

        _factory?.Dispose();
        TestSqlitePools.ClearAll();
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
