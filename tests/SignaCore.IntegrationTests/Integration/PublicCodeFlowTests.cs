using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Host.Security;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>Public policy management through a real authorize, login, and none exchange.</summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class PublicCodeFlowTests(IdentityServerFixture fixture) : IClassFixture<IdentityServerFixture>
{
    private const string RedirectUri = "https://public.example.test/callback";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    [Fact]
    public async Task UnregisteredPublicOrigin_DoesNotGainTokenCorsFromDiscoveryAuthenticationMethod()
    {
        using var http = fixture.CreateHttpClient();
        using var preflight = new HttpRequestMessage(HttpMethod.Options, "/oauth2/token");
        preflight.Headers.TryAddWithoutValidation("Origin", "https://public.example.test");
        preflight.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "POST");

        using var response = await http.SendAsync(preflight, TestContext.Current.CancellationToken);

        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task AdminEnable_AuthorizeLoginExchange_Disable_RejectsNewRequests()
    {
        var token = TestContext.Current.CancellationToken;
        using var admin = await fixture.CreateAdminHttpClientAsync();
        using var create = await admin.PostAsJsonAsync("/api/admin/apps",
            new { appName = $"Public Code {Guid.NewGuid():N}", ttlSeconds = 0, clientType = "Public" }, token);
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        var created = await create.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        var appId = created.GetProperty("appId").GetString()!;
        Assert.Null(created.GetProperty("appSecret").GetString());

        var route = $"/api/admin/apps/{appId}";
        using var audience = await admin.PutAsJsonAsync(route + "/audience-mode",
            new { mode = "PerApplication" }, token);
        Assert.Equal(HttpStatusCode.OK, audience.StatusCode);
        using var registration = await admin.PostAsJsonAsync(route + "/oidc/redirect-uris",
            new { kind = "Redirect", uris = new[] { RedirectUri } }, token);
        Assert.Equal(HttpStatusCode.OK, registration.StatusCode);
        using var originRegistration = await admin.PutAsJsonAsync(route + "/oidc/allowed-origins",
            new { origins = new[] { "https://public.example.test" } }, token);
        Assert.Equal(HttpStatusCode.OK, originRegistration.StatusCode);
        using var otherCreate = await admin.PostAsJsonAsync("/api/admin/apps",
            new { appName = $"Other Public {Guid.NewGuid():N}", ttlSeconds = 0, clientType = "Public" }, token);
        Assert.Equal(HttpStatusCode.OK, otherCreate.StatusCode);
        var other = await otherCreate.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        var otherAppId = other.GetProperty("appId").GetString()!;
        using var otherOrigin = await admin.PutAsJsonAsync($"/api/admin/apps/{otherAppId}/oidc/allowed-origins",
            new { origins = new[] { "https://other.example.test" } }, token);
        Assert.Equal(HttpStatusCode.OK, otherOrigin.StatusCode);

        using var invalidRefresh = await admin.PutAsJsonAsync(route + "/oidc-policy",
            Policy(true, true), token);
        Assert.Equal(HttpStatusCode.BadRequest, invalidRefresh.StatusCode);
        using var afterRejected = await admin.GetAsync(route + "/oidc", token);
        var unchanged = await afterRejected.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        Assert.False(unchanged.GetProperty("allowAuthorizationCode").GetBoolean());
        Assert.False(unchanged.GetProperty("allowRefreshToken").GetBoolean());
        using var enabled = await admin.PutAsJsonAsync(route + "/oidc-policy",
            Policy(true, false), token);
        Assert.Equal(HttpStatusCode.OK, enabled.StatusCode);
        using var read = await admin.GetAsync(route + "/oidc", token);
        var policy = await read.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        Assert.True(policy.GetProperty("allowAuthorizationCode").GetBoolean());
        Assert.False(policy.GetProperty("allowRefreshToken").GetBoolean());
        Assert.DoesNotContain("ecret", await read.Content.ReadAsStringAsync(token), StringComparison.Ordinal);

        using var browser = fixture.CreateNonRedirectingHttpClient(handleCookies: false);
        foreach (var (path, method, header) in new[]
                 {
                     ("/oauth2/token", "POST", "content-type"),
                     ("/oauth2/userinfo", "GET", "authorization")
                 })
        {
            using var preflight = new HttpRequestMessage(HttpMethod.Options, path);
            preflight.Headers.TryAddWithoutValidation("Origin", "https://public.example.test");
            preflight.Headers.TryAddWithoutValidation("Access-Control-Request-Method", method);
            preflight.Headers.TryAddWithoutValidation("Access-Control-Request-Headers", header);
            using var permitted = await browser.SendAsync(preflight, token);
            Assert.Equal(HttpStatusCode.NoContent, permitted.StatusCode);
            Assert.Equal("https://public.example.test", permitted.Headers.GetValues("Access-Control-Allow-Origin").Single());
            Assert.False(permitted.Headers.Contains("Access-Control-Allow-Credentials"));
            Assert.False(permitted.Headers.Contains("Access-Control-Max-Age"));
            Assert.Contains("no-store", permitted.Headers.CacheControl!.ToString());
            Assert.Contains("Origin", permitted.Headers.Vary);
            Assert.Contains("Access-Control-Request-Method", permitted.Headers.Vary);
            Assert.Contains("Access-Control-Request-Headers", permitted.Headers.Vary);
            using var wrongHeader = new HttpRequestMessage(HttpMethod.Options, path);
            wrongHeader.Headers.TryAddWithoutValidation("Origin", "https://public.example.test");
            wrongHeader.Headers.TryAddWithoutValidation("Access-Control-Request-Method", method);
            wrongHeader.Headers.TryAddWithoutValidation("Access-Control-Request-Headers", "x-probe");
            using var deniedPreflight = await browser.SendAsync(wrongHeader, token);
            Assert.False(deniedPreflight.Headers.Contains("Access-Control-Allow-Origin"));
        }
        var authorizeUrl = BuildAuthorizeUrl(appId);
        using var invalidRedirect = await browser.GetAsync(
            authorizeUrl.Replace(Uri.EscapeDataString(RedirectUri),
                Uri.EscapeDataString("https://unregistered.example.test/callback"), StringComparison.Ordinal), token);
        Assert.Equal(HttpStatusCode.BadRequest, invalidRedirect.StatusCode);
        Assert.Null(invalidRedirect.Headers.Location);

        var username = $"public_code_{Guid.NewGuid():N}";
        const string password = "Public-Code-Test-123!";
        await SeedUserAsync(fixture.Services, username, password);
        using var authorize = await browser.GetAsync(authorizeUrl, token);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var authorizeLocation = new Uri(new Uri("https://local.test"), authorize.Headers.Location);
        var handle = QueryHelpers.ParseQuery(authorizeLocation.Query)["login_handle"].ToString();
        using var form = await browser.GetAsync($"/oauth2/login?login_handle={handle}", token);
        Assert.Equal(HttpStatusCode.OK, form.StatusCode);
        var html = await form.Content.ReadAsStringAsync(token);
        var antiforgery = Regex.Match(html, "name=\"__RequestVerificationToken\" value=\"([^\"]*)\"").Groups[1].Value;
        Assert.NotEmpty(antiforgery);
        var cookie = GetSetCookieHeader(form, CookieName);
        Assert.NotNull(cookie);
        var login = new LoginSession(handle, CookieValueFromHeader(cookie!, CookieName), antiforgery);
        using var completion = await browser.SendAsync(CreateLoginPost(
            fields: LoginFields(login, username, password), cookieHeader: CookieHeaderFor(login)), token);
        Assert.Equal(HttpStatusCode.Found, completion.StatusCode);
        var callback = QueryHelpers.ParseQuery(completion.Headers.Location!.Query);
        var code = callback["code"].ToString();
        Assert.NotEmpty(code);
        Assert.Equal("state-0123456789012345", callback["state"].ToString());
        Assert.NotEmpty(callback["iss"].ToString());

        using var exchangeRequest = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = appId,
                ["code"] = code,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = Verifier
            })
        };
        exchangeRequest.Headers.TryAddWithoutValidation("Origin", "https://public.example.test");
        using var exchange = await browser.SendAsync(exchangeRequest, token);
        Assert.Equal(HttpStatusCode.OK, exchange.StatusCode);
        Assert.Equal("https://public.example.test", exchange.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.Contains("Origin", exchange.Headers.Vary);
        Assert.False(exchange.Headers.Contains("Access-Control-Allow-Credentials"));
        Assert.Contains("no-store", exchange.Headers.CacheControl!.ToString());
        var issued = await exchange.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        Assert.Equal("openid", issued.GetProperty("scope").GetString());
        Assert.Equal(300, issued.GetProperty("expires_in").GetInt64());
        var accessToken = new JwtSecurityTokenHandler().ReadJwtToken(issued.GetProperty("access_token").GetString());
        Assert.Equal(300, accessToken.ValidTo.Subtract(accessToken.ValidFrom).TotalSeconds);
        Assert.Equal(appId, Assert.Single(accessToken.Audiences));
        Assert.False(issued.TryGetProperty("refresh_token", out _));
        using var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo");
        userInfoRequest.Headers.TryAddWithoutValidation("Origin", "https://public.example.test");
        userInfoRequest.Headers.TryAddWithoutValidation("Authorization", "Bearer " + issued.GetProperty("access_token").GetString());
        using var userInfo = await browser.SendAsync(userInfoRequest, token);
        Assert.Equal(HttpStatusCode.OK, userInfo.StatusCode);
        Assert.Equal("https://public.example.test", userInfo.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.Contains("no-store", userInfo.Headers.CacheControl!.ToString());
        using var crossAppRequest = new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo");
        crossAppRequest.Headers.TryAddWithoutValidation("Origin", "https://other.example.test");
        crossAppRequest.Headers.TryAddWithoutValidation("Authorization", "Bearer " + issued.GetProperty("access_token").GetString());
        using var crossApp = await browser.SendAsync(crossAppRequest, token);
        Assert.Equal(HttpStatusCode.OK, crossApp.StatusCode);
        Assert.False(crossApp.Headers.Contains("Access-Control-Allow-Origin"));
        using var malformedOriginRequest = new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo");
        malformedOriginRequest.Headers.TryAddWithoutValidation("Origin", new[] { "https://public.example.test", "https://other.example.test" });
        malformedOriginRequest.Headers.TryAddWithoutValidation("Authorization", "Bearer " + issued.GetProperty("access_token").GetString());
        using var malformedOrigin = await browser.SendAsync(malformedOriginRequest, token);
        Assert.False(malformedOrigin.Headers.Contains("Access-Control-Allow-Origin"));
        using var invalidBearer = new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo");
        invalidBearer.Headers.TryAddWithoutValidation("Origin", "https://public.example.test");
        invalidBearer.Headers.TryAddWithoutValidation("Authorization", "Bearer invalid");
        using var invalidToken = await browser.SendAsync(invalidBearer, token);
        Assert.Equal(HttpStatusCode.Unauthorized, invalidToken.StatusCode);
        Assert.False(invalidToken.Headers.Contains("Access-Control-Allow-Origin"));
        var identityCookie = GetSetCookieHeader(completion, IdentitySessionDefaults.CookieName);
        Assert.NotNull(identityCookie);
        using var defaultOfflineRequest = new HttpRequestMessage(HttpMethod.Get,
            authorizeUrl.Replace("scope=openid", "scope=openid%20offline_access", StringComparison.Ordinal));
        defaultOfflineRequest.Headers.TryAddWithoutValidation("Cookie", identityCookie!.Split(';')[0]);
        using var defaultOfflineDenied = await browser.SendAsync(defaultOfflineRequest, token);
        Assert.Equal(HttpStatusCode.Found, defaultOfflineDenied.StatusCode);
        Assert.Equal("invalid_scope", QueryHelpers.ParseQuery(defaultOfflineDenied.Headers.Location!.Query)
            ["error"].ToString());

        using var refreshPolicyUpdate = await admin.PutAsJsonAsync(route + "/oidc-policy",
            Policy(true, true, 3600), token);
        Assert.Equal(HttpStatusCode.OK, refreshPolicyUpdate.StatusCode);
        using var policyReadback = await admin.GetAsync(route + "/oidc", token);
        var stagedPolicy = await policyReadback.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        Assert.True(stagedPolicy.GetProperty("allowRefreshToken").GetBoolean());
        Assert.Equal(3600, stagedPolicy.GetProperty("identitySessionMaxAgeSeconds").GetInt32());

        using var offlineRequest = new HttpRequestMessage(HttpMethod.Get,
            authorizeUrl.Replace("scope=openid", "scope=openid%20offline_access", StringComparison.Ordinal));
        offlineRequest.Headers.TryAddWithoutValidation("Cookie", identityCookie!.Split(';')[0]);
        using var offlineCallback = await browser.SendAsync(offlineRequest, token);
        Assert.Equal(HttpStatusCode.Found, offlineCallback.StatusCode);
        var offlineCode = QueryHelpers.ParseQuery(offlineCallback.Headers.Location!.Query)["code"].ToString();
        Assert.NotEmpty(offlineCode);
        using var wrongVerifier = await browser.PostAsync("/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code", ["client_id"] = appId,
                ["code"] = offlineCode, ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = new string('w', 43)
            }), token);
        Assert.Equal(HttpStatusCode.BadRequest, wrongVerifier.StatusCode);
        Assert.Equal("invalid_grant", (await wrongVerifier.Content
            .ReadFromJsonAsync<JsonElement>(cancellationToken: token)).GetProperty("error").GetString());
        using var wrongTokenRedirect = await browser.PostAsync("/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code", ["client_id"] = appId,
                ["code"] = offlineCode, ["redirect_uri"] = RedirectUri + "/",
                ["code_verifier"] = Verifier
            }), token);
        Assert.Equal(HttpStatusCode.BadRequest, wrongTokenRedirect.StatusCode);
        Assert.Equal("invalid_grant", (await wrongTokenRedirect.Content
            .ReadFromJsonAsync<JsonElement>(cancellationToken: token)).GetProperty("error").GetString());
        using var wrongClient = await browser.PostAsync("/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code", ["client_id"] = otherAppId,
                ["code"] = offlineCode, ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = Verifier
            }), token);
        Assert.NotEqual(HttpStatusCode.OK, wrongClient.StatusCode);
        using (var stateScope = fixture.Services.CreateScope())
        {
            var state = stateScope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            Assert.Empty(await state.RefreshTokens.AsNoTracking()
                .Where(row => row.AppId == appId).ToListAsync(token));
        }
        using var offlineExchange = await browser.PostAsync("/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code", ["client_id"] = appId,
                ["code"] = offlineCode, ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = Verifier
            }), token);
        Assert.Equal(HttpStatusCode.OK, offlineExchange.StatusCode);
        var offlineIssued = await offlineExchange.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        Assert.Equal("openid offline_access", offlineIssued.GetProperty("scope").GetString());
        Assert.Equal(300, offlineIssued.GetProperty("expires_in").GetInt64());
        Assert.Equal(appId, Assert.Single(new JwtSecurityTokenHandler()
            .ReadJwtToken(offlineIssued.GetProperty("access_token").GetString()).Audiences));
        Assert.False(string.IsNullOrEmpty(offlineIssued.GetProperty("id_token").GetString()));
        var rootToken = offlineIssued.GetProperty("refresh_token").GetString()!;
        Assert.False(string.IsNullOrEmpty(rootToken));

        using (var stateScope = fixture.Services.CreateScope())
        {
            var state = stateScope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var roots = await state.RefreshTokens.AsNoTracking()
                .Where(row => row.AppId == appId && row.ParentId == null)
                .ToListAsync(token);
            var root = Assert.Single(roots);
            Assert.StartsWith("sha256-public:", root.TokenValue, StringComparison.Ordinal);
            Assert.NotEqual(rootToken, root.TokenValue);
            Assert.Equal("openid offline_access", root.Scope);
            Assert.Equal(root.Id, Assert.Single(await state.AuthorizationCodes.AsNoTracking()
                .Where(row => row.RefreshFamilyId == root.Id).ToListAsync(token)).RefreshFamilyId);
            var identitySession = await state.IdentitySessions.AsNoTracking()
                .SingleAsync(row => row.Id == root.IdentitySessionId, token);
            Assert.Equal(new[]
            {
                root.CreatedAt.AddDays(7), identitySession.AbsoluteExpiresAt,
                root.AuthTime!.Value.AddSeconds(3600)
            }.Min(), root.ExpiresAt);
        }

        using var rotationRequest = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token", ["client_id"] = appId,
                ["refresh_token"] = rootToken
            })
        };
        rotationRequest.Headers.TryAddWithoutValidation("Origin", "https://public.example.test");
        using var rotation = await browser.SendAsync(rotationRequest, token);
        Assert.Equal(HttpStatusCode.OK, rotation.StatusCode);
        AssertReadableBy(rotation, "https://public.example.test");
        var rotated = await rotation.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        Assert.Equal(300, rotated.GetProperty("expires_in").GetInt64());
        var childToken = rotated.GetProperty("refresh_token").GetString()!;
        Assert.NotEqual(rootToken, childToken);
        using (var stateScope = fixture.Services.CreateScope())
        {
            var state = stateScope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var family = await state.RefreshTokens.AsNoTracking()
                .Where(row => row.AppId == appId && row.Scope == "openid offline_access")
                .ToListAsync(token);
            Assert.Equal(2, family.Count);
            var root = Assert.Single(family, row => row.ParentId == null);
            var child = Assert.Single(family, row => row.ParentId == root.Id);
            Assert.Equal(root.ExpiresAt, child.ExpiresAt);
            Assert.StartsWith("sha256-public:", child.TokenValue, StringComparison.Ordinal);
        }
        using var reuse = await browser.SendAsync(
            RefreshRequest(appId, rootToken, "https://public.example.test"), token);
        Assert.Equal(HttpStatusCode.BadRequest, reuse.StatusCode);
        AssertReadableBy(reuse, "https://public.example.test");
        var reuseResult = await reuse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        Assert.Equal("invalid_grant", reuseResult.GetProperty("error").GetString());
        using var childAfterReuse = await browser.PostAsync("/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token", ["client_id"] = appId,
                ["refresh_token"] = childToken
            }), token);
        Assert.Equal(HttpStatusCode.BadRequest, childAfterReuse.StatusCode);

        using var stagedCodeRequest = new HttpRequestMessage(HttpMethod.Get, authorizeUrl);
        stagedCodeRequest.Headers.TryAddWithoutValidation("Cookie", identityCookie.Split(';')[0]);
        using var stagedCodeCallback = await browser.SendAsync(stagedCodeRequest, token);
        Assert.Equal(HttpStatusCode.Found, stagedCodeCallback.StatusCode);
        var stagedCode = QueryHelpers.ParseQuery(stagedCodeCallback.Headers.Location!.Query)["code"].ToString();
        Assert.NotEmpty(stagedCode);
        using var stagedExchange = await browser.PostAsync("/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code", ["client_id"] = appId,
                ["code"] = stagedCode, ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = Verifier
            }), token);
        Assert.Equal(HttpStatusCode.OK, stagedExchange.StatusCode);
        var stagedIssued = await stagedExchange.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        Assert.False(stagedIssued.TryGetProperty("refresh_token", out _));

        using var pendingOfflineRequest = new HttpRequestMessage(HttpMethod.Get,
            authorizeUrl.Replace("scope=openid", "scope=openid%20offline_access", StringComparison.Ordinal));
        pendingOfflineRequest.Headers.TryAddWithoutValidation("Cookie", identityCookie.Split(';')[0]);
        using var pendingOfflineCallback = await browser.SendAsync(pendingOfflineRequest, token);
        Assert.Equal(HttpStatusCode.Found, pendingOfflineCallback.StatusCode);
        var pendingOfflineCode = QueryHelpers.ParseQuery(pendingOfflineCallback.Headers.Location!.Query)
            ["code"].ToString();
        Assert.NotEmpty(pendingOfflineCode);
        using var refreshDisabled = await admin.PutAsJsonAsync(route + "/oidc-policy",
            Policy(true, false), token);
        Assert.Equal(HttpStatusCode.OK, refreshDisabled.StatusCode);
        using var blockedOfflineExchange = await browser.PostAsync("/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code", ["client_id"] = appId,
                ["code"] = pendingOfflineCode, ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = Verifier
            }), token);
        Assert.Equal(HttpStatusCode.BadRequest, blockedOfflineExchange.StatusCode);
        Assert.Equal("invalid_grant", (await blockedOfflineExchange.Content
            .ReadFromJsonAsync<JsonElement>(cancellationToken: token)).GetProperty("error").GetString());
        using (var stateScope = fixture.Services.CreateScope())
        {
            var state = stateScope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            Assert.Single(await state.RefreshTokens.AsNoTracking()
                .Where(row => row.AppId == appId && row.ParentId == null).ToListAsync(token));
        }

        using var clearedOrigins = await admin.PutAsJsonAsync(route + "/oidc/allowed-origins",
            new { origins = Array.Empty<string>() }, token);
        Assert.Equal(HttpStatusCode.OK, clearedOrigins.StatusCode);
        using var afterClear = new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo");
        afterClear.Headers.TryAddWithoutValidation("Origin", "https://public.example.test");
        afterClear.Headers.TryAddWithoutValidation("Authorization", "Bearer " + issued.GetProperty("access_token").GetString());
        using var noLongerAllowed = await browser.SendAsync(afterClear, token);
        Assert.Equal(HttpStatusCode.OK, noLongerAllowed.StatusCode);
        Assert.False(noLongerAllowed.Headers.Contains("Access-Control-Allow-Origin"));

        using var reuseRequest = new HttpRequestMessage(HttpMethod.Get, authorizeUrl);
        reuseRequest.Headers.TryAddWithoutValidation("Cookie", identityCookie!.Split(';')[0]);
        using var reused = await browser.SendAsync(reuseRequest, token);
        Assert.Equal(HttpStatusCode.Found, reused.StatusCode);
        var outstandingCode = QueryHelpers.ParseQuery(reused.Headers.Location!.Query)["code"].ToString();
        Assert.NotEmpty(outstandingCode);

        using var disabled = await admin.PutAsJsonAsync(route + "/oidc-policy",
            Policy(false, false), token);
        Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);
        using var denied = await browser.GetAsync(authorizeUrl, token);
        Assert.Equal(HttpStatusCode.BadRequest, denied.StatusCode);
        Assert.Null(denied.Headers.Location);
        using var blockedExchange = await browser.PostAsync("/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code", ["client_id"] = appId,
                ["code"] = outstandingCode, ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = Verifier
            }), token);
        Assert.Equal(HttpStatusCode.BadRequest, blockedExchange.StatusCode);
        var blocked = await blockedExchange.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        Assert.Equal("unauthorized_client", blocked.GetProperty("error").GetString());
        using var scope = fixture.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var row = await db.AppRegistrations.AsNoTracking()
            .SingleAsync(app => app.AppId == appId, token);
        Assert.Equal(string.Empty, row.AppSecretHash);
    }

    [Fact]
    public async Task PublicRefresh_IsReadableOnlyByTheValidatedApplicationsRegisteredOrigin()
    {
        const string origin = "https://refresh.example.test";
        const string otherOrigin = "https://refresh-other.example.test";
        var token = TestContext.Current.CancellationToken;
        using var admin = await fixture.CreateAdminHttpClientAsync();
        var appId = await CreatePublicAppAsync(admin, origin, token);
        var route = $"/api/admin/apps/{appId}";
        _ = await CreatePublicAppAsync(admin, otherOrigin, token);
        using (var refreshPolicy = await admin.PutAsJsonAsync(route + "/oidc-policy", Policy(true, true, 3600), token))
        {
            Assert.Equal(HttpStatusCode.OK, refreshPolicy.StatusCode);
        }

        using var browser = fixture.CreateNonRedirectingHttpClient(handleCookies: false);
        var identityCookie = await SignInAsync(browser, appId, token);

        // The preflight admits any active Public Origin and binds no application.
        using (var preflight = new HttpRequestMessage(HttpMethod.Options, "/oauth2/token"))
        {
            preflight.Headers.TryAddWithoutValidation("Origin", otherOrigin);
            preflight.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "POST");
            preflight.Headers.TryAddWithoutValidation("Access-Control-Request-Headers", "content-type");
            using var permitted = await browser.SendAsync(preflight, token);
            Assert.Equal(otherOrigin, permitted.Headers.GetValues("Access-Control-Allow-Origin").Single());
            Assert.Equal("POST", permitted.Headers.GetValues("Access-Control-Allow-Methods").Single());
            Assert.Equal("Content-Type", permitted.Headers.GetValues("Access-Control-Allow-Headers").Single());
        }

        // Success: the exact registered Origin reads a body identical in shape to the Origin-less rotation.
        var current = await RedeemOfflineRootAsync(browser, appId, identityCookie, token);
        using var baseline = await browser.SendAsync(RefreshRequest(appId, current, null), token);
        Assert.Equal(HttpStatusCode.OK, baseline.StatusCode);
        Assert.False(baseline.Headers.Contains("Access-Control-Allow-Origin"));
        var baselineBody = await baseline.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        current = baselineBody.GetProperty("refresh_token").GetString()!;
        using var readable = await browser.SendAsync(RefreshRequest(appId, current, origin), token);
        Assert.Equal(HttpStatusCode.OK, readable.StatusCode);
        AssertReadableBy(readable, origin);
        var readableBody = await readable.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        Assert.Equal(
            baselineBody.EnumerateObject().Select(property => property.Name).Order(),
            readableBody.EnumerateObject().Select(property => property.Name).Order());
        Assert.Equal(300, readableBody.GetProperty("expires_in").GetInt64());
        Assert.Equal("openid offline_access", readableBody.GetProperty("scope").GetString());
        Assert.False(string.IsNullOrEmpty(readableBody.GetProperty("access_token").GetString()));
        Assert.False(string.IsNullOrEmpty(readableBody.GetProperty("id_token").GetString()));
        current = readableBody.GetProperty("refresh_token").GetString()!;

        // Rotations that succeed without read permission: the protocol result is unchanged.
        foreach (var denied in new[]
                 {
                     otherOrigin, "https://unregistered.example.test", "HTTPS://refresh.example.test",
                     "https://Refresh.example.test", origin + "/", null
                 })
        {
            using var response = await browser.SendAsync(RefreshRequest(appId, current, denied), token);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            AssertNotReadable(response);
            current = (await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token))
                .GetProperty("refresh_token").GetString()!;
        }

        using (var duplicate = RefreshRequest(appId, current, null))
        {
            duplicate.Headers.TryAddWithoutValidation("Origin", new[] { origin, origin });
            using var response = await browser.SendAsync(duplicate, token);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            AssertNotReadable(response);
            current = (await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token))
                .GetProperty("refresh_token").GetString()!;
        }

        // Failures before client authentication selects the application never carry read permission.
        using (var unknownClient = await browser.SendAsync(
                   RefreshRequest("unknown-public-client", current, origin), token))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, unknownClient.StatusCode);
            Assert.Equal("invalid_client", await ErrorCodeAsync(unknownClient, token));
            AssertNotReadable(unknownClient);
        }

        foreach (var malformed in new[]
                 {
                     new KeyValuePair<string, string>[]
                     {
                         new("grant_type", "refresh_token"), new("client_id", appId),
                         new("refresh_token", current), new("scope", "openid")
                     },
                     new KeyValuePair<string, string>[]
                     {
                         new("grant_type", "refresh_token"), new("client_id", appId),
                         new("refresh_token", current), new("refresh_token", current)
                     },
                     new KeyValuePair<string, string>[]
                     {
                         new("grant_type", "refresh_token"), new("grant_type", "refresh_token"),
                         new("client_id", appId), new("refresh_token", current)
                     }
                 })
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
            {
                Content = new FormUrlEncodedContent(malformed)
            };
            request.Headers.TryAddWithoutValidation("Origin", origin);
            using var response = await browser.SendAsync(request, token);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("invalid_request", await ErrorCodeAsync(response, token));
            AssertNotReadable(response);
        }

        // The rejected requests consumed nothing: the current member still rotates.
        using (var stillLive = await browser.SendAsync(RefreshRequest(appId, current, origin), token))
        {
            Assert.Equal(HttpStatusCode.OK, stillLive.StatusCode);
            AssertReadableBy(stillLive, origin);
        }

        // A Confidential client's refresh stays unreadable even with a Public application's Origin.
        using (var password = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
               {
                   Content = new FormUrlEncodedContent(new Dictionary<string, string>
                   {
                       ["grant_type"] = "password",
                       ["username"] = IdentityServerFixture.AdminUsername,
                       ["password"] = IdentityServerFixture.AdminPassword,
                       ["client_id"] = IdentityServerFixture.GatewayAppId,
                       ["client_secret"] = IdentityServerFixture.GatewayAppSecret
                   })
               })
        {
            using var issued = await browser.SendAsync(password, token);
            Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
            var legacyRefresh = (await issued.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token))
                .GetProperty("refresh_token").GetString()!;
            using var confidential = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "refresh_token",
                    ["client_id"] = IdentityServerFixture.GatewayAppId,
                    ["client_secret"] = IdentityServerFixture.GatewayAppSecret,
                    ["refresh_token"] = legacyRefresh
                })
            };
            confidential.Headers.TryAddWithoutValidation("Origin", origin);
            using var response = await browser.SendAsync(confidential, token);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            AssertNotReadable(response);
        }

        // Protocol errors after client authentication are readable: reuse revokes the descendants.
        var reusedRoot = await RedeemOfflineRootAsync(browser, appId, identityCookie, token);
        using var reusedRotation = await browser.SendAsync(RefreshRequest(appId, reusedRoot, origin), token);
        Assert.Equal(HttpStatusCode.OK, reusedRotation.StatusCode);
        var reusedChild = (await reusedRotation.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token))
            .GetProperty("refresh_token").GetString()!;
        using (var reuse = await browser.SendAsync(RefreshRequest(appId, reusedRoot, origin), token))
        {
            Assert.Equal(HttpStatusCode.BadRequest, reuse.StatusCode);
            Assert.Equal("invalid_grant", await ErrorCodeAsync(reuse, token));
            AssertReadableBy(reuse, origin);
        }

        using (var revokedChild = await browser.SendAsync(RefreshRequest(appId, reusedChild, origin), token))
        {
            Assert.Equal(HttpStatusCode.BadRequest, revokedChild.StatusCode);
            Assert.Equal("invalid_grant", await ErrorCodeAsync(revokedChild, token));
            AssertReadableBy(revokedChild, origin);
        }

        var disabledRoot = await RedeemOfflineRootAsync(browser, appId, identityCookie, token);
        using (var refreshDisabled = await admin.PutAsJsonAsync(route + "/oidc-policy", Policy(true, false), token))
        {
            Assert.Equal(HttpStatusCode.OK, refreshDisabled.StatusCode);
        }

        using (var disabled = await browser.SendAsync(RefreshRequest(appId, disabledRoot, origin), token))
        {
            Assert.Equal(HttpStatusCode.BadRequest, disabled.StatusCode);
            Assert.Equal("invalid_grant", await ErrorCodeAsync(disabled, token));
            AssertReadableBy(disabled, origin);
        }

        using (var refreshEnabled = await admin.PutAsJsonAsync(route + "/oidc-policy", Policy(true, true, 3600), token))
        {
            Assert.Equal(HttpStatusCode.OK, refreshEnabled.StatusCode);
        }

        // Clearing the Origin registration removes read permission without changing the rotation.
        var clearedRoot = await RedeemOfflineRootAsync(browser, appId, identityCookie, token);
        using (var cleared = await admin.PutAsJsonAsync(route + "/oidc/allowed-origins",
                   new { origins = Array.Empty<string>() }, token))
        {
            Assert.Equal(HttpStatusCode.OK, cleared.StatusCode);
        }

        using (var afterClear = await browser.SendAsync(RefreshRequest(appId, clearedRoot, origin), token))
        {
            Assert.Equal(HttpStatusCode.OK, afterClear.StatusCode);
            AssertNotReadable(afterClear);
            clearedRoot = (await afterClear.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token))
                .GetProperty("refresh_token").GetString()!;
        }

        // A deactivated application keeps its Origin row but fails client authentication unreadably.
        using (var restored = await admin.PutAsJsonAsync(route + "/oidc/allowed-origins",
                   new { origins = new[] { origin } }, token))
        {
            Assert.Equal(HttpStatusCode.OK, restored.StatusCode);
        }

        using (var deactivated = await admin.PutAsJsonAsync(route + "/callback",
                   new { callbackUrl = (string?)null, ttlSeconds = 0, isActive = false }, token))
        {
            Assert.Equal(HttpStatusCode.OK, deactivated.StatusCode);
        }

        using var inactive = await browser.SendAsync(RefreshRequest(appId, clearedRoot, origin), token);
        Assert.Equal(HttpStatusCode.Unauthorized, inactive.StatusCode);
        Assert.Equal("invalid_client", await ErrorCodeAsync(inactive, token));
        AssertNotReadable(inactive);
    }

    private static void AssertReadableBy(HttpResponseMessage response, string origin)
    {
        Assert.Equal(origin, Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
        Assert.Contains("Origin", response.Headers.Vary);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"));
        Assert.False(response.Headers.Contains("Access-Control-Max-Age"));
        Assert.Contains("no-store", response.Headers.CacheControl!.ToString());
    }

    private static void AssertNotReadable(HttpResponseMessage response)
    {
        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
        Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"));
        Assert.Contains("Origin", response.Headers.Vary);
        Assert.Contains("no-store", response.Headers.CacheControl!.ToString());
    }

    private static async Task<string?> ErrorCodeAsync(HttpResponseMessage response, CancellationToken token) =>
        (await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token))
        .GetProperty("error").GetString();

    private static HttpRequestMessage RefreshRequest(string clientId, string refreshToken, string? origin)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token", ["client_id"] = clientId, ["refresh_token"] = refreshToken
            })
        };
        if (origin is not null)
        {
            request.Headers.TryAddWithoutValidation("Origin", origin);
        }

        return request;
    }

    private static async Task<string> CreatePublicAppAsync(HttpClient admin, string origin, CancellationToken token)
    {
        using var create = await admin.PostAsJsonAsync("/api/admin/apps",
            new { appName = $"Public Refresh {Guid.NewGuid():N}", ttlSeconds = 0, clientType = "Public" }, token);
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        var appId = (await create.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token))
            .GetProperty("appId").GetString()!;
        var route = $"/api/admin/apps/{appId}";
        using var audience = await admin.PutAsJsonAsync(route + "/audience-mode", new { mode = "PerApplication" }, token);
        Assert.Equal(HttpStatusCode.OK, audience.StatusCode);
        using var redirect = await admin.PostAsJsonAsync(route + "/oidc/redirect-uris",
            new { kind = "Redirect", uris = new[] { RedirectUri } }, token);
        Assert.Equal(HttpStatusCode.OK, redirect.StatusCode);
        using var origins = await admin.PutAsJsonAsync(route + "/oidc/allowed-origins",
            new { origins = new[] { origin } }, token);
        Assert.Equal(HttpStatusCode.OK, origins.StatusCode);
        using var policy = await admin.PutAsJsonAsync(route + "/oidc-policy", Policy(true, false), token);
        Assert.Equal(HttpStatusCode.OK, policy.StatusCode);
        return appId;
    }

    private async Task<string> SignInAsync(HttpClient browser, string appId, CancellationToken token)
    {
        var username = $"public_refresh_{Guid.NewGuid():N}";
        const string password = "Public-Refresh-Test-123!";
        await SeedUserAsync(fixture.Services, username, password);
        using var authorize = await browser.GetAsync(BuildAuthorizeUrl(appId), token);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var handle = QueryHelpers.ParseQuery(new Uri(new Uri("https://local.test"), authorize.Headers.Location).Query)
            ["login_handle"].ToString();
        using var form = await browser.GetAsync($"/oauth2/login?login_handle={handle}", token);
        Assert.Equal(HttpStatusCode.OK, form.StatusCode);
        var html = await form.Content.ReadAsStringAsync(token);
        var antiforgery = Regex.Match(html, "name=\"__RequestVerificationToken\" value=\"([^\"]*)\"").Groups[1].Value;
        var cookie = GetSetCookieHeader(form, CookieName);
        Assert.NotNull(cookie);
        var login = new LoginSession(handle, CookieValueFromHeader(cookie!, CookieName), antiforgery);
        using var completion = await browser.SendAsync(CreateLoginPost(
            fields: LoginFields(login, username, password), cookieHeader: CookieHeaderFor(login)), token);
        Assert.Equal(HttpStatusCode.Found, completion.StatusCode);
        var identityCookie = GetSetCookieHeader(completion, IdentitySessionDefaults.CookieName);
        Assert.NotNull(identityCookie);
        return identityCookie!.Split(';')[0];
    }

    private static async Task<string> RedeemOfflineRootAsync(
        HttpClient browser, string appId, string identityCookie, CancellationToken token)
    {
        using var authorize = new HttpRequestMessage(HttpMethod.Get,
            BuildAuthorizeUrl(appId).Replace("scope=openid", "scope=openid%20offline_access", StringComparison.Ordinal));
        authorize.Headers.TryAddWithoutValidation("Cookie", identityCookie);
        using var callback = await browser.SendAsync(authorize, token);
        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);
        var code = QueryHelpers.ParseQuery(callback.Headers.Location!.Query)["code"].ToString();
        Assert.NotEmpty(code);
        using var exchange = await browser.PostAsync("/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code", ["client_id"] = appId,
                ["code"] = code, ["redirect_uri"] = RedirectUri, ["code_verifier"] = Verifier
            }), token);
        Assert.Equal(HttpStatusCode.OK, exchange.StatusCode);
        return (await exchange.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token))
            .GetProperty("refresh_token").GetString()!;
    }

    private static object Policy(bool code, bool refresh, int? maxAgeSeconds = null) => new
    {
        clientType = "Public", allowAuthorizationCode = code,
        allowedScopes = refresh ? new[] { "openid", "offline_access" } : new[] { "openid" },
        allowRefreshToken = refresh,
        identitySessionMaxAgeSeconds = maxAgeSeconds
    };

    private static string BuildAuthorizeUrl(string appId) => "/oauth2/authorize?" + string.Join('&',
        new[]
        {
            ("response_type", "code"), ("client_id", appId), ("redirect_uri", RedirectUri),
            ("scope", "openid"), ("state", "state-0123456789012345"),
            ("nonce", "nonce-0123456789012345"), ("code_challenge", Challenge),
            ("code_challenge_method", "S256")
        }.Select(pair => $"{pair.Item1}={Uri.EscapeDataString(pair.Item2)}"));
}
