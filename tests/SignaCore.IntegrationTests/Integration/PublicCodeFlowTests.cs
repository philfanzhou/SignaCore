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
        using var refreshPolicyUpdate = await admin.PutAsJsonAsync(route + "/oidc-policy",
            Policy(true, true, 3600), token);
        Assert.Equal(HttpStatusCode.OK, refreshPolicyUpdate.StatusCode);
        using var policyReadback = await admin.GetAsync(route + "/oidc", token);
        var stagedPolicy = await policyReadback.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        Assert.True(stagedPolicy.GetProperty("allowRefreshToken").GetBoolean());
        Assert.Equal(3600, stagedPolicy.GetProperty("identitySessionMaxAgeSeconds").GetInt32());

        var identityCookie = GetSetCookieHeader(completion, IdentitySessionDefaults.CookieName);
        Assert.NotNull(identityCookie);
        using var offlineRequest = new HttpRequestMessage(HttpMethod.Get,
            authorizeUrl.Replace("scope=openid", "scope=openid%20offline_access", StringComparison.Ordinal));
        offlineRequest.Headers.TryAddWithoutValidation("Cookie", identityCookie!.Split(';')[0]);
        using var offlineDenied = await browser.SendAsync(offlineRequest, token);
        Assert.Equal(HttpStatusCode.Found, offlineDenied.StatusCode);
        var offlineError = QueryHelpers.ParseQuery(offlineDenied.Headers.Location!.Query);
        Assert.Equal("invalid_scope", offlineError["error"].ToString());
        Assert.False(offlineError.ContainsKey("code"));

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
