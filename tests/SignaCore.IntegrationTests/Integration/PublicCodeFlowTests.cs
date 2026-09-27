using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
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

        using var exchange = await browser.PostAsync("/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = appId,
                ["code"] = code,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = Verifier
            }), token);
        Assert.Equal(HttpStatusCode.OK, exchange.StatusCode);
        var issued = await exchange.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        Assert.Equal("openid", issued.GetProperty("scope").GetString());
        Assert.False(issued.TryGetProperty("refresh_token", out _));

        var identityCookie = GetSetCookieHeader(completion, IdentitySessionDefaults.CookieName);
        Assert.NotNull(identityCookie);
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

    private static object Policy(bool code, bool refresh) => new
    {
        clientType = "Public", allowAuthorizationCode = code,
        allowedScopes = new[] { "openid" }, allowRefreshToken = refresh,
        identitySessionMaxAgeSeconds = (int?)null
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
