using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Security;
using SignaCore.Host.Startup;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

public sealed partial class OidcMultiInstanceAcceptanceTests
{
    public static TheoryData<string, bool> StateChanges => new(
        from change in new[] { "idle", "absolute", "revoked", "max-age", "account", "application", "logout" }
        from swap in new[] { false, true } select (change, swap));

    [Theory]
    [MemberData(nameof(StateChanges))]
    public async Task StateMatrix_CommittedChangeIsObservedAtEveryEndpoint(string change, bool swap)
    {
        using var first = CreateInstance();
        using var second = CreateInstance();
        var a = swap ? second : first;
        var b = swap ? first : second;
        var seed = await StateSeedAsync(a, b);
        foreach (var host in new[] { a, b })
        {
            using var accepted = await StateUserInfoAsync(host, seed.Access);
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
            var location = await AuthorizeWithIdentityCookieAsync(host, BuildSuccessAuthorizeUrl(), seed.Cookie);
            Assert.True(location.Contains("code=", StringComparison.Ordinal), "Live session was not reusable.");
        }
        if (change is "account" or "application")
        {
            using var admin = NonRedirectingClient(a);
            admin.DefaultRequestHeaders.Add("Cookie", await LoginManagementAsync(a));
            admin.DefaultRequestHeaders.Add("X-ServiceMantle-Request", "1");
            using var changed = change == "account"
                ? await admin.PatchAsJsonAsync($"/api/admin/users/{seed.AccountId}/status", new { isActive = false }, TestContext.Current.CancellationToken)
                : await admin.PutAsJsonAsync($"/api/admin/apps/{SuccessAppId}/callback", new { callbackUrl = (string?)null, ttlSeconds = 0, isActive = false }, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, changed.StatusCode);
        }
        else if (change == "logout")
        {
            var uri = await StatePrepareLogoutAsync(a, seed.Id);
            using var completed = await StateCompleteLogoutAsync(b, uri, seed.Cookie);
            Assert.Equal(HttpStatusCode.Found, completed.StatusCode);
        }
        else
        {
            using var scope = a.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var session = await db.IdentitySessions.SingleAsync(x => x.Id == seed.SessionId, TestContext.Current.CancellationToken);
            if (change == "idle") session.IdleExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1);
            if (change == "absolute") session.AbsoluteExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1);
            if (change == "revoked") { session.RevokedAt = DateTimeOffset.UtcNow; session.RevocationReason = "logout"; }
            if (change == "max-age")
            {
                session.AuthTime = DateTimeOffset.UtcNow.AddMinutes(-10);
                (await db.AppRegistrations.SingleAsync(x => x.AppId == SuccessAppId, TestContext.Current.CancellationToken)).IdentitySessionMaxAgeSeconds = 60;
            }
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }
        foreach (var host in new[] { a, b })
        {
            using var browser = NonRedirectingClient(host);
            using var authorize = await browser.SendAsync(AuthorizeGet(BuildSuccessAuthorizeUrl(), seed.Cookie), TestContext.Current.CancellationToken);
            if (change == "application")
            {
                Assert.Equal(HttpStatusCode.BadRequest, authorize.StatusCode);
                Assert.Null(authorize.Headers.Location);
                using var unknown = await browser.GetAsync(BuildSuccessAuthorizeUrl().Replace(SuccessAppId, "missing-client", StringComparison.Ordinal), TestContext.Current.CancellationToken);
                Assert.Equal(unknown.StatusCode, authorize.StatusCode);
                Assert.True(await unknown.Content.ReadAsStringAsync(TestContext.Current.CancellationToken) == await authorize.Content.ReadAsStringAsync(TestContext.Current.CancellationToken),
                    "Missing and inactive clients produced different local errors.");
            }
            else
            {
                Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
                Assert.True(authorize.Headers.Location?.ToString().StartsWith("/oauth2/login?", StringComparison.Ordinal) == true,
                    "An unavailable identity session bypassed login.");
            }
            foreach (var grant in new[] { "authorization_code", "refresh_token" })
            {
                using var rejected = await StateTokenAsync(host, grant, grant == "authorization_code" ? seed.PendingCode : seed.Refresh);
                var error = change == "application" ? "invalid_client" : "invalid_grant";
                var actual = await StateErrorAsync(rejected, error);
                if (grant == "refresh_token" && error == "invalid_grant")
                {
                    // An unknown refresh digest follows the legacy router (IN-23). Interactive
                    // members instead have this single closed description for every live-state failure.
                    using var document = JsonDocument.Parse(actual);
                    Assert.Equal("The refresh token is invalid.", document.RootElement.GetProperty("error_description").GetString());
                }
                else
                {
                    using var absent = await StateTokenAsync(host, grant, new string('z', 43), change == "application" ? "missing-client" : SuccessAppId);
                    var expected = await StateErrorAsync(absent, error);
                    Assert.True(actual == expected, "Missing and unavailable grant errors differ.");
                }
            }
            using var userinfo = await StateUserInfoAsync(host, seed.Access);
            AssertStateUserInfoRejected(userinfo);
            using var absentInfo = await StateUserInfoAsync(host, "not-a-token");
            Assert.Equal(absentInfo.Headers.WwwAuthenticate.ToString(), userinfo.Headers.WwwAuthenticate.ToString());
        }
        using var verification = a.Services.CreateScope();
        var context = verification.ServiceProvider.GetRequiredService<IdentityDbContext>();
        Assert.Null((await context.AuthorizationCodes.SingleAsync(x => x.CodeDigest == AuthorizationCodeDigest.Compute(seed.PendingCode), TestContext.Current.CancellationToken)).ConsumedAt);
        var finalSession = await context.IdentitySessions.SingleAsync(x => x.Id == seed.SessionId, TestContext.Current.CancellationToken);
        if (change is "idle" or "absolute" or "max-age" or "application") Assert.Null(finalSession.RevokedAt);
        else Assert.NotNull(finalSession.RevokedAt);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StateMatrix_LogoutUsesExactRedirectAndCookieBindingAcrossInstances(bool swap)
    {
        using var first = CreateInstance();
        using var second = CreateInstance();
        var a = swap ? second : first;
        var b = swap ? first : second;
        var seed = await StateSeedAsync(a, b);
        foreach (var redirect in new[] { StatePostLogout + "/", "https://BFF.state.test/signed-out", StatePostLogout + "?extra=1", "https://bff.state.test:443/signed-out", "https://untrusted.test/" })
        {
            using var invalid = await StateLogoutPreparationResponseAsync(a, seed.Id, redirect);
            Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
            Assert.Null(invalid.Headers.Location);
        }
        var uri = await StatePrepareLogoutAsync(a, seed.Id);
        using var injection = await StateCompleteLogoutAsync(b, uri + "&post_logout_redirect_uri=https://untrusted.test", seed.Cookie);
        Assert.Equal(HttpStatusCode.BadRequest, injection.StatusCode);
        Assert.Null(injection.Headers.Location);
        using var rawHint = await StateCompleteLogoutAsync(b, "/oauth2/logout?id_token_hint=" + Uri.EscapeDataString(seed.Id), seed.Cookie);
        Assert.Equal(HttpStatusCode.BadRequest, rawHint.StatusCode);
        using var noCookie = await StateCompleteLogoutAsync(b, uri, null);
        Assert.Equal(HttpStatusCode.Found, noCookie.StatusCode);
        using var live = await StateUserInfoAsync(a, seed.Access);
        Assert.Equal(HttpStatusCode.OK, live.StatusCode);
        using var replay = await StateCompleteLogoutAsync(a, uri, seed.Cookie);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        var otherCookie = await LoginOnInstanceAsync(b);
        var mismatchedUri = await StatePrepareLogoutAsync(a, seed.Id);
        using var mismatched = await StateCompleteLogoutAsync(b, mismatchedUri, otherCookie);
        Assert.Equal(noCookie.StatusCode, mismatched.StatusCode);
        using (var stillLive = await StateUserInfoAsync(a, seed.Access)) Assert.Equal(HttpStatusCode.OK, stillLive.StatusCode);
        // The unrelated browser session also remains usable after presenting another session's handle.
        var otherLocation = await AuthorizeWithIdentityCookieAsync(a, BuildSuccessAuthorizeUrl(), otherCookie);
        Assert.True(otherLocation.Contains("code=", StringComparison.Ordinal));
        var secondUri = await StatePrepareLogoutAsync(b, seed.Id);
        using var completed = await StateCompleteLogoutAsync(a, secondUri, seed.Cookie);
        Assert.Equal(noCookie.StatusCode, completed.StatusCode);
        Assert.True(noCookie.Headers.Location == completed.Headers.Location, "Logout exposed cookie binding through redirect shape.");
        Assert.True(completed.Headers.Location?.ToString().StartsWith(StatePostLogout + "?state=", StringComparison.Ordinal) == true);
        foreach (var host in new[] { a, b })
        {
            using var rejected = await StateUserInfoAsync(host, seed.Access);
            AssertStateUserInfoRejected(rejected);
        }
    }

    [Fact]
    public async Task StateMatrix_DisconnectedStateNegativeControlDetectsAStaleSession()
    {
        using var a = CreateInstance();
        using var b = CreateInstance();
        var seed = await StateSeedAsync(a, b);
        var copyConnection = ConnectionStringOf("disconnected-state.db");
        await using (var source = new SqliteConnection(_connectionString))
        await using (var copy = new SqliteConnection(copyConnection))
        {
            await source.OpenAsync(TestContext.Current.CancellationToken);
            await copy.OpenAsync(TestContext.Current.CancellationToken);
            source.BackupDatabase(copy);
        }
        // Keep the RSA and DP material identical. Only the source of current state diverges.
        var bootstrap = await InstallationTestSupport.PrepareUninstalledBootstrapAsync(Path.Combine(_workingDirectory, "disconnected-state"),
            new DatabaseOptions { Provider = "SQLite", ConnectionString = copyConnection }, RootSecretOf("shared"), TestContext.Current.CancellationToken);
        using var stale = CreateInstance(bootstrap);
        using var before = await StateUserInfoAsync(stale, seed.Access);
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        var uri = await StatePrepareLogoutAsync(a, seed.Id);
        using var completed = await StateCompleteLogoutAsync(b, uri, seed.Cookie);
        Assert.Equal(HttpStatusCode.Found, completed.StatusCode);
        using var rejected = await StateUserInfoAsync(a, seed.Access);
        AssertStateUserInfoRejected(rejected);
        using var incorrectlyAccepted = await StateUserInfoAsync(stale, seed.Access);
        Assert.Equal(HttpStatusCode.OK, incorrectlyAccepted.StatusCode);
        Assert.Throws<Xunit.Sdk.EqualException>(() => AssertStateUserInfoRejected(incorrectlyAccepted));
    }

    private const string StatePostLogout = "https://bff.state.test/signed-out";
    private sealed record StateSeed(string Cookie, string Id, string Access, string Refresh, string PendingCode, Guid SessionId, Guid AccountId);

    private async Task<StateSeed> StateSeedAsync(WebApplicationFactory<Program> a, WebApplicationFactory<Program> b)
    {
        var cookie = await LoginOnInstanceAsync(a);
        using (var scope = a.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var app = await db.AppRegistrations.SingleAsync(x => x.AppId == SuccessAppId, TestContext.Current.CancellationToken);
            app.AllowRefreshToken = true; app.AllowedScopes = "openid profile offline_access";
            db.AppRedirectUris.Add(new AppRedirectUriEntity { Id = Guid.NewGuid(), AppRegistrationId = app.Id,
                Kind = RedirectUriKind.PostLogout, CanonicalUri = StatePostLogout });
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }
        var url = BuildSuccessAuthorizeUrl().Replace("scope=openid%20profile", "scope=openid%20profile%20offline_access", StringComparison.Ordinal);
        var code = ExtractQueryValue(await AuthorizeWithIdentityCookieAsync(b, url, cookie), "code");
        using var response = await StateTokenAsync(a, "authorization_code", code);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        var access = body.GetProperty("access_token").GetString()!;
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(access);
        var pending = ExtractQueryValue(await AuthorizeWithIdentityCookieAsync(b, BuildSuccessAuthorizeUrl(), cookie), "code");
        return new StateSeed(cookie, body.GetProperty("id_token").GetString()!, access, body.GetProperty("refresh_token").GetString()!, pending,
            Guid.Parse(jwt.Claims.Single(x => x.Type == "sid").Value), Guid.Parse(jwt.Subject));
    }

    private static async Task<HttpResponseMessage> StateTokenAsync(WebApplicationFactory<Program> host, string grant, string value, string clientId = SuccessAppId)
    {
        using var http = NonRedirectingClient(host);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(clientId + ":" + ClientSecret)));
        var fields = new Dictionary<string, string> { ["grant_type"] = grant, [grant == "authorization_code" ? "code" : "refresh_token"] = value };
        if (grant == "authorization_code") { fields["redirect_uri"] = SuccessRegisteredUri; fields["code_verifier"] = CodeVerifier; }
        return await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(fields), TestContext.Current.CancellationToken);
    }

    private static async Task<string> StateErrorAsync(HttpResponseMessage response, string error)
    {
        Assert.Equal(error == "invalid_client" ? HttpStatusCode.Unauthorized : HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        Assert.Equal(error, body.GetProperty("error").GetString());
        foreach (var field in new[] { "access_token", "id_token", "refresh_token" }) Assert.False(body.TryGetProperty(field, out _));
        return body.GetRawText();
    }

    private static async Task<HttpResponseMessage> StateUserInfoAsync(WebApplicationFactory<Program> host, string token)
    {
        using var http = NonRedirectingClient(host);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await http.GetAsync("/oauth2/userinfo", TestContext.Current.CancellationToken);
    }

    private static void AssertStateUserInfoRejected(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("error=\"invalid_token\"", response.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);
    }

    private static async Task<HttpResponseMessage> StateLogoutPreparationResponseAsync(WebApplicationFactory<Program> host, string id, string redirect)
    {
        using var http = NonRedirectingClient(host);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(SuccessAppId + ":" + ClientSecret)));
        return await http.PostAsync("/oauth2/logout/requests", new FormUrlEncodedContent(new Dictionary<string, string>
        { ["id_token_hint"] = id, ["post_logout_redirect_uri"] = redirect, ["state"] = "state-matrix-0123456789abcdef" }), TestContext.Current.CancellationToken);
    }

    private static async Task<string> StatePrepareLogoutAsync(WebApplicationFactory<Program> host, string id)
    {
        using var response = await StateLogoutPreparationResponseAsync(host, id, StatePostLogout);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("logout_uri").GetString()!;
    }

    private static async Task<HttpResponseMessage> StateCompleteLogoutAsync(WebApplicationFactory<Program> host, string uri, string? cookie)
    {
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });
        if (cookie is not null) http.DefaultRequestHeaders.Add("Cookie", IdentitySessionDefaults.CookieName + "=" + cookie);
        return await http.GetAsync(uri, TestContext.Current.CancellationToken);
    }
}
