extern alias BffSample;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace SignaCore.ReferenceBff.Tests;

public sealed partial class ReferenceBffDatabaseContractTests
{
    [Fact]
    public async Task Readme_InstalledSignaCoreThenAdminApisLoginAndSetupCompleteInOrder()
    {
        // FirstRunSetup owns bootstrap/install; this fixture uses its real installation composition.
        // No application or end-user row is seeded: the README operations must create both by HTTP.
        await using var identity = new SignaCoreHostFixture { SeedReferenceAccountAndApplication = false };
        await identity.InitializeAsync();
        using var admin = identity.Host.CreateClient(new WebApplicationFactoryClientOptions
            { BaseAddress = new Uri(SignaCoreHostFixture.Authority), AllowAutoRedirect = false });
        using (var anonymous = await admin.PostAsJsonAsync("/api/admin/apps",
                   new { appName = "Reference BFF", callbackUrl = (string?)null, ttlSeconds = 0, clientType = "Confidential" }, TestContext.Current.CancellationToken))
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        using (var request = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
               { Content = JsonContent.Create(new { username = "bff_admin", password = "BffAdmin-123!" }) })
        {
            request.Headers.Add("X-ServiceMantle-Request", "1");
            using var login = await admin.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        }
        using var created = await admin.PostAsJsonAsync("/api/admin/apps",
            new { appName = "Reference BFF", callbackUrl = (string?)null, ttlSeconds = 0, clientType = "Confidential" }, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        using var app = JsonDocument.Parse(await created.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var id = app.RootElement.GetProperty("appId").GetString()!;
        var secret = app.RootElement.GetProperty("appSecret").GetString()!;
        Assert.False(string.IsNullOrEmpty(id));
        Assert.False(string.IsNullOrEmpty(secret));
        var policy = new { clientType = "Confidential", allowAuthorizationCode = true,
            allowedScopes = new[] { "openid", "profile" }, allowRefreshToken = false, identitySessionMaxAgeSeconds = (int?)null };
        using (var premature = await admin.PutAsJsonAsync($"/api/admin/apps/{id}/oidc-policy", policy, TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.BadRequest, premature.StatusCode);
            Assert.Contains("Authorization Code flow requires a per-application audience.",
                await premature.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }
        using (var audience = await admin.PutAsJsonAsync($"/api/admin/apps/{id}/audience-mode",
                   new { mode = "PerApplication" }, TestContext.Current.CancellationToken))
            Assert.Equal(HttpStatusCode.OK, audience.StatusCode);
        using (var premature = await admin.PutAsJsonAsync($"/api/admin/apps/{id}/oidc-policy", policy, TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.BadRequest, premature.StatusCode);
            Assert.Contains("Authorization Code flow requires at least one redirect URI.",
                await premature.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }
        using (var redirect = await admin.PostAsJsonAsync($"/api/admin/apps/{id}/oidc/redirect-uris",
                   new { kind = "Redirect", uris = new[] { SignaCoreHostFixture.RedirectUri } }, TestContext.Current.CancellationToken))
            Assert.Equal(HttpStatusCode.OK, redirect.StatusCode);
        using (var enabled = await admin.PutAsJsonAsync($"/api/admin/apps/{id}/oidc-policy", policy, TestContext.Current.CancellationToken))
            Assert.Equal(HttpStatusCode.OK, enabled.StatusCode);
        using (var listed = await admin.GetAsync("/api/admin/apps", TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
            BffCanaryAssertions.Absent(await listed.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), [secret], "application readback");
        }
        using (var user = await admin.PostAsJsonAsync("/api/admin/users", new
               { username = SignaCoreHostFixture.Username, password = SignaCoreHostFixture.Password,
                   displayName = (string?)null, remark = (string?)null, nickname = (string?)null }, TestContext.Current.CancellationToken))
            Assert.Equal(HttpStatusCode.OK, user.StatusCode);

        await using var database = await BffDatabase.CreateMigratedAsync("SQLite");
        var terminal = new ReferenceBffSetupCodeTests.SilentTerminal();
        Assert.Equal(0, await RunCode(database, "create", terminal));
        await using var context = database.CreateContext();
        using var backchannel = identity.Host.CreateClient();
        await using var host = BffTestServer.Create(SignaCoreHostFixture.Authority, id, secret,
            SignaCoreHostFixture.RedirectUri, backchannel, identity.Host.Server.CreateHandler(),
            databaseProvider: "SQLite", databaseConnectionString: context.Database.GetConnectionString());
        using var browser = BffTestServer.CreateBrowser(identity.Host, host);
        using var challenge = await browser.Bff.GetAsync("/bff/login", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, challenge.StatusCode);
        using var authorize = await browser.SendOnIdentityServerAsync(new HttpRequestMessage(HttpMethod.Get, challenge.Headers.Location), TestContext.Current.CancellationToken);
        using var credentials = await SignaCoreLoginDriver.PostCredentialsAsync(browser, authorize.Headers.Location!.ToString(),
            SignaCoreHostFixture.Username, SignaCoreHostFixture.Password, TestContext.Current.CancellationToken);
        using var callback = await browser.SendOnBffAsync(new HttpRequestMessage(HttpMethod.Get, credentials.Headers.Location), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callback.StatusCode);
        using var form = await browser.Bff.GetAsync("/bff/setup", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, form.StatusCode);
        var csrf = WebUtility.HtmlDecode(Regex.Match(await form.Content.ReadAsStringAsync(TestContext.Current.CancellationToken),
            "id=\"csrf\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value);
        Assert.NotEmpty(csrf);
        using var completed = await SendSetup(browser.Bff, terminal.Code!.Reveal(), csrf);
        Assert.Equal(HttpStatusCode.NoContent, completed.StatusCode);
        using var authorized = await browser.Bff.GetAsync("/bff/admin", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, authorized.StatusCode);
        Assert.Equal("{\"isAdministrator\":true}", await authorized.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
}
