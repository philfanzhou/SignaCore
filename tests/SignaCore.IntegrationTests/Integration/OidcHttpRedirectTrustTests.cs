using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Integration;

[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class OidcHttpRedirectTrustTests(IdentityServerFixture fixture) : IClassFixture<IdentityServerFixture>
{
    private const string Redirect = "http://10.20.30.40:5008/callback";
    private const string Logout = "http://10.20.30.40:5008/logout";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static OidcRedirectUriPolicy Allowed => OidcRedirectUriPolicy.Default;

    [Fact]
    public async Task Admin_AcceptsPlainHttpRegistrations_AndCanRemoveThem()
    {
        using var allowed = Host(Allowed);
        using var disabled = Host(OidcRedirectUriPolicy.Default);
        var app = await SeedAsync(allowed.Services);
        using var a = allowed.CreateClient(new() { BaseAddress = new("https://localhost") });
        using var b = disabled.CreateClient(new() { BaseAddress = new("https://localhost") });
        // The policy is the same structural rule on every host: plain-http registrations are
        // accepted and removable in any environment, with no per-host allowlist input.
        foreach (var client in new[] { a, b })
        {
            using var login = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
            { Content = System.Net.Http.Json.JsonContent.Create(new { username = IdentityServerFixture.AdminUsername, password = IdentityServerFixture.AdminPassword }) };
            login.Headers.Add("X-ServiceMantle-Request", "1");
            using var response = await client.SendAsync(login, Ct);
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        }
        var route = "/api/admin/apps/" + app.AppId + "/oidc/redirect-uris";
        using var accepted = await a.PostAsync(route, System.Net.Http.Json.JsonContent.Create(new { kind = "Redirect", uris = new[] { Redirect + "/second" } }), Ct);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        // A structurally invalid registration is still rejected without any write.
        using var rejected = await b.PostAsync(route, System.Net.Http.Json.JsonContent.Create(new { kind = "Redirect", uris = new[] { "https://user:pass@10.20.30.40:5008/third" } }), Ct);
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        using var scope = allowed.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var rows = await db.AppRedirectUris.AsNoTracking().Where(x => x.AppRegistrationId == app.Id).ToListAsync(Ct);
        Assert.Equal(3, rows.Count);
        Assert.DoesNotContain(rows, x => x.CanonicalUri.EndsWith("/third", StringComparison.Ordinal));
        var removed = rows.Single(x => x.CanonicalUri == Redirect + "/second");
        using var deletion = await b.DeleteAsync(route + "/" + removed.Id, Ct);
        Assert.Equal(HttpStatusCode.OK, deletion.StatusCode);
        Assert.Equal(2, await db.AppRedirectUris.CountAsync(x => x.AppRegistrationId == app.Id, Ct));
    }

    [Theory]
    [InlineData("cancel")]
    [InlineData("password")]
    [InlineData("sms")]
    public async Task RemovedRegistration_RejectsAuthorizeAndContinuationWithoutConsumption(string action)
    {
        using var permitted = Host(Allowed);
        using var a = Client(permitted);
        var app = await SeedAsync(permitted.Services);
        using var authorize = await a.GetAsync(Authorize(app.AppId), Ct);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        using var page = await a.GetAsync(authorize.Headers.Location, Ct);
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var body = await page.Content.ReadAsStringAsync(Ct);
        var token = System.Text.RegularExpressions.Regex.Match(body, "name=\"__RequestVerificationToken\" value=\"([^\"]+)\"").Groups[1].Value;
        // Use the production token field helper rather than depending on incidental attribute order.
        if (token.Length == 0) token = System.Text.RegularExpressions.Regex.Match(body, "name=\"login_csrf_token\" value=\"([^\"]+)\"").Groups[1].Value;
        Assert.NotEmpty(token);
        var cookie = OAuthLoginTestSupport.GetSetCookieHeader(page, SignaCore.Host.Security.LoginAntiforgeryDefaults.CookieName)!;
        var handle = authorize.Headers.Location!.ToString().Split('=')[1];
        var fields = new Dictionary<string,string>
        {
            ["login_handle"] = handle,
            [SignaCore.Host.Security.LoginAntiforgeryDefaults.TokenFieldName] = token
        };
        if (action == "cancel") fields["action"] = "cancel";
        else if (action == "password") { fields["action"] = "login"; fields["username"] = IdentityServerFixture.AdminUsername; fields["password"] = IdentityServerFixture.AdminPassword; }
        else { fields["action"] = "sms_login"; fields["phone"] = "+8613800000000"; fields["otp"] = "123456"; }
        // The stored registration is removed behind the host: the still-open continuation is
        // refused without consumption, and a fresh authorize is refused locally.
        using (var removalScope = permitted.Services.CreateScope())
        {
            var db = removalScope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            await db.AppRedirectUris.Where(x => x.AppRegistrationId == app.Id).ExecuteDeleteAsync(Ct);
        }
        using var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/login") { Content = new FormUrlEncodedContent(fields) };
        request.Headers.Add("Cookie", cookie.Split(';')[0]);
        using var result = await a.SendAsync(request, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
        Assert.Null(result.Headers.Location);
        using var rejectedAuthorize = await a.GetAsync(Authorize(app.AppId), Ct);
        Assert.Equal(HttpStatusCode.BadRequest, rejectedAuthorize.StatusCode);
        Assert.Null(rejectedAuthorize.Headers.Location);
        using var scope = permitted.Services.CreateScope();
        var continuation = await scope.ServiceProvider.GetRequiredService<IAuthorizationRequestStore>().GetActiveAsync(handle, DateTimeOffset.UtcNow, Ct);
        Assert.NotNull(continuation);
        Assert.Equal(0, await scope.ServiceProvider.GetRequiredService<IdentityDbContext>().AuthorizationCodes.CountAsync(row => row.AppRegistrationId == app.Id, Ct));
    }

    [Theory]
    [InlineData("registration")]
    [InlineData("inactive")]
    public async Task OldCodeAndLogoutRequest_RejectDataDriftWithoutAnyConsumption(string drift)
    {
        using var allowed = Host(Allowed);
        using var changed = Host(Allowed);
        var app = await SeedAsync(allowed.Services);
        string code, handle;
        Guid codeId, logoutId, sessionId;
        using (var scope = allowed.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var credential = await db.PasswordCredentials.SingleAsync(x => x.Username == IdentityServerFixture.AdminUsername, Ct);
            var session = await scope.ServiceProvider.GetRequiredService<IIdentitySessionStore>().CreateAsync(credential.AccountId, credential.Id, DateTimeOffset.UtcNow, Ct);
            var created = await scope.ServiceProvider.GetRequiredService<IAuthorizationCodeStore>().CreateAsync(session, new(app.Id, Redirect, "openid", "nonce-01234567890123456789", Challenge), DateTimeOffset.UtcNow, Ct);
            var prepared = await scope.ServiceProvider.GetRequiredService<ILogoutRequestStore>().CreateAsync(new(app.Id, session.AccountId, session.Id, Logout, null), DateTimeOffset.UtcNow, Ct);
            code = created.Code; codeId = created.Id; handle = prepared.LogoutHandle; logoutId = prepared.Id; sessionId = session.Id;
            if (drift == "registration") await db.AppRedirectUris.Where(x => x.AppRegistrationId == app.Id).ExecuteDeleteAsync(Ct);
            if (drift == "inactive") await db.AppRegistrations.Where(x => x.Id == app.Id).ExecuteUpdateAsync(x => x.SetProperty(a => a.IsActive, false), Ct);
        }
        using var client = Client(changed);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(app.AppId + ":Synthetic123!")));
        using var token = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string,string> { ["code"] = code, ["redirect_uri"] = Redirect, ["code_verifier"] = Verifier, ["grant_type"] = "authorization_code" }), Ct);
        Assert.Equal(drift == "inactive" ? HttpStatusCode.Unauthorized : HttpStatusCode.BadRequest, token.StatusCode);
        using var completion = await client.GetAsync("/oauth2/logout?logout_handle=" + handle, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, completion.StatusCode);
        Assert.Null(completion.Headers.Location);
        using var verify = changed.Services.CreateScope();
        var context = verify.ServiceProvider.GetRequiredService<IdentityDbContext>();
        Assert.Null((await context.AuthorizationCodes.AsNoTracking().SingleAsync(x => x.Id == codeId, Ct)).ConsumedAt);
        Assert.Null((await context.LogoutRequests.AsNoTracking().SingleAsync(x => x.Id == logoutId, Ct)).ConsumedAt);
        Assert.Null((await context.IdentitySessions.AsNoTracking().SingleAsync(x => x.Id == sessionId, Ct)).RevokedAt);
    }

    private WebApplicationFactory<Program> Host(OidcRedirectUriPolicy policy) => fixture.WithTestServices(services => { services.RemoveAll<OidcRedirectUriPolicy>(); services.AddSingleton(policy); });
    private static HttpClient Client(WebApplicationFactory<Program> host) => host.CreateClient(new() { BaseAddress = new("https://localhost"), AllowAutoRedirect = false, HandleCookies = false });
    private static async Task<AppRegistrationEntity> SeedAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var app = new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = "http-trust-" + Guid.NewGuid().ToString("N"), IsActive = true, AppSecretHash = BCrypt.Net.BCrypt.HashPassword("Synthetic123!"), CreatedAt = DateTimeOffset.UtcNow };
        OidcClientConfigurationApplier.Apply(app, new() { AllowAuthorizationCode = true, AllowedScopes = ["openid"], AudienceMode = "PerApplication", RedirectUris = [Redirect], PostLogoutRedirectUris = [Logout] });
        db.AppRegistrations.Add(app);
        await db.SaveChangesAsync(Ct);
        return app;
    }
    private static string Authorize(string client) => "/oauth2/authorize?" + string.Join('&', new Dictionary<string,string> { ["client_id"] = client, ["redirect_uri"] = Redirect, ["response_type"] = "code", ["scope"] = "openid", ["state"] = "state-01234567890123456789", ["nonce"] = "nonce-01234567890123456789", ["code_challenge"] = Challenge, ["code_challenge_method"] = "S256" }.Select(x => x.Key + "=" + Uri.EscapeDataString(x.Value)));
}
