extern alias ConsumerApp;

using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The package's CSRF boundary: the token endpoint issues the antiforgery pair, a
/// session-authenticated unsafe method without a valid token is refused while a safe method and a
/// host-owned Bearer route stay unaffected, and the logout endpoint rejects a missing or wrong
/// token before any session state changes.
/// </summary>
public sealed class ClientCsrfBoundaryTests
{
    private const string ClientId = "client-pack-app";

    private static async Task<(WebApplicationFactory<ConsumerApp.Program> Consumer, CrossServerBrowser Browser)>
        CreateSignedInAsync(FakeIdentityProvider authority)
    {
        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            "client-pack-test-secret",
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler());
        var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));

        // Complete one sign-in so the browser holds a live session cookie.
        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start"));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, startResponse.StatusCode);
        using var authorize = new HttpRequestMessage(
            HttpMethod.Get, startResponse.Headers.Location!);
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(
            authorize, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, authorizeResponse.StatusCode);
        using var callback = new HttpRequestMessage(
            HttpMethod.Get, authorizeResponse.Headers.Location!);
        using var callbackResponse = await browser.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal("/", callbackResponse.Headers.Location!.ToString());
        return (consumer, browser);
    }

    private static async Task<string> FetchCsrfTokenAsync(CrossServerBrowser browser)
    {
        using var csrf = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/csrf"));
        using var response = await browser.SendOnConsumerAsync(
            csrf, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(response.Headers.CacheControl);
        Assert.True(response.Headers.CacheControl.NoStore);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.StartsWith("{\"token\":", body, StringComparison.Ordinal);
        return body["{\"token\":".Length..^1].Trim('"');
    }

    [Fact]
    public async Task TheCsrfEndpoint_IssuesTheTokenWithItsCookie()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateSignedInAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        var token = await FetchCsrfTokenAsync(browser);
        Assert.InRange(token.Length, 20, 512);

        // The antiforgery cookie was set alongside the token for the same browser.
        var cookieHeader = browser.Cookies.GetCookieHeader(new Uri("https://bff.localhost/"));
        Assert.Contains(".AspNetCore.Antiforgery", cookieHeader, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ASessionAuthenticatedUnsafeMethod_WithoutAToken_IsRefused()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateSignedInAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        using var write = new HttpRequestMessage(
            HttpMethod.Post, new Uri(browser.ConsumerBase, "/dashboard"));
        using var response = await browser.SendOnConsumerAsync(
            write, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        // The refusal changed nothing: the session itself is untouched and still works.
        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var dashboardResponse = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, dashboardResponse.StatusCode);
    }

    [Fact]
    public async Task ASessionAuthenticatedUnsafeMethod_WithAStaleToken_IsRefused()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateSignedInAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        await FetchCsrfTokenAsync(browser);
        using var write = new HttpRequestMessage(
            HttpMethod.Post, new Uri(browser.ConsumerBase, "/dashboard"));
        write.Headers.TryAddWithoutValidation(
            SignaCoreHostedLoginDefaults.AntiforgeryHeaderName, "a-token-that-was-never-issued");
        using var response = await browser.SendOnConsumerAsync(
            write, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task ASessionAuthenticatedUnsafeMethod_WithAValidToken_IsServed()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateSignedInAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        var token = await FetchCsrfTokenAsync(browser);
        using var write = new HttpRequestMessage(
            HttpMethod.Post, new Uri(browser.ConsumerBase, "/dashboard"));
        write.Headers.TryAddWithoutValidation(
            SignaCoreHostedLoginDefaults.AntiforgeryHeaderName, token);
        using var response = await browser.SendOnConsumerAsync(
            write, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal($"dashboard-write:{FakeIdentityProvider.DefaultSubject}", body);
    }

    [Fact]
    public async Task AHostBearerRoute_IsNotAffectedByTheSessionCsrfBoundary()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            "client-pack-test-secret",
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler(),
            configureTestServices: services => services.PostConfigure<SignaCoreHostedLoginOptions>(
                options => options.SchemeSelector = context =>
                    context.Request.Path.StartsWithSegments("/api") ? "TestBearer" : null));
        using var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));
        await using var _ = consumer;

        // A Bearer-authenticated POST needs no antiforgery token: it carries no session cookie.
        using var write = new HttpRequestMessage(
            HttpMethod.Post, new Uri(browser.ConsumerBase, "/api/data"));
        write.Headers.TryAddWithoutValidation(
            "Authorization", $"Bearer {ConsumerAppAccess.TestBearerHandlerCredential()}");
        write.Content = new StringContent("payload");
        using var response = await browser.SendOnConsumerAsync(
            write, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("api-data-written", await response.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TheBoundary_KeepsWorking_WhenTheSessionSchemeIsTheDefaultScheme()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            "client-pack-test-secret",
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler(),
            // The integration shape a BFF-style consumer uses: the package's scheme is the
            // application's default scheme, so the request pipeline presents the session
            // principal on every surface, including GET /auth/csrf. The boundary's antiforgery
            // pairs are user-neutral, so tokens issued on such a consumer still validate.
            configureTestServices: services => services.PostConfigure<AuthenticationOptions>(
                options =>
                {
                    options.DefaultScheme = SignaCoreHostedLoginDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = SignaCoreHostedLoginDefaults.AuthenticationScheme;
                }));
        var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));
        using var _ = browser;

        using (var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start")))
        using (var startResponse = await browser.SendOnConsumerAsync(start, TestContext.Current.CancellationToken))
        using (var authorize = new HttpRequestMessage(HttpMethod.Get, startResponse.Headers.Location!))
        using (var authorizeResponse = await browser.SendOnIdentityServerAsync(
            authorize, TestContext.Current.CancellationToken))
        using (var callback = new HttpRequestMessage(HttpMethod.Get, authorizeResponse.Headers.Location!))
        using (var callbackResponse = await browser.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        }

        var token = await FetchCsrfTokenAsync(browser);
        using var write = new HttpRequestMessage(
            HttpMethod.Post, new Uri(browser.ConsumerBase, "/dashboard"));
        write.Headers.TryAddWithoutValidation(
            SignaCoreHostedLoginDefaults.AntiforgeryHeaderName, token);
        using var response = await browser.SendOnConsumerAsync(write, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var logout = new HttpRequestMessage(
            HttpMethod.Post, new Uri(browser.ConsumerBase, "/auth/logout"));
        logout.Headers.TryAddWithoutValidation(
            SignaCoreHostedLoginDefaults.AntiforgeryHeaderName, token);
        using var logoutResponse = await browser.SendOnConsumerAsync(
            logout, TestContext.Current.CancellationToken);
        Assert.NotEqual(HttpStatusCode.BadRequest, logoutResponse.StatusCode);
        Assert.NotEqual("""{"outcome":"csrf_rejected"}""", await logoutResponse.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken));

        await consumer.DisposeAsync();
    }

    [Fact]
    public async Task TheLogoutEndpoint_RejectsAMissingOrWrongTokenBeforeAnyChange()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateSignedInAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        foreach (var wrong in new[] { null, "not-a-real-token" })
        {
            using var logout = new HttpRequestMessage(
                HttpMethod.Post, new Uri(browser.ConsumerBase, "/auth/logout"));
            if (wrong is not null)
            {
                logout.Headers.TryAddWithoutValidation(
                    SignaCoreHostedLoginDefaults.AntiforgeryHeaderName, wrong);
            }

            using var response = await browser.SendOnConsumerAsync(
                logout, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal("""{"outcome":"csrf_rejected"}""", body);
        }

        // Nothing was signed out and nothing was prepared.
        Assert.Empty(authority.LogoutPrepareBodies);
        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var dashboardResponse = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, dashboardResponse.StatusCode);
    }

    [Fact]
    public async Task TheLogoutEndpoint_RejectsTheTokenOfADifferentBrowser()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateSignedInAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        // A second browser (its own cookie container) issues a token: the antiforgery pair is
        // bound per browser, so replaying that token against the first browser's session fails.
        var otherBrowserConsumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            "client-pack-test-secret",
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler());
        using var otherBrowser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            otherBrowserConsumer, authority.Server.CreateHandler(),
            new Uri(FakeIdentityProvider.BaseAddress));
        await using var ___ = otherBrowserConsumer;
        var foreignToken = await FetchCsrfTokenAsync(otherBrowser);

        using var logout = new HttpRequestMessage(
            HttpMethod.Post, new Uri(browser.ConsumerBase, "/auth/logout"));
        logout.Headers.TryAddWithoutValidation(
            SignaCoreHostedLoginDefaults.AntiforgeryHeaderName, foreignToken);
        using var response = await browser.SendOnConsumerAsync(
            logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(authority.LogoutPrepareBodies);
    }
}

/// <summary>Exposes the consumer test app's fixed Bearer credential to the tests above.</summary>
file static class ConsumerAppAccess
{
    internal static string TestBearerHandlerCredential() => "client-pack-bearer-credential";
}
