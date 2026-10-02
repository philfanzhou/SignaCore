extern alias BffSample;

using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SignaCore.ReferenceBff.Tests;

/// <summary>
/// The prepared-logout demonstration of the reference BFF against the real SignaCore host: the
/// client package's <c>POST /bff/logout</c> ends the local session first, then coordinates the
/// upstream sign-out and returns the browser through the one-time <c>/bff/logout/return</c>; a
/// failing upstream preparation still ends the local session with the bounded local-only answer;
/// the CSRF boundary and the return endpoint reject everything else with fixed bounded answers.
/// </summary>
public sealed class ReferenceBffPreparedLogoutTests(SignaCoreHostFixture fixture)
    : IClassFixture<SignaCoreHostFixture>
{
    private const string SessionCookieName = "signacore-bff-session";
    private const string CsrfHeaderName = "X-ReferenceBff-CSRF";

    [Fact]
    public async Task PreparedLogout_EndsTheLocalAndUpstreamSessions_AndReturnsToTheLandingPage()
    {
        using var authorityClient = fixture.Host.Server.CreateHandler();
        using var bff = BffTestServer.Create(
            SignaCoreHostFixture.Authority,
            SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            authorityClient);
        using var browser = BffTestServer.CreateBrowser(fixture.Host, bff);

        var authorizeUrl = await BffSignIn.BeginAsync(browser, TestContext.Current.CancellationToken);
        using var authorize = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.IdentityBase, authorizeUrl));
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(authorize, TestContext.Current.CancellationToken);
        using var login = await SignaCoreLoginDriver.PostCredentialsAsync(
            browser,
            authorizeResponse.Headers.Location!.ToString(),
            SignaCoreHostFixture.Username,
            SignaCoreHostFixture.Password,
            TestContext.Current.CancellationToken);
        using var callback = new HttpRequestMessage(HttpMethod.Get, new Uri(login.Headers.Location!.ToString()));
        using var callbackResponse = await browser.SendOnBffAsync(callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal(1, BffTickets.Count(bff));

        // The package's antiforgery-token endpoint issues the header-token pair the write needs.
        using var csrfRequest = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/csrf"));
        using var csrfResponse = await browser.SendOnBffAsync(csrfRequest, TestContext.Current.CancellationToken);
        csrfResponse.EnsureSuccessStatusCode();
        using var csrfDocument = JsonDocument.Parse(
            await csrfResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var token = csrfDocument.RootElement.GetProperty("token").GetString();
        Assert.False(string.IsNullOrEmpty(token));

        // The genuine logout: the local session ends first, then the browser is sent to
        // SignaCore's prepared logout URI with the one-time logout handle.
        using var logout = new HttpRequestMessage(HttpMethod.Post, new Uri(browser.BffBase, "/bff/logout"));
        logout.Headers.Add(CsrfHeaderName, token);
        using var logoutResponse = await browser.SendOnBffAsync(logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, logoutResponse.StatusCode);
        Assert.StartsWith(
            SignaCoreHostFixture.Authority + "/oauth2/logout",
            logoutResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.Equal(0, BffTickets.Count(bff));

        // SignaCore completes the upstream sign-out and returns the browser to the registered
        // post-logout URI with the echoed state.
        using var upstream = new HttpRequestMessage(HttpMethod.Get, logoutResponse.Headers.Location!);
        using var upstreamResponse = await browser.SendOnIdentityServerAsync(upstream, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, upstreamResponse.StatusCode);
        var returnUri = upstreamResponse.Headers.Location!;
        Assert.Equal(
            SignaCoreHostFixture.PostLogoutRedirectUri,
            returnUri.GetLeftPart(UriPartial.Path));

        // The package accepts the one-time state with its correlation cookie and lands the
        // browser on the fixed local path.
        using var returnUrl = new HttpRequestMessage(HttpMethod.Get, returnUri);
        using var returnResponse = await browser.SendOnBffAsync(returnUrl, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, returnResponse.StatusCode);
        Assert.Equal("/", returnResponse.Headers.Location!.ToString());

        using var home = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/"));
        using var homeResponse = await browser.SendOnBffAsync(home, TestContext.Current.CancellationToken);
        var homeBody = await homeResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("Signed in", homeBody, StringComparison.Ordinal);

        // The upstream identity session is gone too: a fresh authorize request no longer answers
        // with an immediate callback and sends the browser to the login form instead.
        var secondAuthorizeUrl = await BffSignIn.BeginAsync(browser, TestContext.Current.CancellationToken);
        using var secondAuthorize = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.IdentityBase, secondAuthorizeUrl));
        using var secondAuthorizeResponse = await browser.SendOnIdentityServerAsync(secondAuthorize, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, secondAuthorizeResponse.StatusCode);
        Assert.StartsWith(
            "/oauth2/login?login_handle=",
            secondAuthorizeResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheLogoutEndpoint_RejectsMissingAndForgedAntiforgeryTokens_WithoutTouchingTheSession()
    {
        await using var session = await SignInOnceAsync();

        using var bare = new HttpRequestMessage(HttpMethod.Post, new Uri(session.Browser.BffBase, "/bff/logout"))
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>())
        };
        using var bareResponse = await session.Browser.SendOnBffAsync(bare, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, bareResponse.StatusCode);
        Assert.Equal(
            """{"outcome":"csrf_rejected"}""",
            await bareResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        using var forged = new HttpRequestMessage(HttpMethod.Post, new Uri(session.Browser.BffBase, "/bff/logout"));
        forged.Headers.Add(CsrfHeaderName, "a-token-that-was-never-issued");
        using var forgedResponse = await session.Browser.SendOnBffAsync(forged, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, forgedResponse.StatusCode);
        Assert.Equal(1, BffTickets.Count(session.Bff));

        using var home = new HttpRequestMessage(HttpMethod.Get, new Uri(session.Browser.BffBase, "/"));
        using var homeResponse = await session.Browser.SendOnBffAsync(home, TestContext.Current.CancellationToken);
        var body = await homeResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("Signed in", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnUpstreamPreparationFailure_StillEndsTheLocalSession_WithTheBoundedLocalOnlyAnswer()
    {
        // The fake authority serves the sign-in contract but has no logout-preparation endpoint,
        // so the upstream leg fails after the local session has already ended.
        await using var authority = await FakeAuthority.StartAsync();
        using var backchannel = authority.Server.CreateHandler();
        await using var bff = BffTestServer.Create(
            FakeAuthority.BaseAddress,
            SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            backchannel,
            userInfoHandler: authority.Server.CreateHandler());
        using var browser = BffTestServer.CreateBrowserOverAuthority(
            bff, authority.Server.CreateHandler(), new Uri(FakeAuthority.BaseAddress));

        var authorizeUrl = await BffSignIn.BeginAsync(browser, TestContext.Current.CancellationToken);
        using var authorize = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.IdentityBase, authorizeUrl));
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(authorize, TestContext.Current.CancellationToken);
        using var callback = new HttpRequestMessage(HttpMethod.Get, new Uri(authorizeResponse.Headers.Location!.ToString()));
        using var callbackResponse = await browser.SendOnBffAsync(callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal(1, BffTickets.Count(bff));

        var cookie = browser.Cookies.GetCookies(browser.BffBase)[SessionCookieName]!.Value;
        using var csrfRequest = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/csrf"));
        using var csrfResponse = await browser.SendOnBffAsync(csrfRequest, TestContext.Current.CancellationToken);
        using var csrfDocument = JsonDocument.Parse(
            await csrfResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var token = csrfDocument.RootElement.GetProperty("token").GetString();

        using var logout = new HttpRequestMessage(HttpMethod.Post, new Uri(browser.BffBase, "/bff/logout"));
        logout.Headers.Add(CsrfHeaderName, token);
        using var logoutResponse = await browser.SendOnBffAsync(logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, logoutResponse.StatusCode);
        Assert.Equal(
            """{"outcome":"local_only"}""",
            await logoutResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        // The local session ended first and is never restored: no ticket, deleted cookie, and a
        // signed-out home page — the failure detail of the upstream call never surfaces.
        Assert.Equal(0, BffTickets.Count(bff));
        Assert.Contains(
            logoutResponse.Headers.TryGetValues("Set-Cookie", out var cookies) ? cookies : [],
            value => value.StartsWith(SessionCookieName + "=", StringComparison.Ordinal)
                && value.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));
        using var home = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/"));
        using var homeResponse = await browser.SendOnBffAsync(home, TestContext.Current.CancellationToken);
        var homeBody = await homeResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("Signed in", homeBody, StringComparison.Ordinal);
        Assert.DoesNotContain(cookie, homeBody, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheLogoutReturnEndpoint_RejectsAnUnusableStateWithTheBoundedPage()
    {
        using var authorityClient = fixture.Host.Server.CreateHandler();
        using var bff = BffTestServer.Create(
            SignaCoreHostFixture.Authority,
            SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            authorityClient);
        using var browser = BffTestServer.CreateBrowser(fixture.Host, bff);

        // Without a matching one-time correlation, every shape of the return endpoint answers the
        // same bounded page and echoes no request input.
        foreach (var query in new[] { "", "?state=forged-state-attempt", "?state=a&state=b" })
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Get, new Uri(browser.BffBase, "/bff/logout/return" + query));
            using var response = await browser.SendOnBffAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Contains("Sign-out could not be confirmed", body, StringComparison.Ordinal);
        }
    }

    private async Task<SignedIn> SignInOnceAsync()
    {
        var authorityClient = fixture.Host.Server.CreateHandler();
        var bff = BffTestServer.Create(
            SignaCoreHostFixture.Authority,
            SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            authorityClient);
        var browser = BffTestServer.CreateBrowser(fixture.Host, bff);
        try
        {
            var authorizeUrl = await BffSignIn.BeginAsync(browser, TestContext.Current.CancellationToken);
            using var authorize = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.IdentityBase, authorizeUrl));
            using var authorizeResponse = await browser.SendOnIdentityServerAsync(authorize, TestContext.Current.CancellationToken);
            using var login = await SignaCoreLoginDriver.PostCredentialsAsync(
                browser,
                authorizeResponse.Headers.Location!.ToString(),
                SignaCoreHostFixture.Username,
                SignaCoreHostFixture.Password,
                TestContext.Current.CancellationToken);
            using var callback = new HttpRequestMessage(HttpMethod.Get, new Uri(login.Headers.Location!.ToString()));
            using var callbackResponse = await browser.SendOnBffAsync(callback, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
            return new SignedIn(bff, browser);
        }
        catch
        {
            browser.Dispose();
            await bff.DisposeAsync();
            throw;
        }
    }

    private sealed record SignedIn(
        WebApplicationFactory<BffSample.Program> Bff,
        CrossServerBrowser Browser) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            Browser.Dispose();
            await Bff.DisposeAsync();
        }
    }
}
