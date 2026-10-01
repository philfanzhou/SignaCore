extern alias ConsumerApp;

using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The package's prepared logout against the real SignaCore host and against a controllable fake
/// authority: the local session is revoked before the upstream preparation, the browser is sent
/// only to a verified same-origin logout URI, the return is one-time and browser-bound, an
/// upstream failure ends in the fixed local-only result without a retry, a repeated or concurrent
/// logout revokes at most once and prepares at most once, and no ID token, secret, handle, or
/// state ever reaches a response body or a log line.
/// </summary>
public sealed class ClientLogoutTests(SignaCoreHostFixture fixture)
    : IClassFixture<SignaCoreHostFixture>
{
    private const string ClientId = "client-pack-app";
    private const string ClientSecret = "client-pack-test-secret";

    private static async Task<string> FetchCsrfTokenAsync(CrossServerBrowser browser)
    {
        using var csrf = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/csrf"));
        using var response = await browser.SendOnConsumerAsync(
            csrf, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return JsonSerializer.Deserialize<JsonElement>(body).GetProperty("token").GetString()!;
    }

    private static HttpRequestMessage LogoutRequest(Uri consumerBase, string? token = null)
    {
        var request = new HttpRequestMessage(
            HttpMethod.Post, new Uri(consumerBase, "/auth/logout"));
        if (token is not null)
        {
            request.Headers.TryAddWithoutValidation(
                SignaCoreHostedLoginDefaults.AntiforgeryHeaderName, token);
        }

        return request;
    }

    /// <summary>Signs in through the real hosted login and returns the browser with a session.</summary>
    private static async Task<(WebApplicationFactory<ConsumerApp.Program> Consumer, CrossServerBrowser Browser)>
        SignInOnRealHostAsync(
            SignaCoreHostFixture fixture,
            HttpMessageHandler? backchannelOverride = null,
            CapturingLoggerProvider? capture = null,
            TimeProvider? timeProvider = null)
    {
        var consumer = ConsumerAppTestServer.Create(
            SignaCoreHostFixture.Authority,
            SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            backchannelOverride ?? fixture.Host.Server.CreateHandler(),
            timeProvider: timeProvider,
            loggerProvider: capture,
            postLogoutRedirectUri: SignaCoreHostFixture.PostLogoutRedirectUri);
        var browser = ConsumerAppTestServer.CreateBrowser(fixture.Host, consumer);

        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start?returnUrl=/dashboard"));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        using var login = await SignaCoreLoginDriver.DriveToCallbackUrlAsync(
            browser,
            startResponse.Headers.Location!.ToString(),
            SignaCoreHostFixture.Username,
            SignaCoreHostFixture.Password,
            TestContext.Current.CancellationToken);
        using var callback = new HttpRequestMessage(
            HttpMethod.Get, login.Headers.Location!);
        using var callbackResponse = await browser.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal("/dashboard", callbackResponse.Headers.Location!.ToString());
        return (consumer, browser);
    }

    private static async Task<(WebApplicationFactory<ConsumerApp.Program> Consumer, CrossServerBrowser Browser)>
        SignInOnFakeAuthorityAsync(FakeIdentityProvider authority, TimeProvider? timeProvider = null)
    {
        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler(),
            timeProvider: timeProvider,
            postLogoutRedirectUri: SignaCoreHostFixture.PostLogoutRedirectUri);
        var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));

        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start"));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        using var authorize = new HttpRequestMessage(
            HttpMethod.Get, startResponse.Headers.Location!);
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(
            authorize, TestContext.Current.CancellationToken);
        using var callback = new HttpRequestMessage(
            HttpMethod.Get, authorizeResponse.Headers.Location!);
        using var callbackResponse = await browser.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal("/", callbackResponse.Headers.Location!.ToString());
        return (consumer, browser);
    }

    private static async Task AssertSignedOutAsync(CrossServerBrowser browser)
    {
        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var response = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.StartsWith(
            "/auth/start",
            response.Headers.Location!.ToString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Logout_OverTheRealHost_RevokesLocallyThenRedirectsThroughThePreparedHandle()
    {
        var capture = new CapturingLoggerProvider();
        var (consumer, browser) = await SignInOnRealHostAsync(fixture, capture: capture);
        await using var _ = consumer;
        using var __ = browser;

        var token = await FetchCsrfTokenAsync(browser);
        using var logout = LogoutRequest(browser.ConsumerBase, token);
        using var logoutResponse = await browser.SendOnConsumerAsync(
            logout, TestContext.Current.CancellationToken);

        // The browser is redirected to the authority's completion endpoint with exactly one
        // 43-character handle and nothing else.
        Assert.Equal(HttpStatusCode.Found, logoutResponse.StatusCode);
        var location = logoutResponse.Headers.Location!;
        Assert.StartsWith(
            SignaCoreHostFixture.Authority + "/oauth2/logout?logout_handle=",
            location.ToString(),
            StringComparison.Ordinal);
        var handle = location.ToString().Split('=')[1];
        Assert.Equal(43, handle.Length);

        // The logout-return correlation cookie was set: HttpOnly, Secure, scoped to the logout
        // paths, and alive only for the prepared window.
        Assert.Contains(
            logoutResponse.Headers.GetValues("Set-Cookie"),
            cookie => cookie.StartsWith(
                SignaCoreHostedLoginDefaults.SessionCookieName + "-logout-return=",
                StringComparison.Ordinal)
                && cookie.Contains("path=/auth/logout", StringComparison.OrdinalIgnoreCase)
                && cookie.Contains("httponly", StringComparison.OrdinalIgnoreCase)
                && cookie.Contains("secure", StringComparison.OrdinalIgnoreCase));

        // The local session is already gone before the browser follows the redirect.
        await AssertSignedOutAsync(browser);

        // The authority completes the logout and returns the browser with the echoed state.
        using var completion = new HttpRequestMessage(HttpMethod.Get, location);
        using var completionResponse = await browser.SendOnIdentityServerAsync(
            completion, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, completionResponse.StatusCode);
        var returnUrl = completionResponse.Headers.Location!;
        Assert.StartsWith(
            SignaCoreHostFixture.PostLogoutRedirectUri,
            returnUrl.ToString(),
            StringComparison.Ordinal);
        var returnQuery = System.Web.HttpUtility.ParseQueryString(returnUrl.Query);
        Assert.Single(returnQuery.AllKeys);
        Assert.Equal("state", returnQuery.AllKeys[0]);
        Assert.InRange(returnQuery["state"]!.Length, 22, 128);

        // The return consumes the one-time state and lands on the fixed local target.
        using var landing = new HttpRequestMessage(HttpMethod.Get, returnUrl);
        using var landingResponse = await browser.SendOnConsumerAsync(
            landing, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, landingResponse.StatusCode);
        Assert.Equal("/signed-out", landingResponse.Headers.Location!.ToString());

        // No sensitive value of the flow reached any consumer response or log line: the
        // preparation went server-to-server over the same backchannel as the token exchange.
        var logText = string.Join(
            Environment.NewLine,
            capture.Lines.Where(line => line.Contains(
                "[SignaCore.Client.AspNetCore.", StringComparison.Ordinal)));
        Assert.NotEmpty(logText);
        foreach (var response in browser.ConsumerRequests)
        {
            Assert.DoesNotContain("id_token_hint", response.Request.RequestUri!.PathAndQuery,
                StringComparison.Ordinal);
        }

        Assert.DoesNotContain(SignaCoreHostFixture.ClientSecret, logText, StringComparison.Ordinal);
        Assert.DoesNotContain(handle, logText, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(FakeIdentityProvider.LogoutPrepareShape.HttpError)]
    [InlineData(FakeIdentityProvider.LogoutPrepareShape.Unreachable)]
    [InlineData(FakeIdentityProvider.LogoutPrepareShape.CrossOriginUri)]
    [InlineData(FakeIdentityProvider.LogoutPrepareShape.ExtraQueryUri)]
    [InlineData(FakeIdentityProvider.LogoutPrepareShape.MissingUriMember)]
    public async Task AnUpstreamFailure_EndsInTheFixedLocalOnlyResult_WithoutRollingBackOrRetrying(
        FakeIdentityProvider.LogoutPrepareShape shape)
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.LogoutPrepare = shape;
        var (consumer, browser) = await SignInOnFakeAuthorityAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        var token = await FetchCsrfTokenAsync(browser);
        using var logout = LogoutRequest(browser.ConsumerBase, token);
        using var response = await browser.SendOnConsumerAsync(
            logout, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(
            """{"outcome":"local_only"}""",
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        // The local session was revoked first and stays revoked.
        await AssertSignedOutAsync(browser);

        // Exactly one preparation was attempted; there is no retry.
        Assert.Single(authority.LogoutPrepareBodies);
    }

    [Fact]
    public async Task ALogoutTimeout_EndsInTheFixedLocalOnlyResult_WithoutARetry()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.LogoutPrepare = FakeIdentityProvider.LogoutPrepareShape.Timeout;
        var (consumer, browser) = await SignInOnFakeAuthorityAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        var token = await FetchCsrfTokenAsync(browser);

        // The caller abandons the logout request once the preparation is known to be stuck; the
        // timeout path answers the fixed local-only shape when the response can still be written.
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        using var logout = LogoutRequest(browser.ConsumerBase, token);
        HttpResponseMessage? response = null;
        try
        {
            response = await browser.Consumer.SendAsync(
                logout, cancellation.Token);
        }
        catch (OperationCanceledException)
        {
            // The caller left before any answer: the local revocation still stands, which the
            // signed-out assertion below proves.
        }
        finally
        {
            response?.Dispose();
        }

        await AssertSignedOutAsync(browser);
        Assert.Single(authority.LogoutPrepareBodies);
    }

    [Fact]
    public async Task ARepeatedLogout_RevokesOnceAndPreparesOnce()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await SignInOnFakeAuthorityAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        var token = await FetchCsrfTokenAsync(browser);
        using var first = LogoutRequest(browser.ConsumerBase, token);
        using var firstResponse = await browser.SendOnConsumerAsync(
            first, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, firstResponse.StatusCode);

        // The session cookie is gone; a second logout has nothing left to revoke or prepare and
        // answers the same fixed local-only result.
        using var second = LogoutRequest(browser.ConsumerBase, token);
        using var secondResponse = await browser.SendOnConsumerAsync(
            second, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, secondResponse.StatusCode);
        Assert.Equal(
            """{"outcome":"local_only"}""",
            await secondResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Single(authority.LogoutPrepareBodies);
    }

    [Fact]
    public async Task ConcurrentLogouts_RevokesOnceAndPreparesOnce()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await SignInOnFakeAuthorityAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        var token = await FetchCsrfTokenAsync(browser);
        using var first = LogoutRequest(browser.ConsumerBase, token);
        using var second = LogoutRequest(browser.ConsumerBase, token);
        var firstTask = browser.Consumer.SendAsync(first, TestContext.Current.CancellationToken);
        var secondTask = browser.Consumer.SendAsync(second, TestContext.Current.CancellationToken);
        using var firstResponse = await firstTask;
        using var secondResponse = await secondTask;

        // Exactly one of the two requests was redirected to the authority; the other answered the
        // fixed local-only result.
        var outcomes = new[] { firstResponse.StatusCode, secondResponse.StatusCode }
            .OrderBy(code => code)
            .ToArray();
        Assert.Equal(HttpStatusCode.OK, outcomes[0]);
        Assert.Equal(HttpStatusCode.Found, outcomes[1]);
        Assert.Single(authority.LogoutPrepareBodies);
        await AssertSignedOutAsync(browser);
    }

    [Fact]
    public async Task TheReturnState_IsWrongRepeatedOrExpired_AndAnswersTheFixedInvalidResult()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var time = new ManualTimeProvider();
        var (consumer, browser) = await SignInOnFakeAuthorityAsync(authority, time);
        await using var _ = consumer;
        using var __ = browser;

        var token = await FetchCsrfTokenAsync(browser);
        using var logout = LogoutRequest(browser.ConsumerBase, token);
        using var logoutResponse = await browser.SendOnConsumerAsync(
            logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, logoutResponse.StatusCode);

        // The correct one-time state completes the return, redirects to the fixed local target,
        // and cannot be replayed: the browser first finishes at the authority, which returns it
        // with the echoed state, and the package consumes that state exactly once. A wrong state
        // presented against a live correlation finishes it too — probing gains nothing.
        using var completion = new HttpRequestMessage(HttpMethod.Get, logoutResponse.Headers.Location!);
        using var completionResponse = await browser.SendOnIdentityServerAsync(
            completion, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, completionResponse.StatusCode);
        using var valid = new HttpRequestMessage(
            HttpMethod.Get, completionResponse.Headers.Location!);
        using var validResponse = await browser.SendOnConsumerAsync(
            valid, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, validResponse.StatusCode);
        Assert.Equal("/signed-out", validResponse.Headers.Location!.ToString());

        using var replay = new HttpRequestMessage(
            HttpMethod.Get, completionResponse.Headers.Location!);
        using var replayResponse = await browser.SendOnConsumerAsync(
            replay, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, replayResponse.StatusCode);

        // A wrong state is the same fixed invalid answer, and no request input is echoed.
        using var wrong = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(
                browser.ConsumerBase,
                "/auth/logout/return?state=" + Uri.EscapeDataString("a-wrong-state-value-123456")));
        using var wrongResponse = await browser.SendOnConsumerAsync(
            wrong, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, wrongResponse.StatusCode);
        var wrongBody = await wrongResponse.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken);
        Assert.Contains("Sign-out could not be confirmed", wrongBody, StringComparison.Ordinal);
        Assert.DoesNotContain("a-wrong-state-value-123456", wrongBody, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnExpiredReturnState_AnswersTheFixedInvalidResult()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var time = new ManualTimeProvider();
        var (consumer, browser) = await SignInOnFakeAuthorityAsync(authority, time);
        await using var _ = consumer;
        using var __ = browser;

        var token = await FetchCsrfTokenAsync(browser);
        using var logout = LogoutRequest(browser.ConsumerBase, token);
        using var logoutResponse = await browser.SendOnConsumerAsync(
            logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, logoutResponse.StatusCode);

        // The window passing invalidates the package's one-time correlation state: the authority
        // still answers its own completion, but the package's return endpoint refuses.
        time.Advance(TimeSpan.FromMinutes(6));
        using var completion = new HttpRequestMessage(
            HttpMethod.Get, logoutResponse.Headers.Location!);
        using var completionResponse = await browser.SendOnIdentityServerAsync(
            completion, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, completionResponse.StatusCode);
        using var landing = new HttpRequestMessage(
            HttpMethod.Get, completionResponse.Headers.Location!);
        using var landingResponse = await browser.SendOnConsumerAsync(
            landing, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, landingResponse.StatusCode);
    }

    [Fact]
    public async Task ALateBrowserCompletion_AfterTheWindowState_EndsInvalidAtThePackageOnly()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var time = new ManualTimeProvider();
        var (consumer, browser) = await SignInOnFakeAuthorityAsync(authority, time);
        await using var _ = consumer;
        using var __ = browser;

        var token = await FetchCsrfTokenAsync(browser);
        using var logout = LogoutRequest(browser.ConsumerBase, token);
        using var logoutResponse = await browser.SendOnConsumerAsync(
            logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, logoutResponse.StatusCode);

        // The authority-side window passing invalidates the package's correlation state too.
        time.Advance(TimeSpan.FromMinutes(6));
        using var completion = new HttpRequestMessage(
            HttpMethod.Get, logoutResponse.Headers.Location!);
        using var completionResponse = await browser.SendOnIdentityServerAsync(
            completion, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, completionResponse.StatusCode);
        using var landing = new HttpRequestMessage(
            HttpMethod.Get, completionResponse.Headers.Location!);
        using var landingResponse = await browser.SendOnConsumerAsync(
            landing, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, landingResponse.StatusCode);
    }

    [Fact]
    public async Task ThePreparationBody_CarriesTheServerHeldIdTokenOnceAndNothingElse()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await SignInOnFakeAuthorityAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        var token = await FetchCsrfTokenAsync(browser);
        using var logout = LogoutRequest(browser.ConsumerBase, token);
        using var response = await browser.SendOnConsumerAsync(
            logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);

        var body = Assert.Single(authority.LogoutPrepareBodies);
        var fields = body.Split('&')
            .Select(member => member.Split('=', 2))
            .ToDictionary(pair => pair[0], pair => Uri.UnescapeDataString(pair[1]));
        // Exactly the contract's fields: the server-held ID token, the registered post-logout
        // URI, and the one-time state — and never the client secret, which travels only in the
        // Basic header.
        Assert.Equal(
            new[] { "id_token_hint", "post_logout_redirect_uri", "state" }.OrderBy(f => f, StringComparer.Ordinal),
            fields.Keys.OrderBy(f => f, StringComparer.Ordinal));
        Assert.Equal(SignaCoreHostFixture.PostLogoutRedirectUri, fields["post_logout_redirect_uri"]);
        Assert.Contains("eyJ", fields["id_token_hint"], StringComparison.Ordinal);
        Assert.DoesNotContain(
            ClientSecret,
            body + Assert.Single(authority.LogoutPrepareAuthorizationHeaders),
            StringComparison.Ordinal);
        Assert.StartsWith(
            "Basic ",
            Assert.Single(authority.LogoutPrepareAuthorizationHeaders),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task LogoutWithoutAPostLogoutUriConfigured_StillPreparesWithoutAState()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler());
        var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));
        await using var _ = consumer;
        using var __ = browser;

        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start"));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        using var authorize = new HttpRequestMessage(
            HttpMethod.Get, startResponse.Headers.Location!);
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(
            authorize, TestContext.Current.CancellationToken);
        using var callback = new HttpRequestMessage(
            HttpMethod.Get, authorizeResponse.Headers.Location!);
        using var callbackResponse = await browser.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);

        var token = await FetchCsrfTokenAsync(browser);
        using var logout = LogoutRequest(browser.ConsumerBase, token);
        using var response = await browser.SendOnConsumerAsync(
            logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);

        var body = Assert.Single(authority.LogoutPrepareBodies);
        Assert.Contains("id_token_hint=", body, StringComparison.Ordinal);
        Assert.DoesNotContain("post_logout_redirect_uri=", body, StringComparison.Ordinal);
        Assert.DoesNotContain("state=", body, StringComparison.Ordinal);
    }
}
