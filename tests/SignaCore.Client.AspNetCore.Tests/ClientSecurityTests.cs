extern alias ConsumerApp;

using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The package's callback hardening and token validation against a controllable authority: every
/// defect fails the sign-in, never starts a token exchange when the handshake is broken, and
/// never establishes a session. A code is redeemed exactly once with Basic client authentication
/// only, and the failure page carries only the bounded reason.
/// </summary>
public sealed class ClientSecurityTests
{
    private const string ClientId = "client-pack-app";

    private static async Task<(FakeIdentityProvider Authority, WebApplicationFactory<ConsumerApp.Program> Consumer, CrossServerBrowser Browser)>
        CreateAsync(FakeIdentityProvider authority)
    {
        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            "client-pack-test-secret",
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler());
        var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));
        return (authority, consumer, browser);
    }

    /// <summary>Starts a sign-in and returns the authority's immediate callback URL.</summary>
    private static async Task<string> BeginSignInAsync(CrossServerBrowser browser)
    {
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
        return authorizeResponse.Headers.Location!.ToString();
    }

    /// <summary>Drives the full chain from start; returns the final page.</summary>
    private static async Task<(HttpResponseMessage Response, Uri FinalUri, string Body)> DriveAsync(
        CrossServerBrowser browser)
    {
        var callbackUrl = await BeginSignInAsync(browser);
        using var callback = new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl));
        using var callbackResponse = await browser.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken);
        if (callbackResponse.StatusCode == HttpStatusCode.Found
            && callbackResponse.Headers.Location is { } location)
        {
            using var final = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.ConsumerBase, location));
            var (response, finalUri) = await browser.FollowAsync(
                final, TestContext.Current.CancellationToken);
            var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            return (response, finalUri, body);
        }

        var errorBody = await callbackResponse.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken);
        return (callbackResponse, new Uri(callbackUrl), errorBody);
    }

    private static async Task AssertRejectedAsync(
        CrossServerBrowser browser,
        string reason,
        FakeIdentityProvider authority,
        int expectedTokenRequests)
    {
        var callbackUrl = await BeginSignInAsync(browser);
        using var callback = new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl));
        using var callbackResponse = await browser.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        var location = callbackResponse.Headers.Location!.ToString();
        Assert.StartsWith("/auth/signin-failed", location, StringComparison.Ordinal);
        Assert.Contains($"reason={reason}", location, StringComparison.Ordinal);

        // The failure page renders the bounded reason and nothing else.
        using var page = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.ConsumerBase, location));
        var (pageResponse, _, pageBody) = await DrivePageAsync(browser, page);
        Assert.Equal(HttpStatusCode.OK, pageResponse.StatusCode);
        Assert.Contains("Sign-in could not complete", pageBody, StringComparison.Ordinal);

        // No session was established: the protected route still challenges.
        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var dashboardResponse = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, dashboardResponse.StatusCode);
        Assert.StartsWith("/auth/start", dashboardResponse.Headers.Location!.ToString(), StringComparison.Ordinal);

        Assert.Equal(expectedTokenRequests, authority.RedeemedCodes.Count);
    }

    private static async Task<(HttpResponseMessage Response, Uri FinalUri, string Body)> DrivePageAsync(
        CrossServerBrowser browser,
        HttpRequestMessage request)
    {
        var (response, finalUri) = await browser.FollowAsync(request, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return (response, finalUri, body);
    }

    [Fact]
    public async Task ACorrectHandshake_EstablishesTheSession()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (_, consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        var (response, finalUri, body) = await DriveAsync(browser);
        Assert.Equal("/", finalUri.PathAndQuery);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("consumer home", body);

        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var dashboardResponse = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, dashboardResponse.StatusCode);
        var dashboardBody = await dashboardResponse.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal($"dashboard:{FakeIdentityProvider.DefaultSubject}", dashboardBody);
    }

    [Fact]
    public async Task ACorrectHandshake_AuthenticatesTheClientOnceWithBasicOnly()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (_, consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        await DriveAsync(browser);

        var header = Assert.Single(authority.TokenAuthorizationHeaders);
        Assert.StartsWith("Basic ", header, StringComparison.Ordinal);
        // The code is redeemed exactly once.
        Assert.Single(authority.RedeemedCodes);
    }

    [Theory]
    [InlineData(FakeIdentityProvider.TokenDefect.WrongIssuer)]
    [InlineData(FakeIdentityProvider.TokenDefect.WrongAudience)]
    [InlineData(FakeIdentityProvider.TokenDefect.WrongNonce)]
    [InlineData(FakeIdentityProvider.TokenDefect.SigningKeyAbsentFromJwks)]
    public async Task ADefectiveIdToken_FailsTheSignInWithoutASession(
        FakeIdentityProvider.TokenDefect defect)
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.Defect = defect;
        var (_, consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        // The code was redeemed (once) before the ID token failed validation.
        await AssertRejectedAsync(browser, "invalid_token", authority, expectedTokenRequests: 1);
    }

    [Theory]
    [InlineData(FakeIdentityProvider.TokenResponseShape.MissingAccessToken)]
    [InlineData(FakeIdentityProvider.TokenResponseShape.MissingIdToken)]
    [InlineData(FakeIdentityProvider.TokenResponseShape.WrongTokenType)]
    [InlineData(FakeIdentityProvider.TokenResponseShape.NonPositiveExpiresIn)]
    [InlineData(FakeIdentityProvider.TokenResponseShape.NonJsonBody)]
    public async Task AMalformedTokenResponse_FailsTheSignInWithoutASession(
        FakeIdentityProvider.TokenResponseShape shape)
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.ResponseShape = shape;
        var (_, consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        await AssertRejectedAsync(browser, "invalid_token", authority, expectedTokenRequests: 1);
    }

    [Fact]
    public async Task ATamperedState_FailsTheCallbackWithoutAnyTokenExchange()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.Echo = FakeIdentityProvider.AuthorizeEcho.TamperState;
        var (_, consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        await AssertRejectedAsync(browser, "state_mismatch", authority, expectedTokenRequests: 0);
    }

    [Fact]
    public async Task AWrongIssuerParameter_FailsTheCallbackWithoutAnyTokenExchange()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.Echo = FakeIdentityProvider.AuthorizeEcho.WrongIss;
        var (_, consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        await AssertRejectedAsync(browser, "issuer_mismatch", authority, expectedTokenRequests: 0);
    }

    [Fact]
    public async Task AMissingIssuerParameter_FailsTheCallbackWithoutAnyTokenExchange()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.Echo = FakeIdentityProvider.AuthorizeEcho.OmitIss;
        var (_, consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        await AssertRejectedAsync(browser, "invalid_response", authority, expectedTokenRequests: 0);
    }

    [Fact]
    public async Task ADuplicatedStateParameter_FailsTheCallbackWithoutAnyTokenExchange()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.Echo = FakeIdentityProvider.AuthorizeEcho.DuplicateState;
        var (_, consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        await AssertRejectedAsync(browser, "invalid_response", authority, expectedTokenRequests: 0);
    }

    [Fact]
    public async Task ADuplicatedCodeParameter_FailsTheCallbackWithoutAnyTokenExchange()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.Echo = FakeIdentityProvider.AuthorizeEcho.DuplicateCode;
        var (_, consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        await AssertRejectedAsync(browser, "invalid_response", authority, expectedTokenRequests: 0);
    }

    [Fact]
    public async Task AUserDeniedConsent_ShowsTheBoundedAccessDeniedPage()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.Echo = FakeIdentityProvider.AuthorizeEcho.ErrorAccessDenied;
        var (_, consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        await AssertRejectedAsync(browser, "access_denied", authority, expectedTokenRequests: 0);
    }

    [Fact]
    public async Task AReplayedCode_IsNotRedeemedTwice_AndFailsTheSecondSignIn()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.Echo = FakeIdentityProvider.AuthorizeEcho.ReuseCode;
        var (_, consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        // First use: success.
        var (response, _, body) = await DriveAsync(browser);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("consumer home", body);
        Assert.Single(authority.RedeemedCodes);

        // Second use of the same code: the authority answers invalid_grant; the package does not
        // retry and shows the bounded failure page.
        var callbackUrl = await BeginSignInAsync(browser);
        using var callback = new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl));
        using var callbackResponse = await browser.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.StartsWith(
            "/auth/signin-failed",
            callbackResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.Contains(
            "reason=token_exchange_failed",
            callbackResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);

        // Exactly two redemptions total: one per sign-in, never a retry.
        Assert.Equal(2, authority.RedeemedCodes.Count(code => code == "fixed-reused-code"));
    }

    [Fact]
    public async Task AnUnreachableAuthorityAtStart_ShowsTheBoundedFailurePage()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.DiscoveryIssuer = "https://a-different-issuer.example";
        var consumer = ConsumerAppTestServer.Create(
            "https://idp.localhost",
            ClientId,
            "client-pack-test-secret",
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler());
        using var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));
        await using var _ = consumer;

        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start"));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, startResponse.StatusCode);
        Assert.StartsWith(
            "/auth/signin-failed",
            startResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.Contains(
            "reason=authority_unreachable",
            startResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnExternalReturnUrl_IsRejectedWithTheBoundedReason()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (_, consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        foreach (var returnUrl in new[]
                 {
                     "https://evil.example/",
                     "//evil.example/",
                     "/\\evil.example/",
                     "relative/path"
                 })
        {
            using var start = new HttpRequestMessage(
                HttpMethod.Get,
                new Uri(
                    browser.ConsumerBase,
                    "/auth/start?returnUrl=" + Uri.EscapeDataString(returnUrl)));
            using var response = await browser.SendOnConsumerAsync(
                start, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.StartsWith(
                "/auth/signin-failed",
                response.Headers.Location!.ToString(),
                StringComparison.Ordinal);
            Assert.Contains(
                "reason=invalid_return_url",
                response.Headers.Location!.ToString(),
                StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task TheAuthorizeRequest_CarriesExactlyTheContractFields()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (_, consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        await BeginSignInAsync(browser);

        var authorizeUri = Assert.Single(authority.AuthorizeRequests);
        var fields = authorizeUri.Query.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(member => member.Split('=', 2)[0])
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(
            new[]
            {
                "client_id", "code_challenge", "code_challenge_method", "nonce",
                "redirect_uri", "response_type", "scope", "state"
            },
            fields);
        foreach (var forbidden in new[] { "prompt", "max_age", "acr_values", "response_mode" })
        {
            Assert.DoesNotContain(forbidden, authorizeUri.Query, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task TheFailedHandshakeState_CannotBeReplayedWithACorrectedIssuer()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.Echo = FakeIdentityProvider.AuthorizeEcho.WrongIss;
        var (_, consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        // First: the callback answers with the wrong issuer and is rejected.
        var callbackUrl = await BeginSignInAsync(browser);
        using var first = new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl));
        using var firstResponse = await browser.SendOnConsumerAsync(
            first, TestContext.Current.CancellationToken);
        Assert.Contains(
            "reason=issuer_mismatch",
            firstResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);

        // The state was consumed: replaying the same callback with a corrected iss cannot retry
        // the handshake.
        var corrected = callbackUrl.Replace(
            "iss=https://someone-else.example",
            "iss=" + FakeIdentityProvider.BaseAddress);
        using var replay = new HttpRequestMessage(HttpMethod.Get, new Uri(corrected));
        using var replayResponse = await browser.SendOnConsumerAsync(
            replay, TestContext.Current.CancellationToken);
        Assert.Contains(
            "reason=state_mismatch",
            replayResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.Empty(authority.RedeemedCodes);
    }
}
