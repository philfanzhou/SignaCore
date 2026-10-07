extern alias ConsumerApp;

using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The session lifecycle of the package: the session never outlives the access token, its
/// endpoint answers the fixed re-authentication body once expired, the default ticket store fails
/// closed when its capacity is reached, the consumer's authorization decision is reported without
/// ending the session, and the scheme-selection extension point routes API traffic to the
/// consumer's own Bearer handler.
/// </summary>
public sealed class ClientSessionTests
{
    private const string ClientId = "client-pack-app";
    private static readonly string FixedRequiresReauthenticationBody =
        """{"authenticated":false,"requiresReauthentication":true,"displayName":null,"authorization":null}""";

    private sealed class DenyAllDecision : ISignaCoreAuthorizationDecision
    {
        public ValueTask<SignaCoreAuthorizationDecisionResult> DecideAsync(
            ClaimsPrincipal subject,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(SignaCoreAuthorizationDecisionResult.Denied);
    }

    private static async Task<(WebApplicationFactory<ConsumerApp.Program> Consumer, CrossServerBrowser Browser)>
        CreateAsync(
            FakeIdentityProvider authority,
            Action<IServiceCollection>? configure = null,
            TimeProvider? timeProvider = null)
    {
        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            "client-pack-test-secret",
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler(),
            timeProvider: timeProvider,
            configureTestServices: configure);
        var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));
        return (consumer, browser);
    }

    /// <summary>Drives one complete fake-authority sign-in and leaves the session cookie set.</summary>
    private static async Task SignInAsync(CrossServerBrowser browser)
    {
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
    }

    [Fact]
    public async Task AnExpiredSession_AnswersTheFixedRequiresReauthenticationBody_AndChallengesAgain()
    {
        var clock = new ManualTimeProvider();
        // The authority mints on the same clock the consumer validates with: a split clock
        // would mint an iat the consumer's frozen "now" sees as future.
        await using var authority = await FakeIdentityProvider.StartAsync(clock);
        var (consumer, browser) = await CreateAsync(authority, timeProvider: clock);
        await using var _ = consumer;
        using var __ = browser;

        await SignInAsync(browser);

        // The session answers authenticated while the access token is live.
        using var live = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/session"));
        using var liveResponse = await browser.SendOnConsumerAsync(
            live, TestContext.Current.CancellationToken);
        var liveBody = await liveResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("\"authenticated\":true", liveBody, StringComparison.Ordinal);

        // Past the access token's 900-second expiry: the fixed body, never a silent refresh.
        clock.Advance(TimeSpan.FromSeconds(901));
        using var expired = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/session"));
        using var expiredResponse = await browser.SendOnConsumerAsync(
            expired, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, expiredResponse.StatusCode);
        Assert.Equal(
            FixedRequiresReauthenticationBody,
            await expiredResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var dashboardResponse = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, dashboardResponse.StatusCode);
        Assert.StartsWith(
            "/auth/start",
            dashboardResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task AFullTicketStore_FailsClosedInsteadOfEvictingLiveSessions()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, firstBrowser) = await CreateAsync(
            authority,
            configure: services => services
                .PostConfigure<SignaCoreHostedLoginOptions>(options => options.TicketCapacity = 1));
        await using var _ = consumer;
        using var __ = firstBrowser;

        await SignInAsync(firstBrowser);
        using var firstSession = new HttpRequestMessage(
            HttpMethod.Get, new Uri(firstBrowser.ConsumerBase, "/auth/session"));
        using var firstResponse = await firstBrowser.SendOnConsumerAsync(
            firstSession, TestContext.Current.CancellationToken);
        Assert.Contains(
            "\"authenticated\":true",
            await firstResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken),
            StringComparison.Ordinal);

        // The second sign-in cannot store its ticket; it fails closed with the bounded reason
        // and the first session stays intact.
        using var consumerClient2 = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));
        using var __2 = consumerClient2;
        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(consumerClient2.ConsumerBase, "/auth/start"));
        using var startResponse = await consumerClient2.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        using var authorize = new HttpRequestMessage(
            HttpMethod.Get, startResponse.Headers.Location!);
        using var authorizeResponse = await consumerClient2.SendOnIdentityServerAsync(
            authorize, TestContext.Current.CancellationToken);
        using var callback = new HttpRequestMessage(
            HttpMethod.Get, authorizeResponse.Headers.Location!);
        using var callbackResponse = await consumerClient2.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Contains(
            "reason=session_store_full",
            callbackResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);

        using var firstAgain = new HttpRequestMessage(
            HttpMethod.Get, new Uri(firstBrowser.ConsumerBase, "/auth/session"));
        using var firstAgainResponse = await firstBrowser.SendOnConsumerAsync(
            firstAgain, TestContext.Current.CancellationToken);
        Assert.Contains(
            "\"authenticated\":true",
            await firstAgainResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADeniedAuthorizationDecision_IsReportedButKeepsTheSession()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateAsync(
            authority,
            configure: services => services
                .PostConfigure<SignaCoreHostedLoginOptions>(
                    options => options.AuthorizationDecision = new DenyAllDecision()));
        await using var _ = consumer;
        using var __ = browser;

        await SignInAsync(browser);

        using var session = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/session"));
        using var response = await browser.SendOnConsumerAsync(
            session, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("\"authenticated\":true", body, StringComparison.Ordinal);
        Assert.Contains("\"authorization\":1", body, StringComparison.Ordinal);

        // A denial is not a sign-out: the consumer's authenticated route still answers.
        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var dashboardResponse = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, dashboardResponse.StatusCode);
    }

    [Fact]
    public async Task TheSchemeSelector_RoutesApiTrafficToTheConsumerBearerHandler()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateAsync(
            authority,
            configure: services => services
                .PostConfigure<SignaCoreHostedLoginOptions>(options =>
                    options.SchemeSelector = context =>
                        context.Request.Path.StartsWithSegments("/api") ? "TestBearer" : null));
        await using var _ = consumer;
        using var __ = browser;

        // The API route is served by the consumer's own Bearer handler: a valid credential
        // passes, an absent one gets the handler's own 401 — not the package's login redirect.
        using var apiOk = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/api/data"));
        apiOk.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Bearer", "client-pack-bearer-credential");
        using var apiOkResponse = await browser.SendOnConsumerAsync(
            apiOk, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, apiOkResponse.StatusCode);
        Assert.Equal("api-data", await apiOkResponse.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken));

        using var apiAnonymous = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/api/data"));
        using var apiAnonymousResponse = await browser.SendOnConsumerAsync(
            apiAnonymous, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, apiAnonymousResponse.StatusCode);
        Assert.Null(apiAnonymousResponse.Headers.Location);

        // Everything outside /api still authenticates against the package's session.
        await SignInAsync(browser);
        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var dashboardResponse = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, dashboardResponse.StatusCode);
    }
}
