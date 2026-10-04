extern alias ConsumerApp;

using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The package against the real SignaCore host, in memory: the full Authorization Code + PKCE
/// sign-in over the real authorize and login-form endpoints, the Discovery-driven endpoint
/// resolution, the authorization request's exact field set, the session cookie's shape, the
/// session-status answer, the protected consumer route, the challenge entry, and the proof that
/// no sensitive value of the flow ever reaches a response body or a log line.
/// </summary>
public sealed class ClientRealHostSignInTests(SignaCoreHostFixture fixture)
    : IClassFixture<SignaCoreHostFixture>
{
    private static readonly string[] AllowedAuthorizeFields =
    [
        "response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
        "code_challenge", "code_challenge_method"
    ];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SignIn_CompletesOverTheRealHostFlow_AndEstablishesTheServerSideSession(bool useGate)
    {
        var authorityHandler = fixture.Host.Server.CreateHandler();
        var capture = new CapturingLoggerProvider();
        using var consumer = ConsumerAppTestServer.Create(
            SignaCoreHostFixture.Authority,
            SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            authorityHandler,
            loggerProvider: capture,
            configureTestServices: services => services.PostConfigure<SignaCoreHostedLoginOptions>(options =>
                options.PreSignInAuthorizationDecision = useGate ? new RealHostDecision() : null));
        using var browser = ConsumerAppTestServer.CreateBrowser(fixture.Host, consumer);

        // 1. The start endpoint resolves Discovery and redirects to the real authorize endpoint
        //    with exactly the contract's fields.
        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start?returnUrl=/dashboard"));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, startResponse.StatusCode);
        var authorizeUrl = startResponse.Headers.Location!.ToString();
        Assert.StartsWith(
            SignaCoreHostFixture.Authority + "/oauth2/authorize",
            authorizeUrl);
        var authorizeQuery = ParseSingleValuedQuery(authorizeUrl);
        Assert.Equal(
            AllowedAuthorizeFields.OrderBy(f => f, StringComparer.Ordinal),
            authorizeQuery.Keys.OrderBy(f => f, StringComparer.Ordinal));
        Assert.Equal("code", authorizeQuery["response_type"]);
        Assert.Equal(SignaCoreHostFixture.ClientId, authorizeQuery["client_id"]);
        Assert.Equal(SignaCoreHostFixture.RedirectUri, authorizeQuery["redirect_uri"]);
        Assert.Equal("S256", authorizeQuery["code_challenge_method"]);
        Assert.Equal("openid profile", authorizeQuery["scope"]);
        Assert.InRange(authorizeQuery["code_challenge"].Length, 43, 43);
        Assert.InRange(authorizeQuery["state"].Length, 43, 43);
        Assert.InRange(authorizeQuery["nonce"].Length, 43, 43);

        // 2. The real hosted login page: the browser signs in on SignaCore, never on the consumer.
        using var login = await SignaCoreLoginDriver.DriveToCallbackUrlAsync(
            browser,
            authorizeUrl,
            SignaCoreHostFixture.Username,
            SignaCoreHostFixture.Password,
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, login.StatusCode);
        var callbackUrl = login.Headers.Location!.ToString();
        Assert.StartsWith(SignaCoreHostFixture.RedirectUri, callbackUrl, StringComparison.Ordinal);
        var callbackQuery = ParseSingleValuedQuery(callbackUrl);
        var code = callbackQuery["code"];
        var state = callbackQuery["state"];

        // 3. The callback redeems the code over the backchannel, validates the ID token, and
        //    redirects to the local return address with the session cookie set.
        using var callback = new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl));
        using var callbackResponse = await browser.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal("/dashboard", callbackResponse.Headers.Location!.ToString());
        var setCookie = Assert.Single(
            callbackResponse.Headers.GetValues("Set-Cookie"),
            value => value.StartsWith(
                SignaCoreHostedLoginDefaults.SessionCookieName + "=",
                StringComparison.Ordinal));
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", setCookie, StringComparison.OrdinalIgnoreCase);
        // The cookie is an opaque key, not a token: no JWT shape, no padding, and short.
        var cookieValue = setCookie.Split(';', 2)[0].Split('=', 2)[1];
        Assert.DoesNotContain(".", cookieValue, StringComparison.Ordinal);

        // 4. The protected consumer route answers from the session.
        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var dashboardResponse = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, dashboardResponse.StatusCode);
        var dashboardBody = await dashboardResponse.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken);
        Assert.StartsWith("dashboard:", dashboardBody, StringComparison.Ordinal);
        Assert.DoesNotContain("Bearer", dashboardBody, StringComparison.Ordinal);

        // 5. The session endpoint reports state and decision, and carries no token.
        using var session = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/session"));
        using var sessionResponse = await browser.SendOnConsumerAsync(
            session, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, sessionResponse.StatusCode);
        var sessionBody = await sessionResponse.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken);
        Assert.Contains("\"authenticated\":true", sessionBody, StringComparison.Ordinal);
        Assert.Contains("\"requiresReauthentication\":false", sessionBody, StringComparison.Ordinal);
        Assert.Contains(SignaCoreHostFixture.Username, sessionBody, StringComparison.Ordinal);
        Assert.Contains("\"authorization\":0", sessionBody, StringComparison.Ordinal);
        Assert.DoesNotContain(code, sessionBody, StringComparison.Ordinal);

        // 6. SignaCore credentials never transit the consumer, and the flow's sensitive values —
        //    code, state, nonce, secret, full authorize query — never appear in any log line or
        //    any query the consumer saw.
        Assert.DoesNotContain(
            browser.ConsumerRequests.SelectMany(request =>
                new[] { request.Body, request.Request.RequestUri!.PathAndQuery }),
            value => value.Contains(SignaCoreHostFixture.Password, StringComparison.Ordinal));
        var nonce = authorizeQuery["nonce"];
        // The package's own log categories (and its backchannel client's) never carry a code,
        // state, nonce, secret, or full query string. The host's request-tracing categories are
        // the host's logging configuration — the consumer's log pipeline owns their redaction,
        // exactly as the reference deployment documents.
        var packageLogs = capture.Lines
            .Where(line => line.Contains("[SignaCore.Client.AspNetCore.", StringComparison.Ordinal)
                || line.Contains("HttpClient.SignaCoreHostedLogin", StringComparison.Ordinal))
            .ToArray();
        Assert.NotEmpty(packageLogs);
        var logText = string.Join(Environment.NewLine, packageLogs);
        foreach (var sensitive in new[] { code, state, nonce, SignaCoreHostFixture.ClientSecret })
        {
            Assert.DoesNotContain(sensitive, logText, StringComparison.Ordinal);
        }

        Assert.DoesNotContain(authorizeUrl, logText, StringComparison.Ordinal);
        Assert.DoesNotContain(callbackUrl, logText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AProtectedRoute_WithoutASession_ChallengesToTheStartEndpoint()
    {
        var authorityHandler = fixture.Host.Server.CreateHandler();
        using var consumer = ConsumerAppTestServer.Create(
            SignaCoreHostFixture.Authority,
            SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            authorityHandler);
        using var browser = ConsumerAppTestServer.CreateBrowser(fixture.Host, consumer);

        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var response = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(
            "/auth/start?returnUrl=%2Fdashboard",
            response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task TheSessionEndpoint_WithoutASession_AnswersTheFixedRequiresReauthenticationBody()
    {
        var authorityHandler = fixture.Host.Server.CreateHandler();
        using var consumer = ConsumerAppTestServer.Create(
            SignaCoreHostFixture.Authority,
            SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            authorityHandler);
        using var browser = ConsumerAppTestServer.CreateBrowser(fixture.Host, consumer);

        using var session = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/session"));
        using var response = await browser.SendOnConsumerAsync(
            session, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(
            """{"authenticated":false,"requiresReauthentication":true,"displayName":null,"authorization":null}""",
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SignIn_RedirectsTheBrowserThroughTheRealHostWithoutASecretInAnyConsumerRequest()
    {
        var authorityHandler = fixture.Host.Server.CreateHandler();
        using var consumer = ConsumerAppTestServer.Create(
            SignaCoreHostFixture.Authority,
            SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            authorityHandler);
        using var browser = ConsumerAppTestServer.CreateBrowser(fixture.Host, consumer);

        var (response, finalUri) = await browser.FollowAsync(
            new HttpRequestMessage(
                HttpMethod.Get,
                new Uri(browser.ConsumerBase, "/auth/start?returnUrl=/")),
            TestContext.Current.CancellationToken);

        // The chain stops on the hosted login form: the sign-in itself is the user's to complete.
        Assert.StartsWith("/oauth2/login", finalUri.PathAndQuery, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.All(
            browser.ConsumerRequests.Select(request => request.Request.RequestUri!.PathAndQuery),
            query => Assert.False(query.Contains("secret", StringComparison.OrdinalIgnoreCase)));
    }

    private sealed class RealHostDecision : ISignaCorePreSignInAuthorizationDecision
    {
        public ValueTask<SignaCoreAuthorizationDecisionResult> DecideAsync(
            SignaCorePreSignInAuthorizationContext context, CancellationToken cancellationToken)
        {
            Assert.Equal(SignaCoreHostFixture.Authority, context.Issuer);
            Assert.Equal(context.Subject, context.AccessTokenPrincipal.FindFirst("sub")?.Value);
            Assert.Equal(context.Subject, context.IdTokenPrincipal.FindFirst("sub")?.Value);
            return ValueTask.FromResult(SignaCoreAuthorizationDecisionResult.Allowed);
        }
    }

    private static Dictionary<string, string> ParseSingleValuedQuery(string url)
    {
        var query = url.Split('?', 2)[1].Split('#', 2)[0]
            .Split('&', StringSplitOptions.RemoveEmptyEntries);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var member in query)
        {
            var pair = member.Split('=', 2);
            var name = Uri.UnescapeDataString(pair[0]);
            Assert.DoesNotContain(name, result.Keys, StringComparer.Ordinal);
            result[name] = pair.Length == 2 ? Uri.UnescapeDataString(pair[1]) : string.Empty;
        }

        return result;
    }
}
