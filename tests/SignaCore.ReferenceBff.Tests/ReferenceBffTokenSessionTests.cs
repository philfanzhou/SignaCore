extern alias BffSample;

using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using Xunit;
using BffMemoryTicketStore = BffSample::SignaCore.ReferenceBff.MemoryTicketStore;

namespace SignaCore.ReferenceBff.Tests;

/// <summary>
/// The server-side token session of the reference BFF against the real SignaCore host (DF-07,
/// DF-15): tokens are stored in the server-side ticket store, the browser holds only the opaque
/// session cookie, the access token is used solely on the BFF→SignaCore UserInfo leg, an upstream
/// 401 tears the local session down (fail closed), and the only state-changing browser surface is
/// the antiforgery-protected POST logout.
/// </summary>
public sealed partial class ReferenceBffTokenSessionTests(SignaCoreHostFixture fixture)
    : IClassFixture<SignaCoreHostFixture>
{
    private const string SessionCookieName = "signacore-bff-session";

    [GeneratedRegex("name=\"__RequestVerificationToken\" value=\"([^\"]*)\"")]
    private static partial Regex AntiforgeryTokenPattern();

    // ---- Acceptance 1, 12: opaque server-side session, cookie boundary ----

    [Fact]
    public async Task Login_StoresTheTokensServerSide_AndTheBrowserOnlyGetsAnOpaqueSessionCookie()
    {
        await using var session = await SignInAsync();

        // The browser holds one small opaque session cookie: no JWT structure, no token material.
        Assert.True(
            session.SessionCookieValue.Length <= 512,
            $"The session cookie is {session.SessionCookieValue.Length} characters; an opaque key was expected.");
        Assert.DoesNotContain("eyJ", session.SessionCookieValue, StringComparison.Ordinal);

        // The session cookie is HttpOnly, Secure, and SameSite=Lax; the correlation cookie keeps
        // the handshake shape fixed by the sign-in task (SameSite=None).
        var sessionCookieHeader = session.BffResponses
            .SelectMany(response => response.SetCookies)
            .First(cookie => cookie.StartsWith(SessionCookieName + "=", StringComparison.Ordinal));
        Assert.Contains("httponly", sessionCookieHeader, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", sessionCookieHeader, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", sessionCookieHeader, StringComparison.OrdinalIgnoreCase);

        var correlationCookieHeader = session.BffResponses
            .SelectMany(response => response.SetCookies)
            .First(cookie => cookie.Contains("signacore-bff-correlation", StringComparison.Ordinal));
        Assert.Contains("samesite=none", correlationCookieHeader, StringComparison.OrdinalIgnoreCase);

        // The tokens live in the server-side store instead: exactly one ticket, and the cookie
        // carries none of the issued material.
        Assert.Equal(1, session.Store.Count);
        var issued = session.ReadIssuedTokens();
        Assert.DoesNotContain(issued.AccessToken, session.SessionCookieValue, StringComparison.Ordinal);
        Assert.DoesNotContain(issued.IdToken, session.SessionCookieValue, StringComparison.Ordinal);
    }

    // ---- Acceptance 2, 6: UserInfo over the server-side Bearer token ----

    [Fact]
    public async Task BffMe_CallsTheDiscoveryUserInfoEndpoint_WithTheServerSideBearerToken()
    {
        await using var session = await SignInAsync();

        var (response, body) = await SendOnBffCapturingAsync(
            session,
            new HttpRequestMessage(HttpMethod.Get, new Uri(session.Browser.BffBase, "/bff/me")));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("\"sub\"", body, StringComparison.Ordinal);

        // The outbound leg: exactly one UserInfo call, to the Discovery-resolved endpoint, with
        // the access token issued at login as the only Bearer credential.
        var issued = session.ReadIssuedTokens();
        var userInfoCalls = session.UserInfoTraffic.Records
            .Where(record => record.Uri.AbsolutePath.EndsWith("/oauth2/userinfo", StringComparison.Ordinal))
            .ToList();
        var call = Assert.Single(userInfoCalls);
        Assert.Equal(
            SignaCoreHostFixture.Authority + "/oauth2/userinfo",
            call.Uri.GetLeftPart(UriPartial.Path));
        Assert.Equal("Bearer " + issued.AccessToken, call.Authorization);

        // The Bearer header never appears on any browser-facing response.
        Assert.DoesNotContain(session.BffResponses, response => response.HasAuthorizationHeader);
    }

    // ---- Acceptance 3: the local session is reused without a new handshake ----

    [Fact]
    public async Task SubsequentRequests_ReuseTheLocalSession_WithoutANewHandshake()
    {
        await using var session = await SignInAsync();

        var authorizeCallsBefore = session.Browser.IdentityServerRequests
            .Count(request => request.Request.RequestUri!.AbsolutePath == "/oauth2/authorize");

        var (response, body) = await SendOnBffCapturingAsync(
            session,
            new HttpRequestMessage(HttpMethod.Get, new Uri(session.Browser.BffBase, "/")));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Signed in", body, StringComparison.Ordinal);

        var authorizeCallsAfter = session.Browser.IdentityServerRequests
            .Count(request => request.Request.RequestUri!.AbsolutePath == "/oauth2/authorize");
        Assert.Equal(authorizeCallsBefore, authorizeCallsAfter);
        Assert.Equal(1, session.Store.Count);
    }

    // ---- Acceptance 4, 5: token canary over every browser-visible surface ----

    [Fact]
    public async Task TheWholeLoginFlow_LeavesNoTokenMaterialOnAnyBrowserVisibleSurface()
    {
        await using var session = await SignInAsync();
        await SendOnBffCapturingAsync(
            session,
            new HttpRequestMessage(HttpMethod.Get, new Uri(session.Browser.BffBase, "/bff/me")));
        await SendOnBffCapturingAsync(
            session,
            new HttpRequestMessage(HttpMethod.Get, new Uri(session.Browser.BffBase, "/bff/diagnostics")));

        var issued = session.ReadIssuedTokens();
        var canaries = new[]
        {
            issued.AccessToken,
            issued.IdToken,
            issued.CodeVerifier,
            SignaCoreHostFixture.ClientSecret
        };
        Assert.All(canaries, canary => Assert.False(string.IsNullOrEmpty(canary)));

        // Every BFF response: body, Location header, and Set-Cookie headers.
        foreach (var captured in session.BffResponses)
        {
            foreach (var canary in canaries)
            {
                Assert.DoesNotContain(canary, captured.Body, StringComparison.Ordinal);
                Assert.DoesNotContain(canary, captured.Location ?? string.Empty, StringComparison.Ordinal);
                Assert.DoesNotContain(canary, string.Join("\n", captured.SetCookies), StringComparison.Ordinal);
            }
        }

        // Every browser-requested BFF URL (query and fragment included).
        foreach (var captured in session.BffResponses)
        {
            var url = captured.Uri.GetLeftPart(UriPartial.Query);
            Assert.DoesNotContain(canaries, canary => url.Contains(canary, StringComparison.Ordinal));
        }
    }

    // ---- Acceptance 7, 8: upstream revocation fails the local session closed ----

    [Fact]
    public async Task AnUpstreamRevokedSession_FailsClosedOnTheNextProtectedRequest()
    {
        await using var session = await SignInAsync();

        // Revoke the account's identity sessions upstream; SignaCore's UserInfo then answers 401.
        await RevokeUpstreamSessionsAsync();

        var (response, _) = await SendOnBffCapturingAsync(
            session,
            new HttpRequestMessage(HttpMethod.Get, new Uri(session.Browser.BffBase, "/bff/me")));

        // The bounded error page: the upstream detail never reaches the browser.
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal("/error?reason=session_expired", response.Headers.Location!.ToString());

        var (errorResponse, errorBody) = await SendOnBffCapturingAsync(
            session,
            new HttpRequestMessage(HttpMethod.Get, new Uri(session.Browser.BffBase, "/error?reason=session_expired")));
        Assert.Equal(HttpStatusCode.OK, errorResponse.StatusCode);
        Assert.Contains("no longer valid", errorBody, StringComparison.Ordinal);

        // The ticket is gone from the store, and the browser no longer presents a signed-in state.
        Assert.Equal(0, session.Store.Count);
        var (homeResponse, homeBody) = await SendOnBffCapturingAsync(
            session,
            new HttpRequestMessage(HttpMethod.Get, new Uri(session.Browser.BffBase, "/")));
        Assert.Equal(HttpStatusCode.OK, homeResponse.StatusCode);
        Assert.DoesNotContain("Signed in", homeBody, StringComparison.Ordinal);
    }

    // ---- Acceptance 9: an expired local ticket is unusable and reclaimed ----

    [Fact]
    public async Task AnExpiredLocalTicket_IsRemoved_AndTheProtectedEndpointChallengesAgain()
    {
        var clock = new ManipulableClock(DateTimeOffset.UtcNow);
        await using var session = await SignInAsync(clock);
        Assert.Equal(1, session.Store.Count);

        // Past the 8-hour local session lifetime: the ticket is expired.
        clock.Advance(TimeSpan.FromHours(9));

        var (response, _) = await SendOnBffCapturingAsync(
            session,
            new HttpRequestMessage(HttpMethod.Get, new Uri(session.Browser.BffBase, "/bff/me")));

        // The expired ticket is reclaimed on the spot, and the endpoint starts a new handshake.
        Assert.Equal(0, session.Store.Count);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.StartsWith(
            SignaCoreHostFixture.Authority + "/oauth2/authorize",
            response.Headers.Location!.ToString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheTicketStore_ReclaimsExpiredTickets_OnRetrieveAndOnSweep()
    {
        var clock = new ManipulableClock(new DateTimeOffset(2026, 9, 19, 12, 0, 0, TimeSpan.Zero));
        var store = new BffMemoryTicketStore(clock);

        var liveKey = await store.StoreAsync(CreateTicket(clock.GetUtcNow().AddHours(1)));
        var deadKey = await store.StoreAsync(CreateTicket(clock.GetUtcNow().AddMinutes(-1)));

        // Retrieve of an expired ticket returns null and removes it.
        Assert.Null(await store.RetrieveAsync(deadKey));
        Assert.Equal(1, store.Count);
        Assert.NotNull(await store.RetrieveAsync(liveKey));

        // The sweep reclaims expired tickets no request ever presents again.
        _ = await store.StoreAsync(CreateTicket(clock.GetUtcNow().AddMinutes(-5)));
        Assert.Equal(2, store.Count);
        Assert.Equal(1, store.RemoveExpired());
        Assert.Equal(1, store.Count);
        Assert.NotNull(await store.RetrieveAsync(liveKey));

        // Remove drops the ticket entirely.
        await store.RemoveAsync(liveKey);
        Assert.Equal(0, store.Count);
        Assert.Null(await store.RetrieveAsync(liveKey));
    }

    // ---- Acceptance 10: cancelling the UserInfo leg leaves no half-written state ----

    [Fact]
    public async Task CancellingTheUserInfoCall_ObservesTheRequestToken_AndLeavesTheSessionIntact()
    {
        var blocking = new BlockingUserInfoHandler();
        await using var session = await SignInAsync(userInfoHandler: blocking);

        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var request = new HttpRequestMessage(HttpMethod.Get, new Uri(session.Browser.BffBase, "/bff/me"));
        var operation = session.Browser.SendOnBffAsync(request, cancellation.Token);

        // Give the pipeline time to reach the blocked UserInfo call, then abandon it.
        await Task.Delay(TimeSpan.FromMilliseconds(300), TestContext.Current.CancellationToken);
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);
        Assert.True(blocking.ObservedCancellation);

        // No half-written state: the ticket is untouched and the session still signs the home
        // page in; nothing detached kept running.
        Assert.Equal(1, session.Store.Count);
        var (response, body) = await SendOnBffCapturingAsync(
            session,
            new HttpRequestMessage(HttpMethod.Get, new Uri(session.Browser.BffBase, "/")));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Signed in", body, StringComparison.Ordinal);
    }

    // ---- Acceptance 11: logout is a POST behind antiforgery ----

    [Fact]
    public async Task Logout_OnlyAcceptsAnAntiforgeryPost()
    {
        await using var session = await SignInAsync();

        var token = AntiforgeryTokenPattern().Match(session.HomeBody).Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(token), "The signed-in home page carried no antiforgery token.");

        // There is no GET logout.
        using var get = new HttpRequestMessage(HttpMethod.Get, new Uri(session.Browser.BffBase, "/bff/logout"));
        using var getResponse = await session.Browser.SendOnBffAsync(get, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, getResponse.StatusCode);
        Assert.Equal(1, session.Store.Count);

        // A cross-site POST without a token is rejected before any state changes.
        using var barePost = new HttpRequestMessage(HttpMethod.Post, new Uri(session.Browser.BffBase, "/bff/logout"))
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>())
        };
        using var bareResponse = await session.Browser.SendOnBffAsync(barePost, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, bareResponse.StatusCode);
        Assert.Equal(1, session.Store.Count);

        // A forged token is rejected as well.
        using var forgedPost = new HttpRequestMessage(HttpMethod.Post, new Uri(session.Browser.BffBase, "/bff/logout"))
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = "a-token-that-was-never-issued"
            })
        };
        using var forgedResponse = await session.Browser.SendOnBffAsync(forgedPost, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, forgedResponse.StatusCode);
        Assert.Equal(1, session.Store.Count);

        // The genuine POST signs the local session out: cookie cleared, ticket removed.
        using var post = new HttpRequestMessage(HttpMethod.Post, new Uri(session.Browser.BffBase, "/bff/logout"))
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = token
            })
        };
        using var postResponse = await session.Browser.SendOnBffAsync(post, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, postResponse.StatusCode);
        Assert.Equal("/", postResponse.Headers.Location!.ToString());
        Assert.Contains(
            postResponse.Headers.TryGetValues("Set-Cookie", out var cookies) ? cookies : [],
            cookie => cookie.StartsWith(SessionCookieName + "=", StringComparison.Ordinal)
                && cookie.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(0, session.Store.Count);

        var (_, homeBody) = await SendOnBffCapturingAsync(
            session,
            new HttpRequestMessage(HttpMethod.Get, new Uri(session.Browser.BffBase, "/")));
        Assert.DoesNotContain("Signed in", homeBody, StringComparison.Ordinal);
    }

    // ---- Driving and capture ----

    private async Task<SignedInSession> SignInAsync(
        ManipulableClock? clock = null,
        HttpMessageHandler? userInfoHandler = null)
    {
        var backchannel = new RecordingHandler(fixture.Host.Server.CreateHandler());
        var backchannelClient = new HttpClient(backchannel, disposeHandler: false)
        {
            BaseAddress = new Uri(SignaCoreHostFixture.Authority)
        };
        var outbound = new RecordingHandler(fixture.Host.Server.CreateHandler());
        var bff = BffTestServer.Create(
            SignaCoreHostFixture.Authority,
            SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            backchannelClient,
            userInfoHandler ?? outbound,
            clock);
        var browser = BffTestServer.CreateBrowser(fixture.Host, bff);
        var captures = new List<CapturedResponse>();

        try
        {
            // The full real handshake: challenge → authorize → credential POST → callback → home.
            var (challenge, _) = await SendOnBffCapturingAsync(
                browser,
                captures,
                new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/login")));
            Assert.Equal(HttpStatusCode.Found, challenge.StatusCode);
            var authorizeUrl = challenge.Headers.Location!.ToString();

            using var authorize = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.IdentityBase, authorizeUrl));
            using var authorizeResponse = await browser.SendOnIdentityServerAsync(authorize, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Found, authorizeResponse.StatusCode);

            using var login = await SignaCoreLoginDriver.PostCredentialsAsync(
                browser,
                authorizeResponse.Headers.Location!.ToString(),
                SignaCoreHostFixture.Username,
                SignaCoreHostFixture.Password,
                TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Found, login.StatusCode);

            var (callback, _) = await SendOnBffCapturingAsync(
                browser,
                captures,
                new HttpRequestMessage(HttpMethod.Get, new Uri(login.Headers.Location!.ToString())));
            Assert.Equal(HttpStatusCode.Found, callback.StatusCode);

            var (_, homeBody) = await SendOnBffCapturingAsync(
                browser,
                captures,
                new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/")));
            Assert.Contains("Signed in", homeBody, StringComparison.Ordinal);

            var cookieValue = browser.Cookies.GetCookies(browser.BffBase)[SessionCookieName]?.Value;
            Assert.False(string.IsNullOrEmpty(cookieValue), "The login issued no BFF session cookie.");

            return new SignedInSession
            {
                Bff = bff,
                Browser = browser,
                BackchannelClient = backchannelClient,
                Backchannel = backchannel,
                UserInfoTraffic = outbound,
                BffResponses = captures,
                SessionCookieValue = cookieValue!,
                HomeBody = homeBody
            };
        }
        catch
        {
            browser.Dispose();
            backchannelClient.Dispose();
            await bff.DisposeAsync();
            throw;
        }
    }

    private async Task RevokeUpstreamSessionsAsync()
    {
        using var scope = fixture.Host.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var credential = await dbContext.PasswordCredentials
            .AsNoTracking()
            .SingleAsync(row => row.Username == SignaCoreHostFixture.Username, TestContext.Current.CancellationToken);
        var sessions = await dbContext.IdentitySessions
            .Where(row => row.AccountId == credential.AccountId && row.RevokedAt == null)
            .ToListAsync(TestContext.Current.CancellationToken);
        Assert.NotEmpty(sessions);

        var now = DateTimeOffset.UtcNow;
        foreach (var identitySession in sessions)
        {
            identitySession.RevokedAt = now;
            identitySession.RevocationReason = "logout";
        }

        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        dbContext.ChangeTracker.Clear();
    }

    private static async Task<(HttpResponseMessage Response, string Body)> SendOnBffCapturingAsync(
        SignedInSession session,
        HttpRequestMessage request) =>
        await SendOnBffCapturingAsync(session.Browser, session.BffResponses, request);

    private static async Task<(HttpResponseMessage Response, string Body)> SendOnBffCapturingAsync(
        CrossServerBrowser browser,
        List<CapturedResponse> captures,
        HttpRequestMessage request)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var method = request.Method;
        var uri = request.RequestUri!;
        var response = await browser.SendOnBffAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        captures.Add(new CapturedResponse(
            method,
            uri,
            response.StatusCode,
            response.Headers.Location?.ToString(),
            response.Headers.TryGetValues("Set-Cookie", out var setCookies) ? setCookies.ToArray() : [],
            response.Headers.Contains("Authorization"),
            body));
        return (response, body);
    }

    private static AuthenticationTicket CreateTicket(DateTimeOffset expiresUtc) =>
        new(
            new ClaimsPrincipal(new ClaimsIdentity([], "Test")),
            new AuthenticationProperties { ExpiresUtc = expiresUtc },
            "Test");

    private sealed record CapturedResponse(
        HttpMethod Method,
        Uri Uri,
        HttpStatusCode Status,
        string? Location,
        string[] SetCookies,
        bool HasAuthorizationHeader,
        string Body);

    private sealed class SignedInSession : IAsyncDisposable
    {
        public required WebApplicationFactory<BffSample.Program> Bff { get; init; }

        public required CrossServerBrowser Browser { get; init; }

        public required HttpClient BackchannelClient { get; init; }

        public required RecordingHandler Backchannel { get; init; }

        public required RecordingHandler UserInfoTraffic { get; init; }

        public required List<CapturedResponse> BffResponses { get; init; }

        public required string SessionCookieValue { get; init; }

        public required string HomeBody { get; init; }

        public BffMemoryTicketStore Store => Bff.Services.GetRequiredService<BffMemoryTicketStore>();

        /// <summary>The material the token endpoint issued and the PKCE verifier presented to it,
        /// read from the recorded backchannel traffic.</summary>
        public (string AccessToken, string IdToken, string CodeVerifier) ReadIssuedTokens()
        {
            var exchange = Backchannel.Records.SingleOrDefault(record =>
                record.Method == HttpMethod.Post
                && record.Uri.AbsolutePath.EndsWith("/oauth2/token", StringComparison.Ordinal))
                ?? throw new InvalidOperationException("The login never reached the token endpoint.");

            using var document = JsonDocument.Parse(exchange.ResponseBody);
            var accessToken = document.RootElement.GetProperty("access_token").GetString()
                ?? throw new InvalidOperationException("The token response carried no access token.");
            var idToken = document.RootElement.GetProperty("id_token").GetString()
                ?? throw new InvalidOperationException("The token response carried no id token.");

            const string verifierPrefix = "code_verifier=";
            var verifierField = exchange.RequestBody
                .Split('&', StringSplitOptions.RemoveEmptyEntries)
                .SingleOrDefault(field => field.StartsWith(verifierPrefix, StringComparison.Ordinal))
                ?? throw new InvalidOperationException("The token request carried no PKCE verifier.");
            var codeVerifier = Uri.UnescapeDataString(verifierField[verifierPrefix.Length..]);

            return (accessToken, idToken, codeVerifier);
        }

        public async ValueTask DisposeAsync()
        {
            Browser.Dispose();
            BackchannelClient.Dispose();
            await Bff.DisposeAsync();
        }
    }

    /// <summary>Records both legs of the BFF's outbound traffic and replays the response body so
    /// the OIDC handler and the endpoints can still consume it.</summary>
    private sealed class RecordingHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        public List<OutboundRecord> Records { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var requestBody = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);
            var response = await base.SendAsync(request, cancellationToken);
            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
            var contentType = response.Content.Headers.ContentType;
            response.Content = new StringContent(responseBody, Encoding.UTF8);
            if (contentType is not null)
            {
                response.Content.Headers.ContentType = contentType;
            }

            Records.Add(new OutboundRecord(
                request.Method,
                request.RequestUri!,
                requestBody,
                request.Headers.Authorization?.ToString(),
                responseBody));
            return response;
        }
    }

    private sealed record OutboundRecord(
        HttpMethod Method,
        Uri Uri,
        string RequestBody,
        string? Authorization,
        string ResponseBody);

    /// <summary>Fails the request only when the caller's token fires; any earlier fault would
    /// break the test with a different exception.</summary>
    private sealed class BlockingUserInfoHandler : HttpMessageHandler
    {
        public bool ObservedCancellation { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                ObservedCancellation = true;
                throw;
            }

            throw new InvalidOperationException("The blocking UserInfo handler must never complete.");
        }
    }

    private sealed class ManipulableClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan delta) => _now = _now.Add(delta);
    }
}
