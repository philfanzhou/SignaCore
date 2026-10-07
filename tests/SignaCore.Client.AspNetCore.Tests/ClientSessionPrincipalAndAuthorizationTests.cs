extern alias ConsumerApp;

using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The session-status endpoint's two extension points: the response writer receives the
/// verified session principal (with any claims a custom ticket store added, null when
/// anonymous or expired) through the new four-argument overload whose default forwards to the
/// historical three-argument one; and <c>SessionEndpointRequireAuthorization</c> (default
/// false) can require an authenticated user on that endpoint only, with the host's pipeline
/// presenting the challenge.
/// </summary>
public sealed class ClientSessionPrincipalAndAuthorizationTests
{
    private const string ClientId = "client-pack-app";

    /// <summary>Records what the new overload received; renders a fixed body.</summary>
    private sealed class RecordingWriter : ISignaCoreHostedLoginResponseWriter
    {
        public List<(SignaCoreSessionStatus Status, ClaimsPrincipal? Principal)> Received { get; } = [];

        public Task WriteSignInFailureAsync(
            HttpContext context, SignaCoreSignInReason reason, CancellationToken cancellationToken) =>
            SignaCoreDefaultResponseWriter.Instance.WriteSignInFailureAsync(context, reason, cancellationToken);

        public Task WriteFailurePageAsync(
            HttpContext context, SignaCoreSignInReason? reason, CancellationToken cancellationToken) =>
            SignaCoreDefaultResponseWriter.Instance.WriteFailurePageAsync(context, reason, cancellationToken);

        public Task WriteSessionStatusAsync(
            HttpContext context, SignaCoreSessionStatus status, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The three-argument overload must not be called directly.");

        public async Task WriteSessionStatusAsync(
            HttpContext context,
            SignaCoreSessionStatus status,
            ClaimsPrincipal? principal,
            CancellationToken cancellationToken)
        {
            Received.Add((status, principal));
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                """{"authenticated":""" + (status.Authenticated ? "true" : "false") + "}",
                cancellationToken);
        }
    }

    /// <summary>Only implements the historical three-argument signature, exactly like a writer
    /// written before the principal overload existed.</summary>
    private sealed class LegacyWriter : ISignaCoreHostedLoginResponseWriter
    {
        public int Calls { get; private set; }

        public Task WriteSignInFailureAsync(
            HttpContext context, SignaCoreSignInReason reason, CancellationToken cancellationToken) =>
            SignaCoreDefaultResponseWriter.Instance.WriteSignInFailureAsync(context, reason, cancellationToken);

        public Task WriteFailurePageAsync(
            HttpContext context, SignaCoreSignInReason? reason, CancellationToken cancellationToken) =>
            SignaCoreDefaultResponseWriter.Instance.WriteFailurePageAsync(context, reason, cancellationToken);

        public Task WriteSessionStatusAsync(
            HttpContext context, SignaCoreSessionStatus status, CancellationToken cancellationToken)
        {
            Calls++;
            return SignaCoreDefaultResponseWriter.Instance.WriteSessionStatusAsync(context, status, cancellationToken);
        }
    }

    /// <summary>A consumer-style store that adds a role claim at storage time — the documented
    /// hook for claims the ID token does not carry.</summary>
    private sealed class RoleInjectingStore(TimeProvider clock) : ITicketStore
    {
        private readonly InMemoryTicketStore _inner = new(clock);

        public Task<string?> StoreAsync(SignaCoreSessionTicket ticket, CancellationToken cancellationToken)
        {
            var enriched = ticket with
            {
                Principal = new ClaimsPrincipal(new ClaimsIdentity(
                    ticket.Principal.Claims.Append(new Claim("role", "order_manager")),
                    ticket.Principal.Identity?.AuthenticationType,
                    nameType: "name",
                    roleType: "role"))
            };
            return _inner.StoreAsync(enriched, cancellationToken);
        }

        public Task<SignaCoreSessionTicket?> RetrieveAsync(string key, CancellationToken cancellationToken) =>
            _inner.RetrieveAsync(key, cancellationToken);

        public Task RemoveAsync(string key, CancellationToken cancellationToken) =>
            _inner.RemoveAsync(key, cancellationToken);

        public int RemoveExpired(CancellationToken cancellationToken) =>
            _inner.RemoveExpired(cancellationToken);
    }

    private static async Task<(WebApplicationFactory<ConsumerApp.Program> Consumer, CrossServerBrowser Browser)>
        SignInAsync(
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

    private static async Task<(HttpResponseMessage Response, string Body)> GetSessionAsync(
        CrossServerBrowser browser)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/session"));
        using var response = await browser.SendOnConsumerAsync(
            request, TestContext.Current.CancellationToken);
        return (response, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    private static async Task<(HttpResponseMessage Response, string Body)> GetSessionAnonymouslyAsync(
        WebApplicationFactory<ConsumerApp.Program> consumer)
    {
        using var client = new HttpClient(consumer.Server.CreateHandler())
        {
            BaseAddress = new Uri("https://bff.localhost")
        };
        using var response = await client.GetAsync("/auth/session", TestContext.Current.CancellationToken);
        return (response, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TheWriterReceivesTheSessionPrincipal_WithConsumerInjectedClaims()
    {
        var writer = new RecordingWriter();
        var clock = new ManualTimeProvider();
        await using var authority = await FakeIdentityProvider.StartAsync(clock);
        var (consumer, browser) = await SignInAsync(
            authority,
            configure: services =>
            {
                services.AddSingleton<ITicketStore>(new RoleInjectingStore(clock));
                services.PostConfigure<SignaCoreHostedLoginOptions>(
                    options => options.ResponseWriter = writer);
            },
            timeProvider: clock);
        await using var _ = consumer;
        using var __ = browser;

        var (response, body) = await GetSessionAsync(browser);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("\"authenticated\":true", body, StringComparison.Ordinal);

        // The principal the writer saw is the ticket's — carrying the role claim the custom
        // store injected at storage time, the documented hook for ID-token-absent claims.
        var (status, principal) = Assert.Single(writer.Received);
        Assert.True(status.Authenticated);
        Assert.NotNull(principal);
        Assert.Equal(
            FakeIdentityProvider.DefaultSubject,
            principal!.FindFirst("sub")?.Value);
        Assert.Equal("order_manager", principal.FindFirst("role")?.Value);

        // An anonymous browser gets the fixed expired status and a null principal.
        writer.Received.Clear();
        var (anonymousResponse, anonymousBody) = await GetSessionAnonymouslyAsync(consumer);
        Assert.Equal(HttpStatusCode.OK, anonymousResponse.StatusCode);
        Assert.Contains("\"authenticated\":false", anonymousBody, StringComparison.Ordinal);
        var (anonymousStatus, anonymousPrincipal) = Assert.Single(writer.Received);
        Assert.False(anonymousStatus.Authenticated);
        Assert.Null(anonymousPrincipal);
    }

    [Fact]
    public async Task ALegacyWriter_OnlyImplementingTheOldSignature_StillServesTheEndpoint()
    {
        var writer = new LegacyWriter();
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await SignInAsync(
            authority,
            configure: services => services.PostConfigure<SignaCoreHostedLoginOptions>(
                options => options.ResponseWriter = writer));
        await using var _ = consumer;
        using var __ = browser;

        // The four-argument overload's default body forwards to the historical one; the response
        // is the default fixed JSON and the legacy writer was called.
        var (response, body) = await GetSessionAsync(browser);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("\"authenticated\":true", body, StringComparison.Ordinal);
        Assert.Equal(1, writer.Calls);
    }

    [Fact]
    public async Task ByDefault_TheSessionEndpoint_IsAnonymousExactlyAsBefore()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, _) = await SignInAsync(authority);
        await using var _ = consumer;

        var (response, body) = await GetSessionAnonymouslyAsync(consumer);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(
            """{"authenticated":false,"requiresReauthentication":true,"displayName":null,"authorization":null}""",
            body);
    }

    [Fact]
    public async Task WithTheOptionOn_UnauthenticatedSessionReadsAreRejected_AndOtherEndpointsStayOpen()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await SignInAsync(
            authority,
            configure: services => services.PostConfigure<SignaCoreHostedLoginOptions>(
                options => options.SessionEndpointRequireAuthorization = true));
        await using var _ = consumer;
        using var __ = browser;

        // Anonymous: rejected by the host's authorization pipeline (the test app's default
        // scheme challenges with its own 401).
        using var anonymousClient = new HttpClient(consumer.Server.CreateHandler())
        {
            BaseAddress = new Uri("https://bff.localhost")
        };
        using var anonymous = await anonymousClient.GetAsync(
            "/auth/session", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        // Authenticated through the host's own default scheme (the test app's Bearer): the
        // endpoint answers as before for any principal the host's pipeline accepts.
        using var authorized = new HttpRequestMessage(HttpMethod.Get, "/auth/session");
        authorized.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Bearer", "client-pack-bearer-credential");
        using var authorizedResponse = await anonymousClient.SendAsync(
            authorized, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, authorizedResponse.StatusCode);

        // Every other package endpoint is untouched: start redirects anonymously and csrf
        // issues a token anonymously.
        using var start = await anonymousClient.GetAsync(
            "/auth/start", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, start.StatusCode);
        using var csrf = await anonymousClient.GetAsync(
            "/auth/csrf", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, csrf.StatusCode);
    }

    [Fact]
    public async Task WithTheOptionOn_AndThePackageSchemeAsDefault_TheChallengeRedirectsToStart()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await SignInAsync(
            authority,
            configure: services =>
            {
                services.PostConfigure<SignaCoreHostedLoginOptions>(
                    options => options.SessionEndpointRequireAuthorization = true);
                // A host that makes the package's scheme its default authenticates the endpoint
                // through the session handler and presents its challenge: one redirect to the
                // sign-in start.
                services.PostConfigure<AuthenticationOptions>(
                    options => options.DefaultScheme = SignaCoreHostedLoginDefaults.AuthenticationScheme);
            });
        await using var _ = consumer;
        using var __ = browser;

        using var client = new HttpClient(consumer.Server.CreateHandler())
        {
            BaseAddress = new Uri("https://bff.localhost")
        };
        using var response = await client.GetAsync("/auth/session", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.StartsWith(
            "/auth/start?returnUrl=",
            response.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.Contains(
            Uri.EscapeDataString("/auth/session"),
            response.Headers.Location!.ToString(),
            StringComparison.Ordinal);

        // The signed-in browser — authenticated by the session cookie through the package's
        // scheme — still reads the endpoint.
        var (authenticated, body) = await GetSessionAsync(browser);
        Assert.Equal(HttpStatusCode.OK, authenticated.StatusCode);
        Assert.Contains("\"authenticated\":true", body, StringComparison.Ordinal);
    }
}
