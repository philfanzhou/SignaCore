using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The SQLite HTTP contract of the standard RP-Initiated Logout <c>GET /oauth2/session/end</c>
/// (ADR 0010 stage 1): the shared <c>IN-31</c> hint judgement against the application named by
/// the hint's <c>aud</c> claim, the exact <c>IN-32</c> post-logout match, the staged-plus-completed
/// single-visit flow with the <c>EV-06</c>/<c>EV-07</c> cookie semantics, and the closed local
/// error surface. The prepared logout's own contract lives in the other partial files.
/// </summary>
public sealed partial class OAuthLogoutTests
{
    private static string StandardEndPath(string idTokenHint, string? postLogoutUri = null, string? state = null)
    {
        var query = $"?id_token_hint={Uri.EscapeDataString(idTokenHint)}";
        if (postLogoutUri is not null) query += $"&post_logout_redirect_uri={Uri.EscapeDataString(postLogoutUri)}";
        if (state is not null) query += $"&state={Uri.EscapeDataString(state)}";
        return "/oauth2/session/end" + query;
    }

    private static HttpRequestMessage StandardEndRequest(
        string path, string? cookieValue = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (cookieValue is not null)
        {
            request.Headers.TryAddWithoutValidation(
                "Cookie", $"{IdentitySessionDefaults.CookieName}={cookieValue}");
        }
        return request;
    }

    [Fact]
    public async Task StandardEnd_WithAValidHintAndMatchingCookie_RevokesTheSessionAndRedirects()
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, cookieValue) = await LoginAndCaptureSessionAsync(host);
        var familyRootId = await SeedInteractiveFamilyAsync(accountId, sessionId);
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false
        });
        var idToken = await MintIdTokenAsync(accountId, sessionId);

        using var response = await http.SendAsync(
            StandardEndRequest(StandardEndPath(idToken, RegisteredPostLogoutUri, State), cookieValue),
            TestContext.Current.CancellationToken);

        // The exact registered redirect with the state appended byte-for-byte.
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(
            $"{RegisteredPostLogoutUri}?state={State}",
            response.Headers.Location!.ToString());
        AssertBrowserSecurityHeaders(response);
        AssertCookieDeleted(response);
        Assert.DoesNotContain(
            ReadSetCookies(response),
            cookie => cookie.Contains("management", StringComparison.OrdinalIgnoreCase));

        // EV-06 carried over unchanged: the session is revoked with reason logout and the
        // interactive family is revoked in the same committed unit.
        var session = await GetSessionAsync(sessionId);
        Assert.NotNull(session.RevokedAt);
        Assert.Equal("logout", session.RevocationReason);
        var family = await QueryAsync(async dbContext =>
            await dbContext.RefreshTokens.AsNoTracking()
                .SingleAsync(row => row.Id == familyRootId, TestContext.Current.CancellationToken));
        Assert.True(family.IsRevoked);

        // The staged request is consumed exactly once. The state is deliberately not persisted on
        // the standard route (ADR 0010 stage 4: the caller echoes the validated request value, so
        // the stored column keeps the prepared flow's tighter bound) and the flow marker travels
        // in the staged audit description.
        var row = await QueryAsync(async dbContext =>
            await dbContext.LogoutRequests.AsNoTracking()
                .SingleAsync(r => r.IdentitySessionId == sessionId, TestContext.Current.CancellationToken));
        Assert.NotNull(row.ConsumedAt);
        Assert.Equal(RegisteredPostLogoutUri, row.PostLogoutRedirectUri);
        Assert.Null(row.State);

        // The response and location never carry the hint.
        Assert.DoesNotContain(idToken, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    [Fact]
    public async Task StandardEnd_WithoutAPostLogoutUri_RendersTheLocalCompletionPage()
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, cookieValue) = await LoginAndCaptureSessionAsync(host);
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false
        });
        var idToken = await MintIdTokenAsync(accountId, sessionId);

        using var response = await http.SendAsync(
            StandardEndRequest(StandardEndPath(idToken), cookieValue),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Equal("text/html; charset=utf-8", response.Content.Headers.ContentType?.ToString());
        Assert.Contains("You are signed out", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        AssertCookieDeleted(response);
        var session = await GetSessionAsync(sessionId);
        Assert.NotNull(session.RevokedAt);
    }

    [Fact]
    public async Task StandardEnd_WithoutTheSessionCookie_ConsumesWithoutRevocation()
    {
        // EV-07 carried over unchanged: a missing or foreign cookie consumes the staged request
        // and changes no session, family, or code state — but the committed answer still redirects.
        using var host = CreateLogoutHost();
        var (accountId, sessionId, _) = await LoginAndCaptureSessionAsync(host);
        var familyRootId = await SeedInteractiveFamilyAsync(accountId, sessionId);
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false
        });
        var idToken = await MintIdTokenAsync(accountId, sessionId);

        using var response = await http.SendAsync(
            StandardEndRequest(StandardEndPath(idToken, RegisteredPostLogoutUri, State)),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var session = await GetSessionAsync(sessionId);
        Assert.Null(session.RevokedAt);
        var family = await QueryAsync(async dbContext =>
            await dbContext.RefreshTokens.AsNoTracking()
                .SingleAsync(row => row.Id == familyRootId, TestContext.Current.CancellationToken));
        Assert.False(family.IsRevoked);
        var row = await QueryAsync(async dbContext =>
            await dbContext.LogoutRequests.AsNoTracking()
                .SingleAsync(r => r.IdentitySessionId == sessionId, TestContext.Current.CancellationToken));
        Assert.NotNull(row.ConsumedAt);
    }

    [Theory]
    [InlineData("wrong-issuer")]
    [InlineData("wrong-audience")]
    [InlineData("foreign-key")]
    [InlineData("missing-sub")]
    [InlineData("missing-sid")]
    [InlineData("iat-too-old")]
    [InlineData("iat-in-the-future")]
    [InlineData("not-a-jwt")]
    public async Task StandardEnd_WithAnInvalidHint_AnswersOneLocal400AndWritesNothing(string variant)
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, cookieValue) = await LoginAndCaptureSessionAsync(host);
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false
        });
        var idToken = await MintIdTokenAsync(accountId, sessionId, variant: variant);

        using var response = await http.SendAsync(
            StandardEndRequest(StandardEndPath(idToken, RegisteredPostLogoutUri), cookieValue),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Contains("Invalid logout request", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.False(await QueryAsync(async dbContext =>
            await dbContext.LogoutRequests.AsNoTracking()
                .AnyAsync(r => r.IdentitySessionId == sessionId, TestContext.Current.CancellationToken)));
        var session = await GetSessionAsync(sessionId);
        Assert.Null(session.RevokedAt);
    }

    [Theory]
    [InlineData("https://bff.logout.test/logged-out/")]
    [InlineData("https://BFF.logout.test/logged-out")]
    [InlineData("https://bff.logout.test/logged-out?extra=1")]
    [InlineData("https://bff.logout.test:8443/logged-out")]
    [InlineData("https://other.test/logged-out")]
    public async Task StandardEnd_WithAnUnregisteredPostLogoutUri_IsRejectedLocally(string uri)
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, cookieValue) = await LoginAndCaptureSessionAsync(host);
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false
        });
        var idToken = await MintIdTokenAsync(accountId, sessionId);

        using var response = await http.SendAsync(
            StandardEndRequest(StandardEndPath(idToken, uri), cookieValue),
            TestContext.Current.CancellationToken);

        // IN-32 carried over: no redirect is ever issued to an unregistered URI, and the request
        // fails closed without consuming or staging anything.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.False(await QueryAsync(async dbContext =>
            await dbContext.LogoutRequests.AsNoTracking()
                .AnyAsync(r => r.IdentitySessionId == sessionId, TestContext.Current.CancellationToken)));
    }

    [Fact]
    public async Task StandardEnd_WithoutAHint_IsRejected()
    {
        using var host = CreateLogoutHost();
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false
        });

        using var response = await http.GetAsync(
            "/oauth2/session/end?state=unhinted-canary-state-0123456789",
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("?id_token_hint=one&id_token_hint=two")]
    [InlineData("?id_token_hint=one&client_id=known-client")]
    [InlineData("?id_token_hint=one&prompt=login")]
    public async Task StandardEnd_WithDuplicatedOrUnknownQueryFields_IsRejected(string query)
    {
        using var host = CreateLogoutHost();
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false
        });

        using var response = await http.GetAsync("/oauth2/session/end" + query, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task StandardEnd_IsAdvertisedByDiscovery()
    {
        using var host = CreateLogoutHost();
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false
        });

        using var response = await http.GetAsync("/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var document = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        var endpoint = document.GetProperty("end_session_endpoint").GetString()!;
        // The origin is request-derived in this in-memory host (no TLS), so only the absolute
        // shape and the exact route are asserted here; the unit tests pin the composed value.
        Assert.EndsWith("/oauth2/session/end", endpoint, StringComparison.Ordinal);
        Assert.Matches("^https?://", endpoint);
    }
}
