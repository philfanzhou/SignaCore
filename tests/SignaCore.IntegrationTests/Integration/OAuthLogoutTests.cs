using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The SQLite HTTP contract of the prepared logout (<c>#68</c>): the <c>IN-30</c>–<c>IN-34</c>
/// preparation over client authentication (including the credential mix, the strict form
/// structure, the <c>IN-31</c> ID-token judgement with its <c>exp</c> exception, the exact
/// <c>IN-32</c> post-logout match, and the <c>IN-33</c> state bound), the <c>IN-35</c>/<c>IN-36</c>
/// browser completion with its single-use five-minute handle, the <c>EV-06</c>/<c>EV-07</c>
/// external-shape equivalence, the corruption and boundary cases, the <c>SC-05</c>/<c>SC-06</c>
/// serial orders against code redemption, the response-header set, the untouched management
/// cookie, and the canary scan. The standard RP-Initiated shape stays unadvertised
/// (<c>AC-10</c>).
/// </summary>
public sealed class OAuthLogoutTests : IClassFixture<IdentityServerFixture>
{
    private const string AppId = "logout-contract-app";
    private const string AppSecret = "logout-contract-secret-canary";
    private const string RegisteredRedirectUri = "https://bff.logout.test/callback?tenant=unit";
    private const string RegisteredPostLogoutUri = "https://bff.logout.test/logged-out";
    private const string State = "logout-canary-state-0123456789";
    private const string Username = "logout_contract_user";
    private const string Password = "LogoutContract123";
    private const string InvalidDescription = "The logout request could not be validated.";
    private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly IdentityServerFixture _fixture;

    public OAuthLogoutTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- Step 1: the preparation contract ----

    [Fact]
    public async Task Prepare_WithAValidHint_ReturnsARelativeLogoutUriAndStoresOnlyTheDigest()
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, _) = await LoginAndCaptureSessionAsync(host);
        using var http = host.CreateClient();

        var idToken = await MintIdTokenAsync(accountId, sessionId);
        var response = await PrepareAsync(
            http,
            [("id_token_hint", idToken), ("post_logout_redirect_uri", RegisteredPostLogoutUri), ("state", State)]);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        var logoutUri = body.GetProperty("logout_uri").GetString()!;
        Assert.StartsWith("/oauth2/logout?logout_handle=", logoutUri, StringComparison.Ordinal);
        Assert.DoesNotContain("://", logoutUri, StringComparison.Ordinal);
        var handle = logoutUri["/oauth2/logout?logout_handle=".Length..];
        Assert.Equal(43, handle.Length);

        // DF-08/DF-10: the validated token is never stored and the row keeps only the digest.
        var row = await QueryAsync(async dbContext =>
            await dbContext.LogoutRequests.AsNoTracking()
                .SingleAsync(r => r.ConsumedAt == null && r.IdentitySessionId == sessionId, TestContext.Current.CancellationToken));
        Assert.Equal(LoginHandleDigest.Compute(handle), row.HandleDigest);
        Assert.Equal(accountId, row.AccountId);
        Assert.Equal(sessionId, row.IdentitySessionId);
        Assert.Equal(RegisteredPostLogoutUri, row.PostLogoutRedirectUri);
        Assert.Equal(State, row.State);
        Assert.Equal(
            row.CreatedAt.AddMinutes(IdentityConstants.LogoutHandleLifetimeMinutes),
            row.ExpiresAt);
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
    public async Task Prepare_WithAnInvalidHint_AnswersOneLocal400AndWritesNothing(string variant)
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, _) = await LoginAndCaptureSessionAsync(host);
        using var http = host.CreateClient();
        var idToken = await MintIdTokenAsync(accountId, sessionId, variant: variant);

        var response = await PrepareAsync(http, [("id_token_hint", idToken)]);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_request", body.GetProperty("error").GetString());
        Assert.Equal(InvalidDescription, body.GetProperty("error_description").GetString());
        Assert.False(await QueryAsync(async dbContext =>
            await dbContext.LogoutRequests.AsNoTracking()
                .AnyAsync(r => r.IdentitySessionId == sessionId, TestContext.Current.CancellationToken)));
    }

    [Fact]
    public async Task Prepare_IgnoresExpiryButNotFreshness()
    {
        // IN-31: an expired ID token with a fresh iat still prepares logout — exp is ignored only
        // here, and the token is still validated in full otherwise.
        using var host = CreateLogoutHost();
        var (accountId, sessionId, _) = await LoginAndCaptureSessionAsync(host);
        using var http = host.CreateClient();
        var idToken = await MintIdTokenAsync(accountId, sessionId, expired: true);

        var response = await PrepareAsync(http, [("id_token_hint", idToken)]);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData("trailing-slash", "https://bff.logout.test/logged-out/")]
    [InlineData("host-case", "https://BFF.logout.test/logged-out")]
    [InlineData("query-differs", "https://bff.logout.test/logged-out?extra=1")]
    [InlineData("port", "https://bff.logout.test:8443/logged-out")]
    [InlineData("unregistered-host", "https://evil.example.net/logged-out")]
    public async Task Prepare_WithAnUnregisteredPostLogoutUri_IsRejectedWithoutARow(string label, string uri)
    {
        _ = label;
        using var host = CreateLogoutHost();
        var (accountId, sessionId, _) = await LoginAndCaptureSessionAsync(host);
        using var http = host.CreateClient();
        var idToken = await MintIdTokenAsync(accountId, sessionId);

        var response = await PrepareAsync(
            http,
            [("id_token_hint", idToken), ("post_logout_redirect_uri", uri)]);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(await QueryAsync(async dbContext =>
            await dbContext.LogoutRequests.AsNoTracking()
                .AnyAsync(r => r.IdentitySessionId == sessionId, TestContext.Current.CancellationToken)));
    }

    [Theory]
    [InlineData("too-short", "short-state")]
    [InlineData("too-long", "logout-state-0123456789abcdef-logout-state-0123456789abcdef-logout-state-0123456789abcdef-logout-state-0123456789abcdef-logout-state-01234")]
    [InlineData("bad-character", "logout state 0123456789abcd!")]
    public async Task Prepare_WithAnInvalidState_IsRejected(string label, string state)
    {
        _ = label;
        using var host = CreateLogoutHost();
        var (accountId, sessionId, _) = await LoginAndCaptureSessionAsync(host);
        using var http = host.CreateClient();
        var idToken = await MintIdTokenAsync(accountId, sessionId);

        var response = await PrepareAsync(
            http, [("id_token_hint", idToken), ("state", state)]);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(await QueryAsync(async dbContext =>
            await dbContext.LogoutRequests.AsNoTracking()
                .AnyAsync(r => r.IdentitySessionId == sessionId, TestContext.Current.CancellationToken)));
    }

    [Fact]
    public async Task Prepare_RejectsUnknownFieldsDuplicateFieldsAndAnOversizedBody()
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, _) = await LoginAndCaptureSessionAsync(host);
        using var http = host.CreateClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader();
        var idToken = await MintIdTokenAsync(accountId, sessionId);

        // Unknown field.
        Assert.Equal(HttpStatusCode.BadRequest, (await SendRawPrepareAsync(
            http,
            $"id_token_hint={idToken}&resource=urn:example:unexpected")).StatusCode);
        // A duplicated known field.
        Assert.Equal(HttpStatusCode.BadRequest, (await SendRawPrepareAsync(
            http,
            $"id_token_hint={idToken}&state={State}&state={State}")).StatusCode);
        // An oversized body: one admitted field padded past the 16 KiB request-size bound; the
        // server answers 413 (the Kestrel size limit) or the local 400 — never a row.
        var oversized = await SendRawPrepareAsync(
            http,
            $"id_token_hint={new string('a', 17 * 1024)}");
        Assert.True(
            oversized.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.RequestEntityTooLarge,
            $"Unexpected status {oversized.StatusCode}");
        Assert.False(await QueryAsync(async dbContext =>
            await dbContext.LogoutRequests.AsNoTracking()
                .AnyAsync(r => r.IdentitySessionId == sessionId, TestContext.Current.CancellationToken)));
    }

    [Fact]
    public async Task Prepare_RejectsTheBasicPlusFormCredentialMix()
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, _) = await LoginAndCaptureSessionAsync(host);
        using var http = host.CreateClient();
        var idToken = await MintIdTokenAsync(accountId, sessionId);

        var response = await SendRawPrepareAsync(
            http,
            $"id_token_hint={idToken}&client_secret=whatever-long-secret-value");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Prepare_WithoutClientAuthentication_IsRejected()
    {
        using var host = CreateLogoutHost();
        using var http = host.CreateClient();
        var response = await http.PostAsync(
            "/oauth2/logout/requests",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["id_token_hint"] = "x" }),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ---- Step 2: the browser completion contract ----

    [Fact]
    public async Task Complete_WithAMatchingCookie_RevokesTheSessionAndTheFamiliesAndRedirects()
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, cookieValue) = await LoginAndCaptureSessionAsync(host);
        var familyRootId = await SeedInteractiveFamilyAsync(accountId, sessionId);
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        });

        var handle = await PrepareHandleAsync(host, accountId, sessionId, withRedirect: true);
        using var request = new HttpRequestMessage(
            HttpMethod.Get, $"/oauth2/logout?logout_handle={handle}");
        request.Headers.TryAddWithoutValidation(
            "Cookie", $"{IdentitySessionDefaults.CookieName}={cookieValue}");
        using var completion = await http.SendAsync(request, TestContext.Current.CancellationToken);

        // EV-06 external shape: the exact registered redirect with the state appended
        // byte-for-byte, and no other query value.
        Assert.Equal(HttpStatusCode.Found, completion.StatusCode);
        Assert.Equal(
            $"{RegisteredPostLogoutUri}?state={State}",
            completion.Headers.Location!.ToString());
        AssertBrowserSecurityHeaders(completion);

        // The identity cookie is deleted; the management cookie is never touched.
        AssertCookieDeleted(completion);
        Assert.DoesNotContain(
            ReadSetCookies(completion),
            cookie => cookie.Contains("management", StringComparison.OrdinalIgnoreCase));

        var session = await GetSessionAsync(sessionId);
        Assert.NotNull(session.RevokedAt);
        Assert.Equal("logout", session.RevocationReason);
        var family = await QueryAsync(async dbContext =>
            await dbContext.RefreshTokens.AsNoTracking()
                .SingleAsync(row => row.Id == familyRootId, TestContext.Current.CancellationToken));
        Assert.True(family.IsRevoked);

        // EV-06 committed exactly one completion audit with bounded ids only.
        var audits = await QueryAsync(async dbContext =>
            await dbContext.AuditLogs.AsNoTracking()
                .Where(log => log.Action == "oidc.logout.completed"
                    && log.Description.Contains(sessionId.ToString("D")))
                .ToListAsync(TestContext.Current.CancellationToken));
        var audit = Assert.Single(audits);
        Assert.Contains("result:revoked", audit.Description, StringComparison.Ordinal);
        Assert.DoesNotContain(handle, audit.Description, StringComparison.Ordinal);
        Assert.DoesNotContain(State, audit.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Complete_WithoutARegisteredUri_ReturnsTheLocalCompletionPage()
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, cookieValue) = await LoginAndCaptureSessionAsync(host);
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        });

        var handle = await PrepareHandleAsync(host, accountId, sessionId, withRedirect: false);
        using var request = new HttpRequestMessage(
            HttpMethod.Get, $"/oauth2/logout?logout_handle={handle}");
        request.Headers.TryAddWithoutValidation(
            "Cookie", $"{IdentitySessionDefaults.CookieName}={cookieValue}");
        using var completion = await http.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, completion.StatusCode);
        Assert.Null(completion.Headers.Location);
        Assert.Equal("text/html", completion.Content.Headers.ContentType?.MediaType);
        AssertBrowserSecurityHeaders(completion);
        AssertCookieDeleted(completion);

        var session = await GetSessionAsync(sessionId);
        Assert.NotNull(session.RevokedAt);
        Assert.Equal("logout", session.RevocationReason);
    }

    [Fact]
    public async Task Complete_WithoutACookie_ConsumesOnlyAndAnswersWithTheSameExternalShape()
    {
        // EV-06 and EV-07 for two identically prepared requests answer with byte-for-byte the
        // same external shape — no session-state oracle — while only the cookie path revokes.
        using var host = CreateLogoutHost();
        var (accountId, sessionId, cookieValue) = await LoginAndCaptureSessionAsync(host);
        using var cookieClient = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        });
        using var cookielessClient = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        var cookieHandle = await PrepareHandleAsync(host, accountId, sessionId, withRedirect: true);
        var cookielessHandle = await PrepareHandleAsync(host, accountId, sessionId, withRedirect: true);

        using var cookieRequest = new HttpRequestMessage(
            HttpMethod.Get, $"/oauth2/logout?logout_handle={cookieHandle}");
        cookieRequest.Headers.TryAddWithoutValidation(
            "Cookie", $"{IdentitySessionDefaults.CookieName}={cookieValue}");
        using var cookieCompletion = await cookieClient.SendAsync(cookieRequest, TestContext.Current.CancellationToken);

        using var cookielessResponse = await cookielessClient.GetAsync(
            $"/oauth2/logout?logout_handle={cookielessHandle}", TestContext.Current.CancellationToken);

        Assert.Equal(cookieCompletion.StatusCode, cookielessResponse.StatusCode);
        Assert.Equal(
            cookieCompletion.Headers.Location?.ToString(),
            cookielessResponse.Headers.Location?.ToString());

        // Only the EV-06 path revoked; the EV-07 path consumed without any state write.
        var session = await GetSessionAsync(sessionId);
        Assert.NotNull(session.RevokedAt);

        var audits = await QueryAsync(async dbContext =>
            await dbContext.AuditLogs.AsNoTracking()
                .Where(log => log.Action == "oidc.logout.completed"
                    && log.Description.Contains(sessionId.ToString("D")))
                .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal(2, audits.Count);
        Assert.Contains(audits, audit =>
            audit.Description.Contains("result:revoked", StringComparison.Ordinal));
        Assert.Contains(audits, audit =>
            audit.Description.Contains("result:no_session_write", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Complete_WithAMismatchedCookie_FollowsEv07AndLeavesThatSessionAlone()
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, _) = await LoginAndCaptureSessionAsync(host);
        var (_, otherSessionId, otherCookie) = await LoginAndCaptureSessionAsync(host);
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        });

        var handle = await PrepareHandleAsync(host, accountId, sessionId, withRedirect: false);
        using var request = new HttpRequestMessage(
            HttpMethod.Get, $"/oauth2/logout?logout_handle={handle}");
        request.Headers.TryAddWithoutValidation(
            "Cookie", $"{IdentitySessionDefaults.CookieName}={otherCookie}");
        using var completion = await http.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, completion.StatusCode);

        // EV-07 for the named session and no revocation of either session.
        Assert.Null((await GetSessionAsync(sessionId)).RevokedAt);
        Assert.Null((await GetSessionAsync(otherSessionId)).RevokedAt);
    }

    [Fact]
    public async Task Complete_Twice_TheSecondUseOfOneHandleIsALocal400()
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, cookieValue) = await LoginAndCaptureSessionAsync(host);
        using var http = host.CreateClient();
        http.DefaultRequestHeaders.Add(
            "Cookie", $"{IdentitySessionDefaults.CookieName}={cookieValue}");

        var handle = await PrepareHandleAsync(host, accountId, sessionId, withRedirect: false);
        using var first = await http.GetAsync($"/oauth2/logout?logout_handle={handle}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        using var second = await http.GetAsync($"/oauth2/logout?logout_handle={handle}", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, second.StatusCode);
        Assert.Null(second.Headers.Location);
        Assert.Equal(1, await QueryAsync(async dbContext =>
            await dbContext.LogoutRequests.AsNoTracking()
                .CountAsync(r => r.IdentitySessionId == sessionId, TestContext.Current.CancellationToken)));
    }

    [Fact]
    public async Task Complete_WithAnExpiredHandle_IsALocal400()
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, cookieValue) = await LoginAndCaptureSessionAsync(host);
        using var http = host.CreateClient();
        http.DefaultRequestHeaders.Add(
            "Cookie", $"{IdentitySessionDefaults.CookieName}={cookieValue}");

        var handle = await PrepareHandleAsync(host, accountId, sessionId, withRedirect: false);
        // The boundary is inclusive: the operation instant at the deadline is already expired.
        await ExecuteAsync(async dbContext =>
        {
            await dbContext.LogoutRequests
                .Where(row => row.HandleDigest == LoginHandleDigest.Compute(handle))
                .ExecuteUpdateAsync(setters => setters.SetProperty(
                    row => row.ExpiresAt,
                    DateTimeOffset.UtcNow.AddSeconds(-1)),
                    TestContext.Current.CancellationToken);
        });

        using var completion = await http.GetAsync($"/oauth2/logout?logout_handle={handle}", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, completion.StatusCode);
        Assert.Null(completion.Headers.Location);
        var session = await GetSessionAsync(sessionId);
        Assert.Null(session.RevokedAt);
    }

    [Theory]
    [InlineData("missing", "/oauth2/logout")]
    [InlineData("malformed", "/oauth2/logout?logout_handle=short")]
    [InlineData("bad-character", "/oauth2/logout?logout_handle=abc!def")]
    [InlineData("extra-query-field", "/oauth2/logout?logout_handle=abc&client_id=x")]
    public async Task Complete_WithAnUnusableQuery_AnswersOneLocal400WithNoWrite(string label, string url)
    {
        _ = label;
        var consumedBefore = await QueryAsync(async dbContext =>
            await dbContext.LogoutRequests.AsNoTracking()
                .CountAsync(row => row.ConsumedAt != null, TestContext.Current.CancellationToken));
        using var host = CreateLogoutHost();
        using var http = host.CreateClient();
        using var completion = await http.GetAsync(url, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, completion.StatusCode);
        Assert.Null(completion.Headers.Location);
        AssertBrowserSecurityHeaders(completion);
        Assert.Equal(consumedBefore, await QueryAsync(async dbContext =>
            await dbContext.LogoutRequests.AsNoTracking()
                .CountAsync(row => row.ConsumedAt != null, TestContext.Current.CancellationToken)));
    }

    [Fact]
    public async Task Complete_WithACorruptSessionAccountBinding_IsALocal400WithZeroWrites()
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, _) = await LoginAndCaptureSessionAsync(host);
        using var http = host.CreateClient();

        // A row whose stored sub cannot belong to the live session row under the stored sid.
        var handle = await PrepareHandleAsync(host, accountId, sessionId, withRedirect: false);
        await ExecuteAsync(async dbContext =>
        {
            await dbContext.LogoutRequests
                .Where(row => row.HandleDigest == LoginHandleDigest.Compute(handle))
                .ExecuteUpdateAsync(setters => setters.SetProperty(
                    row => row.AccountId, Guid.NewGuid()),
                    TestContext.Current.CancellationToken);
        });

        using var completion = await http.GetAsync($"/oauth2/logout?logout_handle={handle}", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, completion.StatusCode);
        Assert.Null(completion.Headers.Location);
        var row = await QueryAsync(async dbContext =>
            await dbContext.LogoutRequests.AsNoTracking()
                .SingleAsync(r => r.HandleDigest == LoginHandleDigest.Compute(handle), TestContext.Current.CancellationToken));
        Assert.Null(row.ConsumedAt);
        Assert.Null((await GetSessionAsync(sessionId)).RevokedAt);
    }

    // ---- SC-05 / SC-06: the serial orders against code redemption ----

    [Fact]
    public async Task LogoutFirst_LeavesTheBoundCodeUnconsumedAndFailingWithoutAReplayAudit()
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, cookieValue) = await LoginAndCaptureSessionAsync(host);
        var code = await SeedCodeAsync(accountId, sessionId);
        using var http = host.CreateClient();
        http.DefaultRequestHeaders.Add(
            "Cookie", $"{IdentitySessionDefaults.CookieName}={cookieValue}");

        var handle = await PrepareHandleAsync(host, accountId, sessionId, withRedirect: false);
        using var completion = await http.GetAsync($"/oauth2/logout?logout_handle={handle}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, completion.StatusCode);

        // SC-05: redemption after logout fails the live-session check with the generic
        // invalid_grant, consumes nothing, and writes no replay audit.
        using var redeem = host.CreateClient();
        redeem.DefaultRequestHeaders.Authorization = BasicHeader();
        var response = await redeem.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = RegisteredRedirectUri,
                ["code_verifier"] = Verifier
            }),
            TestContext.Current.CancellationToken);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
        var codeRow = await QueryAsync(async dbContext =>
            await dbContext.AuthorizationCodes.AsNoTracking()
                .SingleAsync(row => row.CodeDigest == AuthorizationCodeDigest.Compute(code), TestContext.Current.CancellationToken));
        Assert.Null(codeRow.ConsumedAt);
        Assert.False(await QueryAsync(async dbContext =>
            await dbContext.AuditLogs.AsNoTracking()
                .AnyAsync(log => log.Action == "oidc.code.replayed", TestContext.Current.CancellationToken)));
    }

    [Fact]
    public async Task RedeemFirst_ThenLogout_RevokesTheSessionAndTheBoundFamily()
    {
        using var host = CreateLogoutHost();
        var (accountId, sessionId, cookieValue) = await LoginAndCaptureSessionAsync(host);
        var familyRootId = await SeedInteractiveFamilyAsync(accountId, sessionId);
        var code = await SeedCodeAsync(accountId, sessionId);

        using var redeem = host.CreateClient();
        redeem.DefaultRequestHeaders.Authorization = BasicHeader();
        var response = await redeem.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = RegisteredRedirectUri,
                ["code_verifier"] = Verifier
            }),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var http = host.CreateClient();
        http.DefaultRequestHeaders.Add(
            "Cookie", $"{IdentitySessionDefaults.CookieName}={cookieValue}");
        var handle = await PrepareHandleAsync(host, accountId, sessionId, withRedirect: false);
        using var completion = await http.GetAsync($"/oauth2/logout?logout_handle={handle}", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, completion.StatusCode);
        var session = await GetSessionAsync(sessionId);
        Assert.NotNull(session.RevokedAt);
        Assert.Equal("logout", session.RevocationReason);
        var family = await QueryAsync(async dbContext =>
            await dbContext.RefreshTokens.AsNoTracking()
                .SingleAsync(row => row.Id == familyRootId, TestContext.Current.CancellationToken));
        Assert.True(family.IsRevoked);
    }

    // ---- AC-10 and the sensitive-value canary ----

    [Fact]
    public async Task Discovery_DoesNotAdvertiseEndSessionEndpoint()
    {
        using var host = CreateLogoutHost();
        using var http = host.CreateClient();
        var document = await http.GetFromJsonAsync<JsonElement>(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        Assert.False(document.TryGetProperty("end_session_endpoint", out _));
    }

    [Fact]
    public async Task SecretsNeverReachLogsOrAudits()
    {
        var capture = new CapturingLoggerProvider();
        using var factory = _fixture.WithTestServices(services =>
        {
            services.RemoveAll<ILoggerFactory>();
            services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
            {
                logging.AddProvider(capture);
                logging.SetMinimumLevel(LogLevel.Information);
                logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
                logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);
            }));
        });
        var (accountId, sessionId, cookieValue) = await LoginAndCaptureSessionAsync(factory);
        var idToken = await MintIdTokenAsync(accountId, sessionId);

        string handle;
        using (var client = factory.CreateClient())
        {
            client.DefaultRequestHeaders.Authorization = BasicHeader();
            using var prepared = await client.PostAsync(
                "/oauth2/logout/requests",
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["id_token_hint"] = idToken,
                    ["post_logout_redirect_uri"] = RegisteredPostLogoutUri,
                    ["state"] = State
                }),
                TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, prepared.StatusCode);
            var body = await prepared.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
            handle = body.GetProperty("logout_uri").GetString()!["/oauth2/logout?logout_handle=".Length..];
        }

        using (var browser = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        }))
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"/oauth2/logout?logout_handle={handle}");
            request.Headers.TryAddWithoutValidation(
                "Cookie", $"{IdentitySessionDefaults.CookieName}={cookieValue}");
            using var completion = await browser.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Found, completion.StatusCode);
        }

        // The capture is proven non-empty through the logout's own Information lines.
        Assert.Contains(capture.Messages, message =>
            message.Contains("Logout request prepared", StringComparison.Ordinal)
            || message.Contains("Logout completed", StringComparison.Ordinal));

        var dump = string.Join(Environment.NewLine, capture.Messages);
        Assert.DoesNotContain(idToken, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(handle, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(State, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(AppSecret, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(cookieValue, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(RegisteredPostLogoutUri, dump, StringComparison.Ordinal);
    }

    // ---- Helpers ----

    /// <summary>
    /// A fresh host per test: the global per-IP rate limiter is per-host state, and one class of
    /// full login runs would exhaust the shared host's window. The database stays shared.
    /// </summary>
    private WebApplicationFactory<Program> CreateLogoutHost() =>
        _fixture.WithTestServices(_ => { });

    private static AuthenticationHeaderValue BasicHeader() =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{AppId}:{AppSecret}")));

    private async Task<Guid> SeedLogoutAppAsync()
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var application = await dbContext.AppRegistrations
            .FirstOrDefaultAsync(app => app.AppId == AppId, TestContext.Current.CancellationToken);
        if (application is null)
        {
            application = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = AppId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword(AppSecret),
                AppName = "Logout Contract App",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.PerApplication,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = "openid profile",
                AllowRefreshToken = false
            };
            dbContext.AppRegistrations.Add(application);
        }

        application.IsActive = true;
        application.AllowAuthorizationCode = true;
        application.AllowedScopes = "openid profile";
        application.AudienceMode = AudienceMode.PerApplication;
        application.ClientType = OidcClientType.Confidential;

        var registrations = dbContext.AppRedirectUris
            .Where(registration => registration.AppRegistrationId == application.Id);
        dbContext.AppRedirectUris.RemoveRange(registrations);
        dbContext.AppRedirectUris.Add(new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = application.Id,
            Kind = RedirectUriKind.Redirect,
            CanonicalUri = RegisteredRedirectUri
        });
        dbContext.AppRedirectUris.Add(new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = application.Id,
            Kind = RedirectUriKind.PostLogout,
            CanonicalUri = RegisteredPostLogoutUri
        });
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        return application.Id;
    }

    /// <summary>
    /// Completes a real authorize + login run through the shared success application and returns
    /// the account id, the created session id, and the live identity-cookie value.
    /// </summary>
    private async Task<(Guid AccountId, Guid SessionId, string CookieValue)> LoginAndCaptureSessionAsync(
        WebApplicationFactory<Program> host)
    {
        var username = $"{Username}_{Guid.NewGuid():N}";
        var accountId = await OAuthLoginTestSupport.SeedUserAsync(_fixture.Services, username, Password);
        using var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        });
        var cookieValue = await OAuthLoginTestSupport.CompleteSuccessLoginAndGetIdentityCookieValueAsync(
            _fixture.Services, client, username, Password);

        var sessionId = await QueryAsync(async dbContext =>
            await dbContext.IdentitySessions.AsNoTracking()
                .Where(session => session.AccountId == accountId)
                .OrderByDescending(session => session.AuthTime)
                .Select(session => session.Id)
                .FirstAsync(TestContext.Current.CancellationToken));
        return (accountId, sessionId, cookieValue);
    }

    private async Task<string> MintIdTokenAsync(
        Guid accountId,
        Guid sessionId,
        string variant = "valid",
        bool expired = false)
    {
        using var scope = _fixture.Services.CreateScope();
        var keyManager = scope.ServiceProvider.GetRequiredService<IKeyManager>();
        var issuer = scope.ServiceProvider.GetRequiredService<JwtOptions>().Issuer;

        if (variant == "not-a-jwt")
        {
            return "this-is-not-a-compact-jws";
        }

        var claims = new List<Claim>();
        if (variant != "missing-sub")
        {
            claims.Add(new Claim("sub", accountId.ToString("D")));
        }

        if (variant != "missing-sid")
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Sid, sessionId.ToString("D")));
        }

        var issuedAt = variant switch
        {
            "iat-too-old" => DateTime.UtcNow.AddHours(IdentityConstants.LogoutHintMaximumAgeHours + 1),
            "iat-in-the-future" => DateTime.UtcNow.AddHours(2),
            _ => DateTime.UtcNow.AddMinutes(-5)
        };

        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            new JwtHeader(new SigningCredentials(
                variant == "foreign-key"
                    ? new RsaSecurityKey(System.Security.Cryptography.RSA.Create(2048)) { KeyId = "foreign-key" }
                    : keyManager.GetCurrentKey(),
                SecurityAlgorithms.RsaSha256)),
            new JwtPayload(
                issuer: variant == "wrong-issuer" ? "https://attacker.test" : issuer,
                audience: variant == "wrong-audience" ? "another-client" : AppId,
                claims: claims,
                notBefore: null,
                expires: expired ? DateTime.UtcNow.AddMinutes(-1) : null,
                issuedAt: issuedAt)));
    }

    private async Task<string> PrepareHandleAsync(
        WebApplicationFactory<Program> host,
        Guid accountId,
        Guid sessionId,
        bool withRedirect)
    {
        // The prepare endpoint's client authentication needs the application row; seed it here so
        // the helper stands on its own under any test-case order.
        await SeedLogoutAppAsync();
        using var http = host.CreateClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader();
        var idToken = await MintIdTokenAsync(accountId, sessionId);
        var fields = new List<KeyValuePair<string, string>>
        {
            new("id_token_hint", idToken)
        };
        if (withRedirect)
        {
            fields.Add(new KeyValuePair<string, string>("post_logout_redirect_uri", RegisteredPostLogoutUri));
            fields.Add(new KeyValuePair<string, string>("state", State));
        }

        var response = await http.PostAsync(
            "/oauth2/logout/requests",
            new FormUrlEncodedContent(fields),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);
        return body.GetProperty("logout_uri").GetString()!["/oauth2/logout?logout_handle=".Length..];
    }

    private async Task<HttpResponseMessage> PrepareAsync(
        HttpClient http,
        IReadOnlyList<(string Name, string Value)> fields)
    {
        var body = string.Join("&", fields.Select(field =>
            $"{field.Name}={Uri.EscapeDataString(field.Value)}"));
        return await SendRawPrepareAsync(http, body);
    }

    private async Task<HttpResponseMessage> SendRawPrepareAsync(HttpClient http, string rawBody)
    {
        await SeedLogoutAppAsync();
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            "/oauth2/logout/requests")
        {
            Content = new StringContent(
                rawBody, Encoding.UTF8, "application/x-www-form-urlencoded")
        };
        request.Headers.Authorization = BasicHeader();
        return await http.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private async Task<Guid> SeedInteractiveFamilyAsync(Guid accountId, Guid sessionId)
    {
        var now = DateTimeOffset.UtcNow;
        var rootId = Guid.NewGuid();
        await ExecuteAsync(async dbContext =>
        {
            dbContext.RefreshTokens.Add(new RefreshTokenEntity
            {
                Id = rootId,
                FamilyId = rootId,
                AccountId = accountId,
                TokenValue = RefreshTokenDigest.Compute("logout-contract-family-" + sessionId.ToString("N")),
                CreatedAt = now,
                ExpiresAt = now.AddDays(7),
                AppId = AppId,
                IdentitySessionId = sessionId,
                Scope = "openid profile offline_access",
                AuthTime = now.AddMinutes(-10)
            });
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        });
        return rootId;
    }

    private async Task<string> SeedCodeAsync(Guid accountId, Guid sessionId)
    {
        var applicationRowId = await SeedLogoutAppAsync();
        using var scope = _fixture.Services.CreateScope();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var sessions = new IdentitySessionStore(
            scope.ServiceProvider.GetRequiredService<IIdentitySessionRepository>(), unitOfWork);
        var codes = new AuthorizationCodeStore(
            scope.ServiceProvider.GetRequiredService<IAuthorizationCodeRepository>(), unitOfWork);
        var lookup = await sessions.GetAsync(sessionId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
        var creation = await codes.CreateAsync(
            lookup.Session!,
            new AuthorizationCodeBinding(applicationRowId, RegisteredRedirectUri, "openid profile", "logout-nonce", Challenge),
            DateTimeOffset.UtcNow,
            TestContext.Current.CancellationToken);
        return creation.Code;
    }

    private async Task<IdentitySessionEntity> GetSessionAsync(Guid sessionId) =>
        await QueryAsync(async dbContext =>
            await dbContext.IdentitySessions.AsNoTracking()
                .SingleAsync(row => row.Id == sessionId, TestContext.Current.CancellationToken));

    private async Task<TResult> QueryAsync<TResult>(Func<IdentityDbContext, Task<TResult>> query)
    {
        using var scope = _fixture.Services.CreateScope();
        return await query(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }

    private async Task ExecuteAsync(Func<IdentityDbContext, Task> action)
    {
        using var scope = _fixture.Services.CreateScope();
        await action(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }

    private static void AssertBrowserSecurityHeaders(HttpResponseMessage response)
    {
        Assert.Contains("no-store", response.Headers.CacheControl?.ToString() ?? string.Empty, StringComparison.Ordinal);
        Assert.Contains("no-cache", response.Headers.Pragma.ToString(), StringComparison.Ordinal);
        Assert.Contains("no-referrer", response.Headers.GetValues("Referrer-Policy").Single(), StringComparison.Ordinal);
        Assert.Contains("DENY", response.Headers.GetValues("X-Frame-Options").Single(), StringComparison.Ordinal);
        Assert.Equal(
            OAuthLoginTestSupport.ExpectedContentSecurityPolicy,
            response.Headers.GetValues("Content-Security-Policy").Single());
    }

    private static void AssertCookieDeleted(HttpResponseMessage response)
    {
        var setCookies = ReadSetCookies(response);
        var deleted = setCookies.FirstOrDefault(cookie =>
            cookie.StartsWith(IdentitySessionDefaults.CookieName, StringComparison.Ordinal));
        Assert.NotNull(deleted);
        Assert.Contains("expires=", deleted, StringComparison.OrdinalIgnoreCase);
    }

    private static List<string> ReadSetCookies(HttpResponseMessage response) =>
        response.Headers.NonValidated.TryGetValues("Set-Cookie", out var values)
            ? values.ToList()
            : [];

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<string> _messages = new();

        public IReadOnlyCollection<string> Messages => _messages;

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(CapturingLoggerProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                owner._messages.Enqueue(formatter(state, exception));
        }
    }
}
