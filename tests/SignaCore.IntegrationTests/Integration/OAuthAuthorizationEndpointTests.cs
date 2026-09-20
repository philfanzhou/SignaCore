using System.Data.Common;
using System.IO;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Validators;
using SignaCore.Host;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Wire contract of <c>GET /oauth2/authorize</c>. The endpoint takes attacker-controlled URL input,
/// so these tests assert the two properties that matter before any protocol detail: an unverified
/// client or redirect URI never produces a <c>Location</c>, and the local answer is the same for
/// every reason it could have been rejected.
/// <para>
/// This slice issues no authorization code, so a fully valid request is answered locally as well.
/// </para>
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public class OAuthAuthorizationEndpointTests : IClassFixture<IdentityServerFixture>
{
    private const string InteractiveAppId = "authorize-contract-app";
    private const string InactiveAppId = "authorize-inactive-app";
    private const string NonInteractiveAppId = "authorize-plain-app";
    private const string RegisteredUri = "https://bff.authorize.test/callback";
    private const string RegisteredUriWithQuery = "https://bff.authorize.test/cb?tenant=blue";
    private const string PostLogoutUri = "https://bff.authorize.test/signed-out";

    private const string CanaryState = "canary-state-abcdefghij";
    private const string CanaryNonce = "canary-nonce-abcdefghij";
    private const string CanaryChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static readonly SemaphoreSlim SeedLock = new(1, 1);
    private static bool _seeded;

    private readonly IdentityServerFixture _fixture;

    public OAuthAuthorizationEndpointTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- Stage 1: parameter cardinality ----

    [Theory]
    [InlineData("client_id")]
    [InlineData("redirect_uri")]
    public async Task DuplicateTrustParameter_IsALocalErrorWithNoLocation(string name)
    {
        var response = await GetAsync(Valid().Duplicate(name));

        await AssertLocalErrorAsync(response);
    }

    [Fact]
    public async Task DuplicateClientIdAndRedirectUri_IsALocalErrorWithNoLocation()
    {
        var response = await GetAsync(Valid().Duplicate("client_id").Duplicate("redirect_uri"));

        await AssertLocalErrorAsync(response);
    }

    // ---- Stage 2: current application ----

    /// <summary>
    /// Unknown, inactive, and non-interactive clients must be indistinguishable: the response is
    /// compared byte for byte, not merely by status code.
    /// </summary>
    [Fact]
    public async Task UnknownInactiveAndNonInteractiveClients_ProduceIdenticalLocalResponses()
    {
        var unknown = await GetAsync(Valid().With("client_id", "no-such-client"));
        var inactive = await GetAsync(Valid().With("client_id", InactiveAppId));
        var nonInteractive = await GetAsync(Valid().With("client_id", NonInteractiveAppId));
        var unmatchedUri = await GetAsync(Valid().With("redirect_uri", "https://attacker.test/callback"));

        var bodies = new List<string>();
        foreach (var response in new[] { unknown, inactive, nonInteractive, unmatchedUri })
        {
            bodies.Add(await AssertLocalErrorAsync(response));
        }

        Assert.All(bodies, body => Assert.Equal(bodies[0], body));
    }

    // ---- Stage 3: exact registered redirect URI ----

    [Theory]
    [InlineData("https://bff.authorize.test/callback/")]
    [InlineData("https://bff.authorize.test/CALLBACK")]
    [InlineData("https://bff.authorize.test:443/callback")]
    [InlineData("https://bff.authorize.test/callback?x=1")]
    [InlineData("https://bff.authorize.test.attacker.test/callback")]
    [InlineData("https://bff.authorize.test/signed-out")]
    public async Task RedirectUriThatIsNotTheRegisteredString_IsALocalErrorThatNeverEchoesIt(string submitted)
    {
        var response = await GetAsync(Valid().With("redirect_uri", submitted));

        var body = await AssertLocalErrorAsync(response);
        Assert.DoesNotContain(submitted, body, StringComparison.Ordinal);
        Assert.DoesNotContain("attacker.test", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingRedirectUri_IsALocalError()
    {
        await AssertLocalErrorAsync(await GetAsync(Valid().Without("redirect_uri")));
    }

    // ---- Stage 4: protocol errors reach the verified destination ----

    [Theory]
    [InlineData(null)]
    [InlineData("token")]
    public async Task InvalidResponseType_RedirectsWithUnsupportedResponseType(string? responseType)
    {
        var query = responseType is null
            ? Valid().Without("response_type")
            : Valid().With("response_type", responseType);

        var parameters = AssertSafeRedirect(await GetAsync(query));

        Assert.Equal(OAuthErrorCodes.UnsupportedResponseType, parameters["error"]);
        Assert.Equal(CanaryState, parameters["state"]);
        Assert.Equal(Issuer, parameters["iss"]);
        Assert.False(string.IsNullOrWhiteSpace(parameters["error_description"]));
    }

    [Theory]
    [InlineData("profile")]
    [InlineData("openid unknown_scope")]
    [InlineData("openid openid")]
    [InlineData("openid offline_access")]
    public async Task InvalidScope_RedirectsWithInvalidScope(string scope)
    {
        var parameters = AssertSafeRedirect(await GetAsync(Valid().With("scope", scope)));

        Assert.Equal(OAuthErrorCodes.InvalidScope, parameters["error"]);
        Assert.Equal(CanaryState, parameters["state"]);
    }

    [Fact]
    public async Task OverlongScope_RedirectsWithInvalidScope()
    {
        var parameters = AssertSafeRedirect(
            await GetAsync(Valid().With("scope", "openid " + new string('a', 200))));

        Assert.Equal(OAuthErrorCodes.InvalidScope, parameters["error"]);
    }

    [Theory]
    [InlineData("state", null)]
    [InlineData("state", "short")]
    [InlineData("nonce", null)]
    [InlineData("nonce", "short")]
    public async Task InvalidStateOrNonce_RedirectsWithInvalidRequest(string name, string? value)
    {
        var query = value is null ? Valid().Without(name) : Valid().With(name, value);

        var parameters = AssertSafeRedirect(await GetAsync(query));

        Assert.Equal(OAuthErrorCodes.InvalidRequest, parameters["error"]);
        if (name == "state")
        {
            Assert.Null(parameters["state"]);
        }
    }

    [Theory]
    [InlineData("code_challenge_method", null)]
    [InlineData("code_challenge_method", "plain")]
    [InlineData("code_challenge_method", "S512")]
    [InlineData("code_challenge", null)]
    [InlineData("code_challenge", "tooshort")]
    [InlineData("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c.")]
    [InlineData("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c~")]
    [InlineData("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c=")]
    public async Task InvalidPkce_RedirectsWithInvalidRequest(string name, string? value)
    {
        var query = value is null ? Valid().Without(name) : Valid().With(name, value);

        var parameters = AssertSafeRedirect(await GetAsync(query));

        Assert.Equal(OAuthErrorCodes.InvalidRequest, parameters["error"]);
    }

    [Theory]
    [InlineData("prompt", "login", OAuthErrorCodes.InvalidRequest)]
    [InlineData("max_age", "0", OAuthErrorCodes.InvalidRequest)]
    [InlineData("acr_values", "urn:example", OAuthErrorCodes.InvalidRequest)]
    [InlineData("response_mode", "form_post", OAuthErrorCodes.InvalidRequest)]
    [InlineData("request", "eyJhbGciOiJub25lIn0", OAuthErrorCodes.RequestNotSupported)]
    [InlineData("request_uri", "https://attacker.test/req", OAuthErrorCodes.RequestUriNotSupported)]
    [InlineData("registration", "{}", OAuthErrorCodes.RegistrationNotSupported)]
    public async Task RejectedField_RedirectsWithItsOwnError(string name, string value, string expectedError)
    {
        var parameters = AssertSafeRedirect(await GetAsync(Valid().With(name, value)));

        Assert.Equal(expectedError, parameters["error"]);
        Assert.Equal(CanaryState, parameters["state"]);
    }

    [Fact]
    public async Task UnknownField_IsIgnoredAndDoesNotChangeTheOutcome()
    {
        var response = await GetAsync(Valid().With("ui_locales", "en-US").With("display", "page"));

        var handle = await AssertLoginRedirectAsync(response);
        Assert.NotEqual(string.Empty, handle);
    }

    [Fact]
    public async Task DuplicateProtocolField_RedirectsWithInvalidRequest()
    {
        var parameters = AssertSafeRedirect(await GetAsync(Valid().Duplicate("scope")));

        Assert.Equal(OAuthErrorCodes.InvalidRequest, parameters["error"]);
    }

    // ---- Ordering counter-proof ----

    /// <summary>
    /// Both requests are invalid twice: once at a stage that decides redirect trust and once at a
    /// later protocol stage. If the implementation ever evaluated the protocol field first, these
    /// would answer with a 302 to an unverified destination.
    /// </summary>
    [Fact]
    public async Task UnmatchedRedirectUriWithInvalidScope_IsLocalRatherThanARedirect()
    {
        var response = await GetAsync(Valid()
            .With("redirect_uri", "https://attacker.test/callback")
            .With("scope", "openid unknown_scope"));

        await AssertLocalErrorAsync(response);
    }

    [Fact]
    public async Task UnknownClientWithInvalidState_IsLocalRatherThanARedirect()
    {
        var response = await GetAsync(Valid()
            .With("client_id", "no-such-client")
            .With("state", "short"));

        await AssertLocalErrorAsync(response);
    }

    // ---- Response shape ----

    [Theory]
    [InlineData("Mixed.Case~With-All_Unreserved.0123456789")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("~.-_State0123456789abc")]
    public async Task ValidState_IsEchoedByteForByte(string state)
    {
        var parameters = AssertSafeRedirect(
            await GetAsync(Valid().With("state", state).With("response_type", "token")));

        Assert.Equal(state, parameters["state"]);
    }

    /// <summary>A registered URI that already carries a query keeps it and gains the error fields.</summary>
    [Fact]
    public async Task RegisteredUriWithAQuery_KeepsItAndAppendsTheErrorFields()
    {
        var response = await GetAsync(Valid()
            .With("redirect_uri", RegisteredUriWithQuery)
            .With("response_type", "token"));

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith(RegisteredUriWithQuery + "&", location, StringComparison.Ordinal);
        var parameters = HttpUtility.ParseQueryString(new Uri(location).Query);
        Assert.Equal("blue", parameters["tenant"]);
        Assert.Equal(OAuthErrorCodes.UnsupportedResponseType, parameters["error"]);
    }

    [Fact]
    public async Task ValidRequest_PersistsTheContinuationAndRedirectsToTheLoginPage()
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var application = await dbContext.AppRegistrations.AsNoTracking()
            .SingleAsync(app => app.AppId == InteractiveAppId, TestContext.Current.CancellationToken);
        var acceptedBefore = await dbContext.AuditLogs.AsNoTracking()
            .LongCountAsync(
                log => log.Action == "oidc.authorize.validated"
                    && log.Description == "accepted"
                    && log.TargetId == application.Id.ToString("D"),
                TestContext.Current.CancellationToken);

        var response = await GetAsync(Valid());

        var handle = await AssertLoginRedirectAsync(response);

        // The handle opens the login form on the same host, and exactly one continuation row with
        // the validated snapshot plus exactly one accepted audit row exist.
        using (var http = _fixture.CreateNonRedirectingHttpClient())
        {
            using var loginPage = await http.GetAsync(
                "/oauth2/login?login_handle=" + Uri.EscapeDataString(handle),
                TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, loginPage.StatusCode);
        }

        scope.Dispose();
        using var verifyScope = _fixture.Services.CreateScope();
        var verifyContext = verifyScope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var digest = LoginHandleDigest.Compute(handle);
        var continuation = await verifyContext.AuthorizationRequests.AsNoTracking()
            .SingleAsync(row => row.HandleDigest == digest, TestContext.Current.CancellationToken);
        Assert.Equal(application.Id, continuation.AppRegistrationId);
        Assert.Equal(RegisteredUri, continuation.RedirectUri);
        Assert.Equal("openid profile", continuation.Scope);
        Assert.Equal(CanaryState, continuation.State);
        Assert.Equal(CanaryNonce, continuation.Nonce);
        Assert.Equal(CanaryChallenge, continuation.CodeChallenge);
        Assert.Equal(
            IdentityConstants.LoginHandleLifetimeMinutes,
            (continuation.ExpiresAt - continuation.CreatedAt).TotalMinutes);
        Assert.Null(continuation.ConsumedAt);

        var acceptedAfter = await verifyContext.AuditLogs.AsNoTracking()
            .LongCountAsync(
                log => log.Action == "oidc.authorize.validated"
                    && log.Description == "accepted"
                    && log.TargetId == application.Id.ToString("D"),
                TestContext.Current.CancellationToken);
        Assert.Equal(acceptedBefore + 1, acceptedAfter);
    }

    [Fact]
    public async Task EveryResponse_CarriesTheBrowserSecurityHeaders()
    {
        var local = await GetAsync(Valid().With("client_id", "no-such-client"));
        var redirected = await GetAsync(Valid().With("response_type", "token"));
        var accepted = await GetAsync(Valid());

        foreach (var response in new[] { local, redirected, accepted })
        {
            AssertBrowserSecurityHeaders(response);
        }
    }

    [Fact]
    public async Task PostToTheAuthorizationEndpoint_IsNotSupported()
    {
        using var http = _fixture.CreateNonRedirectingHttpClient();
        await SeedAsync();

        var response = await http.PostAsync(
            "/oauth2/authorize",
            new FormUrlEncodedContent(new Dictionary<string, string>()),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
    }

    // ---- Sensitive values and audit ----

    /// <summary>
    /// Drives every failure family with recognisable values and then reads back what the endpoint
    /// persisted. The redirect URL is allowed to carry <c>state</c> — that is the whole point of a
    /// safe redirect — but nothing durable may.
    /// </summary>
    [Fact]
    public async Task RecognisableSensitiveValues_DoNotReachAuditRecords()
    {
        await GetAsync(Valid().With("response_type", "token"));
        await GetAsync(Valid().With("scope", "openid unknown_scope"));
        await GetAsync(Valid().With("client_id", "no-such-client"));
        await GetAsync(Valid().With("redirect_uri", "https://attacker.test/callback?secret=leak"));
        await GetAsync(Valid());

        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var records = await dbContext.AuditLogs
            .AsNoTracking()
            .Where(log => log.Action.StartsWith("oidc.authorize"))
            .ToListAsync(TestContext.Current.CancellationToken);

        Assert.NotEmpty(records);
        foreach (var record in records)
        {
            var serialized = string.Join(
                ' ',
                record.Action,
                record.TargetType,
                record.TargetId,
                record.ActorName,
                record.Description,
                record.BeforeSnapshot,
                record.AfterSnapshot,
                record.CorrelationId);

            Assert.DoesNotContain(CanaryState, serialized, StringComparison.Ordinal);
            Assert.DoesNotContain(CanaryNonce, serialized, StringComparison.Ordinal);
            Assert.DoesNotContain(CanaryChallenge, serialized, StringComparison.Ordinal);
            Assert.DoesNotContain("attacker.test", serialized, StringComparison.Ordinal);
            Assert.DoesNotContain("secret=leak", serialized, StringComparison.Ordinal);
            Assert.DoesNotContain(RegisteredUri, serialized, StringComparison.Ordinal);
        }
    }

    // ---- Accepted: the login continuation redirect ----

    /// <summary>
    /// The accepted redirect carries exactly one query field — the 43-character handle — on a
    /// same-origin relative location, and none of the submitted protocol values travel in it.
    /// </summary>
    [Fact]
    public async Task AcceptedRedirect_LocationCarriesOnlyTheHandle()
    {
        var response = await GetAsync(Valid());

        var handle = await AssertLoginRedirectAsync(response);
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith("/oauth2/login?login_handle=", location, StringComparison.Ordinal);
        Assert.DoesNotContain("http", location, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(CanaryState, location, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryNonce, location, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryChallenge, location, StringComparison.Ordinal);
        Assert.DoesNotContain("openid", location, StringComparison.Ordinal);
        Assert.DoesNotContain(RegisteredUri, location, StringComparison.Ordinal);

        // The handle is the only stored reference to the request and the database holds only its
        // digest: the plaintext never persists.
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var rows = await dbContext.AuthorizationRequests.AsNoTracking()
            .Where(row => row.HandleDigest == LoginHandleDigest.Compute(handle))
            .ToListAsync(TestContext.Current.CancellationToken);
        Assert.Single(rows);
    }

    /// <summary>A host mounted under a reverse-proxy path prefix keeps the prefix in the location.</summary>
    [Fact]
    public async Task AcceptedRedirect_UnderAPathBaseKeepsThePrefix()
    {
        await SeedAsync();
        using var factory = _fixture.WithTestServices(services =>
            services.AddSingleton<IStartupFilter>(new PathBaseStartupFilter("/signacore")));
        using var http = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var response = await http.GetAsync(
            "/signacore/oauth2/authorize" + Valid().Build(), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.StartsWith(
            "/signacore/oauth2/login?login_handle=",
            response.Headers.Location!.ToString(),
            StringComparison.Ordinal);
    }

    /// <summary>No rejection path — local or redirected — writes a continuation row.</summary>
    [Fact]
    public async Task Rejections_LeaveTheContinuationTableUnchanged()
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var before = await dbContext.AuthorizationRequests
            .AsNoTracking()
            .CountAsync(TestContext.Current.CancellationToken);

        await GetAsync(Valid().With("client_id", "no-such-client"));
        await GetAsync(Valid().With("redirect_uri", "https://attacker.test/callback"));
        await GetAsync(Valid().With("scope", "openid unknown_scope"));
        await GetAsync(Valid().With("response_type", "token"));

        var after = await dbContext.AuthorizationRequests
            .AsNoTracking()
            .CountAsync(TestContext.Current.CancellationToken);
        Assert.Equal(before, after);
    }

    /// <summary>
    /// When the single save that commits the continuation and its audit row fails, the endpoint
    /// answers with the existing 500 JSON body, sets no Location, and persists neither row.
    /// </summary>
    [Fact]
    public async Task AcceptedWriteFailure_IsAtomic()
    {
        await SeedAsync();
        var interceptor = new ContinuationInsertFailureInterceptor();
        using var factory = CreateHostWithDbInterceptor(interceptor);
        using var http = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        (int Continuations, int AcceptedAudits) Count()
        {
            using var scope = _fixture.Services.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var continuations = dbContext.AuthorizationRequests.AsNoTracking()
                .CountAsync(TestContext.Current.CancellationToken).GetAwaiter().GetResult();
            var audits = dbContext.AuditLogs.AsNoTracking()
                .CountAsync(
                    log => log.Action == "oidc.authorize.validated" && log.Description == "accepted",
                    TestContext.Current.CancellationToken).GetAwaiter().GetResult();
            return (continuations, audits);
        }

        var before = Count();

        using var response = await http.GetAsync(
            "/oauth2/authorize" + Valid().Build(), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Equal(1, interceptor.InjectedFailures);
        Assert.Null(response.Headers.Location);
        Assert.Equal(1, interceptor.InjectedFailures);

        var after = Count();
        Assert.Equal(before.Continuations, after.Continuations);
        Assert.Equal(before.AcceptedAudits, after.AcceptedAudits);
    }

    /// <summary>
    /// Cancellation at the commit boundary of the accepted write unit (<c>EV-18</c>/<c>SC-20</c>):
    /// before the commit nothing persists, after the commit the continuation and its audit row
    /// stay authoritative.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AcceptedCommitCancellation_IsBounded(bool afterCommit)
    {
        await SeedAsync();
        using var cancellation = new CancellationTokenSource();
        var gate = new ContinuationCommitGate();
        using var factory = CreateHostWithDbInterceptor(
            new ArmOnContinuationInsertInterceptor(gate),
            new ContinuationCommitCancellationInterceptor(gate, cancellation, afterCommit));
        using var http = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        (int Continuations, int AcceptedAudits) Count()
        {
            using var scope = _fixture.Services.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var continuations = dbContext.AuthorizationRequests.AsNoTracking()
                .CountAsync(TestContext.Current.CancellationToken).GetAwaiter().GetResult();
            var audits = dbContext.AuditLogs.AsNoTracking()
                .CountAsync(
                    log => log.Action == "oidc.authorize.validated" && log.Description == "accepted",
                    TestContext.Current.CancellationToken).GetAwaiter().GetResult();
            return (continuations, audits);
        }

        var before = Count();

        if (afterCommit)
        {
            using var response = await http.GetAsync(
                "/oauth2/authorize" + Valid().Build(), TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.NotNull(response.Headers.Location);
        }
        else
        {
            using var response = await http.GetAsync(
                "/oauth2/authorize" + Valid().Build(), TestContext.Current.CancellationToken);
            Assert.NotEqual(HttpStatusCode.Found, response.StatusCode);
            Assert.Null(response.Headers.Location);
        }

        Assert.Equal(1, gate.CommitAttempts);

        var after = Count();
        if (afterCommit)
        {
            Assert.Equal(before.Continuations + 1, after.Continuations);
            Assert.Equal(before.AcceptedAudits + 1, after.AcceptedAudits);
        }
        else
        {
            Assert.Equal(before.Continuations, after.Continuations);
            Assert.Equal(before.AcceptedAudits, after.AcceptedAudits);
        }
    }

    /// <summary>
    /// Two concurrent valid requests from one browser create two independent continuations —
    /// separate handles, separate rows — and both handles open the login form.
    /// </summary>
    [Fact]
    public async Task ConcurrentValidRequests_CreateIndependentContinuations()
    {
        await SeedAsync();
        using var http = _fixture.CreateNonRedirectingHttpClient();

        var first = http.GetAsync("/oauth2/authorize" + Valid().Build(), TestContext.Current.CancellationToken);
        var second = http.GetAsync("/oauth2/authorize" + Valid().Build(), TestContext.Current.CancellationToken);
        var responses = await Task.WhenAll(first, second);

        var handles = new List<string>();
        foreach (var response in responses)
        {
            handles.Add(await AssertLoginRedirectAsync(response));
        }

        Assert.NotEqual(handles[0], handles[1]);

        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        foreach (var handle in handles)
        {
            Assert.Equal(1, await dbContext.AuthorizationRequests.AsNoTracking()
                .CountAsync(
                    row => row.HandleDigest == LoginHandleDigest.Compute(handle),
                    TestContext.Current.CancellationToken));
            using var loginPage = await http.GetAsync(
                "/oauth2/login?login_handle=" + Uri.EscapeDataString(handle),
                TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, loginPage.StatusCode);
        }
    }

    /// <summary>
    /// This slice reads no cookie: with a valid identity cookie (<c>PS-18</c>) and a management
    /// cookie present, the accepted outcome is unchanged and the identity sessions are neither
    /// written nor slid.
    /// </summary>
    [Fact]
    public async Task AcceptedRedirect_IgnoresIdentityAndManagementCookies()
    {
        await SeedAsync();
        var identityCookie = await IssueIdentityCookieAsync();
        var managementCookie = await LoginManagementCookieAsync();

        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var sessionsBefore = await dbContext.IdentitySessions.AsNoTracking()
            .CountAsync(TestContext.Current.CancellationToken);

        using var http = _fixture.CreateNonRedirectingHttpClient();
        using var request = new HttpRequestMessage(
            HttpMethod.Get, "/oauth2/authorize" + Valid().Build());
        request.Headers.TryAddWithoutValidation(
            "Cookie", $"{identityCookie}; {managementCookie}");

        using var response = await http.SendAsync(request, TestContext.Current.CancellationToken);

        await AssertLoginRedirectAsync(response);

        Assert.Equal(
            sessionsBefore,
            await dbContext.IdentitySessions.AsNoTracking()
                .CountAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>Any instance recovers the continuation: host B renders the login form for A's handle.</summary>
    [Fact]
    public async Task AnotherHost_ResolvesTheHandleThroughTheSharedDatabase()
    {
        var response = await GetAsync(Valid());
        var handle = await AssertLoginRedirectAsync(response);

        using var factory = _fixture.WithTestServices(_ => { });
        using var http = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        using var loginPage = await http.GetAsync(
            "/oauth2/login?login_handle=" + Uri.EscapeDataString(handle),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, loginPage.StatusCode);
    }

    /// <summary>
    /// Under the default log configuration, the accepted path leaves none of the submitted
    /// protocol values and no handle plaintext in the SignaCore logs or in any durable store; the
    /// database holds only the handle digest.
    /// </summary>
    [Fact]
    public async Task AcceptedPath_LeaksNoProtocolValuesIntoLogsOrStorage()
    {
        await SeedAsync();
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
        using var http = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var response = await http.GetAsync(
            "/oauth2/authorize" + Valid().Build(), TestContext.Current.CancellationToken);
        var handle = await AssertLoginRedirectAsync(response);

        using (var scope = _fixture.Services.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var continuation = await dbContext.AuthorizationRequests.AsNoTracking()
                .SingleAsync(
                    row => row.HandleDigest == LoginHandleDigest.Compute(handle),
                    TestContext.Current.CancellationToken);
            Assert.Equal(CanaryState, continuation.State);
            Assert.Equal(CanaryNonce, continuation.Nonce);
            Assert.Equal(CanaryChallenge, continuation.CodeChallenge);
        }

        var messages = capture.Messages;
        foreach (var message in messages)
        {
            Assert.DoesNotContain(handle, message, StringComparison.Ordinal);
            Assert.DoesNotContain(CanaryState, message, StringComparison.Ordinal);
            Assert.DoesNotContain(CanaryNonce, message, StringComparison.Ordinal);
            Assert.DoesNotContain(CanaryChallenge, message, StringComparison.Ordinal);
            Assert.DoesNotContain("openid", message, StringComparison.Ordinal);
        }
    }

    private async Task<string> IssueIdentityCookieAsync()
    {
        using var scope = _fixture.Services.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        await context.SignInAsync(
            IdentitySessionDefaults.AuthenticationScheme,
            IdentitySessionPrincipal.Create(Guid.NewGuid()));

        var setCookie = Assert.Single(context.Response.Headers["Set-Cookie"].ToArray());
        return setCookie.Split(';')[0];
    }

    private async Task<string> LoginManagementCookieAsync()
    {
        using var factory = _fixture.WithTestServices(_ => { });
        using var http = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
        using var login = new HttpRequestMessage(
            HttpMethod.Post, "/management/v1/session/login")
        {
            Content = JsonContent.Create(new
            {
                username = IdentityServerFixture.AdminUsername,
                password = IdentityServerFixture.AdminPassword
            })
        };
        login.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        using var loginResponse = await http.SendAsync(login, TestContext.Current.CancellationToken);
        loginResponse.EnsureSuccessStatusCode();

        var setCookie = loginResponse.Headers.GetValues("Set-Cookie")
            .Single(value => value.StartsWith("__Host-ServiceMantle.Management=", StringComparison.Ordinal));
        return setCookie.Split(';')[0];
    }

    /// <summary>
    /// Asserts the wire shape of the accepted result: a 302 whose location is a same-origin
    /// relative login URL carrying exactly one query field — the 43-character
    /// <c>[A-Za-z0-9_-]</c> handle — plus the browser security headers. Returns the handle.
    /// </summary>
    private static async Task<string> AssertLoginRedirectAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        AssertBrowserSecurityHeaders(response);

        var location = response.Headers.Location!.ToString();
        Assert.StartsWith("/oauth2/login?login_handle=", location, StringComparison.Ordinal);
        var query = HttpUtility.ParseQueryString(location[(location.IndexOf('?') + 1)..]);
        Assert.Single(query.AllKeys, key => key == "login_handle");
        var handle = query["login_handle"]!;
        Assert.Equal(IdentityConstants.LoginHandleLength, handle.Length);
        Assert.All(handle, character =>
            Assert.True(char.IsAsciiLetterOrDigit(character) || character is '-' or '_'));
        await Task.CompletedTask;
        return handle;
    }

    private WebApplicationFactory<Program> CreateHostWithDbInterceptor(
        params Microsoft.EntityFrameworkCore.Diagnostics.IInterceptor[] interceptors) =>
        _fixture.WithTestServices(services =>
        {
            // EF Core aggregates DbContextOptions from every registered configuration, so the
            // interceptor joins the host's own configuration instead of replacing it.
            services.ConfigureDbContext<IdentityDbContext>(
                optionsBuilder => optionsBuilder.AddInterceptors(interceptors));
        });

    private sealed class PathBaseStartupFilter(string pathBase) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) =>
            app =>
            {
                app.UsePathBase(pathBase);
                next(app);
            };
    }

    /// <summary>
    /// Fails the one statement that persists the continuation, so the audit row staged in the same
    /// save rolls back with it.
    /// </summary>
    private sealed class ContinuationInsertFailureInterceptor : DbCommandInterceptor
    {
        public int InjectedFailures { get; private set; }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfShouldFail(command);
            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }

        public override ValueTask<InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<System.Data.Common.DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfShouldFail(command);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }

        private void ThrowIfShouldFail(DbCommand command)
        {
            // Only the continuation INSERT matches: the startup cleanup also references the table
            // in its DELETE, and it must not consume the injected failure.
            if (InjectedFailures >= 1
                || !command.CommandText.Contains(
                    "INSERT INTO \"authorization_requests\"", StringComparison.Ordinal))
            {
                return;
            }

            InjectedFailures++;
            throw new IOException("Injected continuation write failure.");
        }
    }

    /// <summary>
    /// Marks the transaction commit that follows the continuation insert as the write unit's
    /// commit boundary.
    /// </summary>
    private sealed class ContinuationCommitGate
    {
        public bool Armed;
        public int CommitAttempts;
    }

    /// <summary>Arms the shared gate when the continuation INSERT runs.</summary>
    private sealed class ArmOnContinuationInsertInterceptor(ContinuationCommitGate gate)
        : DbCommandInterceptor
    {
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            ArmIfContinuationInsert(command);
            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }

        public override ValueTask<InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<System.Data.Common.DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            ArmIfContinuationInsert(command);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }

        private void ArmIfContinuationInsert(DbCommand command)
        {
            if (!gate.Armed
                && command.CommandText.Contains(
                    "authorization_requests", StringComparison.OrdinalIgnoreCase)
                && command.CommandText.Contains(
                    "INSERT", StringComparison.OrdinalIgnoreCase))
            {
                gate.Armed = true;
            }
        }
    }

    /// <summary>
    /// Cancels at the armed transaction commit: before the commit the whole unit rolls back,
    /// after the commit the rows stay authoritative.
    /// </summary>
    private sealed class ContinuationCommitCancellationInterceptor(
        ContinuationCommitGate gate,
        CancellationTokenSource cancellation,
        bool afterCommit) : DbTransactionInterceptor
    {
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(
            DbTransaction transaction,
            TransactionEventData eventData,
            InterceptionResult result,
            CancellationToken cancellationToken = default)
        {
            if (!gate.Armed)
            {
                return ValueTask.FromResult(result);
            }

            gate.CommitAttempts++;
            if (!afterCommit)
            {
                cancellation.Cancel();
                throw new OperationCanceledException(
                    "The continuation write was cancelled before its commit.", cancellation.Token);
            }

            return ValueTask.FromResult(result);
        }

        public override Task TransactionCommittedAsync(
            DbTransaction transaction,
            TransactionEndEventData eventData,
            CancellationToken cancellationToken = default)
        {
            if (gate.Armed)
            {
                cancellation.Cancel();
            }

            return Task.CompletedTask;
        }
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly object _lock = new();
        private readonly List<string> _messages = [];

        public IReadOnlyList<string> Messages
        {
            get
            {
                lock (_lock)
                {
                    return _messages.ToArray();
                }
            }
        }

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(CapturingLoggerProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                lock (owner._lock)
                {
                    owner._messages.Add(formatter(state, exception));
                }
            }
        }
    }

    /// <summary>
    /// A local rejection has no registered subject to audit, so unauthenticated traffic cannot grow
    /// the audit table. The counter in <c>AuthMetrics</c> carries that volume instead.
    /// </summary>
    [Fact]
    public async Task LocallyRejectedRequests_WriteNoAuditRecord()
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var before = await dbContext.AuditLogs
            .CountAsync(log => log.Action.StartsWith("oidc.authorize"), TestContext.Current.CancellationToken);

        await GetAsync(Valid().With("client_id", "another-missing-client"));

        var after = await dbContext.AuditLogs
            .CountAsync(log => log.Action.StartsWith("oidc.authorize"), TestContext.Current.CancellationToken);
        Assert.Equal(before, after);
    }

    // ---- Regression: the advertised capability matches the delivered core ----

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-authorization-server")]
    public async Task DiscoveryDocuments_AdvertiseTheAuthorizationEndpointCore(string path)
    {
        using var http = _fixture.CreateHttpClient();

        var document = await http.GetFromJsonAsync<JsonElement>(
            path,
            TestContext.Current.CancellationToken);

        Assert.True(document.TryGetProperty("authorization_endpoint", out _));
        Assert.Equal(
            ["S256"],
            document.GetProperty("code_challenge_methods_supported").EnumerateArray()
                .Select(value => value.GetString()));
        Assert.Equal(
            ["code"],
            document.GetProperty("response_types_supported").EnumerateArray().Select(value => value.GetString()));
        var grantTypes = document.GetProperty("grant_types_supported")
            .EnumerateArray()
            .Select(value => value.GetString())
            .ToList();
        Assert.Contains("authorization_code", grantTypes);
    }

    private string Issuer => _fixture.Services.GetRequiredService<JwtOptions>().Issuer;

    private static void AssertBrowserSecurityHeaders(HttpResponseMessage response)
    {
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Contains("no-cache", response.Headers.Pragma.ToString(), StringComparison.Ordinal);
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
    }

    private static async Task<string> AssertLocalErrorAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.False(response.Headers.Contains("Location"));
        AssertBrowserSecurityHeaders(response);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("href", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(CanaryState, body, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryNonce, body, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryChallenge, body, StringComparison.Ordinal);
        return body;
    }

    private System.Collections.Specialized.NameValueCollection AssertSafeRedirect(
        HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        AssertBrowserSecurityHeaders(response);

        var location = response.Headers.Location!;
        Assert.StartsWith(RegisteredUri + "?", location.ToString(), StringComparison.Ordinal);
        var parameters = HttpUtility.ParseQueryString(location.Query);
        Assert.Equal(Issuer, parameters["iss"]);
        return parameters;
    }

    private async Task<HttpResponseMessage> GetAsync(QueryBuilder query)
    {
        await SeedAsync();
        using var http = _fixture.CreateNonRedirectingHttpClient();
        return await http.GetAsync("/oauth2/authorize" + query.Build(), TestContext.Current.CancellationToken);
    }

    private static QueryBuilder Valid()
    {
        return new QueryBuilder()
            .With("response_type", "code")
            .With("client_id", InteractiveAppId)
            .With("redirect_uri", RegisteredUri)
            .With("scope", "openid profile")
            .With("state", CanaryState)
            .With("nonce", CanaryNonce)
            .With("code_challenge", CanaryChallenge)
            .With("code_challenge_method", "S256");
    }

    private async Task SeedAsync()
    {
        await SeedLock.WaitAsync(TestContext.Current.CancellationToken);
        try
        {
            if (_seeded)
            {
                return;
            }

            using var scope = _fixture.Services.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();

            var interactive = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = InteractiveAppId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword("authorize-contract-secret"),
                AppName = "Authorize Contract App",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.PerApplication,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = "openid profile",
                AllowRefreshToken = false
            };
            interactive.RedirectUris =
            [
                Registration(interactive.Id, RedirectUriKind.Redirect, RegisteredUri),
                Registration(interactive.Id, RedirectUriKind.Redirect, RegisteredUriWithQuery),
                Registration(interactive.Id, RedirectUriKind.PostLogout, PostLogoutUri)
            ];

            var inactive = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = InactiveAppId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword("authorize-inactive-secret"),
                AppName = "Authorize Inactive App",
                IsActive = false,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.PerApplication,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = "openid profile"
            };
            inactive.RedirectUris =
            [
                Registration(inactive.Id, RedirectUriKind.Redirect, RegisteredUri)
            ];

            var nonInteractive = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = NonInteractiveAppId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword("authorize-plain-secret"),
                AppName = "Authorize Plain App",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.Shared,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = false,
                AllowedScopes = "openid"
            };

            dbContext.AppRegistrations.AddRange(interactive, inactive, nonInteractive);
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
            _seeded = true;
        }
        finally
        {
            SeedLock.Release();
        }
    }

    private static AppRedirectUriEntity Registration(Guid appId, RedirectUriKind kind, string uri)
    {
        return new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = appId,
            Kind = kind,
            CanonicalUri = uri
        };
    }

    private sealed class QueryBuilder
    {
        private readonly List<KeyValuePair<string, string>> _values = [];

        public QueryBuilder With(string name, string value)
        {
            _values.RemoveAll(pair => pair.Key == name);
            _values.Add(new KeyValuePair<string, string>(name, value));
            return this;
        }

        public QueryBuilder Without(string name)
        {
            _values.RemoveAll(pair => pair.Key == name);
            return this;
        }

        /// <summary>Repeats a parameter with its existing value, so duplicates match exactly.</summary>
        public QueryBuilder Duplicate(string name)
        {
            var existing = _values.First(pair => pair.Key == name);
            _values.Add(existing);
            return this;
        }

        public string Build()
        {
            return "?" + string.Join(
                '&',
                _values.Select(pair =>
                    $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
        }
    }
}
