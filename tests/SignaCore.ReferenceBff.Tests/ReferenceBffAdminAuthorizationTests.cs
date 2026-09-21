extern alias BffSample;

using System.Data.Common;
using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using SignaCore.ReferenceBff.Database;
using ServiceMantle.Persistence.EntityFrameworkCore;
using Xunit;
using BffIdentityCheckService = BffSample::SignaCore.ReferenceBff.BffIdentityCheckService;
using BffMemoryTicketStore = BffSample::SignaCore.ReferenceBff.MemoryTicketStore;
using BffProgram = BffSample::Program;

namespace SignaCore.ReferenceBff.Tests;

/// <summary>
/// The runtime administrator authorization of the reference BFF (#74 runtime identity/authorization
/// sub-stage): the standard OIDC handshake captures the verified issuer/subject server-side, every
/// management request re-confirms the identity upstream and then matches the exact local active
/// binding, and each failure family answers one fixed manual status — 401 (session torn down), 403
/// (local denial, ticket kept), or 503 (a dependency could not answer, ticket kept). Anonymous
/// requests take the standard challenge back to the fixed route. Cancellation traverses every
/// boundary; no boundary ever widens permission.
/// </summary>
public sealed class ReferenceBffAdminAuthorizationTests
{
    private const string SessionCookieName = "signacore-bff-session";
    private const string ClientId = "reference-bff";

    // ---- Challenge and the fixed return route ----

    [Fact]
    public async Task AnAnonymousRequest_IsChallenged_AndTheFlowReturnsOnlyToTheFixedAdminRoute()
    {
        await using var authority = await FakeAuthority.StartAsync();
        await using var database = await TempBffDatabase.CreateMigratedWithBindingAsync(
            FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject);
        await using var bff = CreateBff(authority, database);
        using var browser = CreateBrowser(bff, authority);

        // An attacker-controlled query parameter must not become an open return URL.
        using (var anonymous = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin?next=https://attacker.example")))
        using (var response = await browser.SendOnBffAsync(anonymous, TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.StartsWith(
                FakeAuthority.BaseAddress + "/authorize",
                response.Headers.Location!.ToString(),
                StringComparison.Ordinal);
        }

        // Completing the handshake lands exactly on /bff/admin — nothing else is honored.
        await SignInAsync(browser);
        using (var admin = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin")))
        using (var response = await browser.SendOnBffAsync(admin, TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }

    // ---- The authorized decision ----

    [Fact]
    public async Task ACorrectlyBoundAdministrator_GetsTheFixedBody_WithNoCrossRequestCaching()
    {
        await using var authority = await FakeAuthority.StartAsync();
        await using var database = await TempBffDatabase.CreateMigratedWithBindingAsync(
            FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject);
        await using var bff = CreateBff(authority, database);
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        for (var request = 1; request <= 2; request++)
        {
            using var admin = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
            using var response = await browser.SendOnBffAsync(admin, TestContext.Current.CancellationToken);
            var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("""{"isAdministrator":true}""", body);
        }

        // Two requests, two upstream confirmations: the administrator decision is never cached.
        Assert.Equal(2, authority.UserInfoCalls);

        // Revoking the binding takes effect on the very next query, with the ticket kept.
        await database.DeactivateBindingAsync();
        using (var admin = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin")))
        using (var response = await browser.SendOnBffAsync(admin, TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        Assert.Equal(1, TicketStore(bff).Count);
        await AssertStillSignedInAsync(browser);
    }

    // ---- The forbidden family: local denial keeps the ticket ----

    [Fact]
    public async Task WithoutABinding_TheRequestIsForbidden_ButTheSessionSurvives()
    {
        await using var authority = await FakeAuthority.StartAsync();
        await using var database = await TempBffDatabase.CreateMigratedAsync();
        await using var bff = CreateBff(authority, database);
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        using var admin = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        using var response = await browser.SendOnBffAsync(admin, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(1, TicketStore(bff).Count);
        await AssertStillSignedInAsync(browser);
        await using var untouched = new ReferenceBffDbContext(
            new DbContextOptionsBuilder<ReferenceBffDbContext>()
                .UseReferenceBffSqlite(database.ConnectionString).Options);
        Assert.Single(await untouched.ServiceInstallations.ToListAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await untouched.ManagementRoleBindings.ToListAsync(TestContext.Current.CancellationToken));

    }

    [Theory]
    [InlineData("WrongSubject")]
    [InlineData("WrongIssuer")]
    [InlineData("Inactive")]
    public async Task ANonMatchingBinding_NeverGrantsTheRequest(string caseName)
    {
        await using var authority = await FakeAuthority.StartAsync();
        await using var database = await TempBffDatabase.CreateMigratedAsync();
        await SeedCaseBindingAsync(database, caseName);
        await using var bff = CreateBff(authority, database);
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        using var admin = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        using var response = await browser.SendOnBffAsync(admin, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(1, TicketStore(bff).Count);
    }

    [Fact]
    public async Task AGenericAdminClaim_Alone_NeverGrantsTheRequest()
    {
        await using var authority = await FakeAuthority.StartAsync();
        authority.ExtraIdTokenClaims.Add(new Claim("role", "admin"));
        authority.ExtraIdTokenClaims.Add(new Claim("admin", "true"));
        await using var database = await TempBffDatabase.CreateMigratedAsync();
        await using var bff = CreateBff(authority, database);
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        using var admin = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        using var response = await browser.SendOnBffAsync(admin, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    // ---- Sign-in capture: the ID token must carry exactly one usable subject ----

    [Theory]
    [InlineData(FakeAuthority.TokenSubjectMode.Missing)]
    [InlineData(FakeAuthority.TokenSubjectMode.Duplicate)]
    public async Task AMissingOrDuplicatedIdTokenSubject_FailsTheSignInWithoutASession(
        FakeAuthority.TokenSubjectMode mode)
    {
        await using var authority = await FakeAuthority.StartAsync();
        authority.SubjectMode = mode;
        await using var database = await TempBffDatabase.CreateMigratedWithBindingAsync(
            FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject);
        await using var bff = CreateBff(authority, database);
        using var browser = CreateBrowser(bff, authority);

        var final = await DriveSignInAsync(browser);
        Assert.Contains("could not complete", final.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("Signed in", final.Body, StringComparison.Ordinal);
        Assert.Equal(0, TicketStore(bff).Count);
    }

    // ---- The session-invalid family: ticket metadata and upstream confirmation ----

    [Fact]
    public async Task ALegacyTicketWithoutIdentityMetadata_IsRejectedAndCleared()
    {
        await using var authority = await FakeAuthority.StartAsync();
        await using var database = await TempBffDatabase.CreateMigratedWithBindingAsync(
            FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject);
        await using var bff = CreateBff(authority, database);
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        await ReplaceTicketAsync(bff, browser, ticket => new AuthenticationTicket(
            ticket.Principal,
            new AuthenticationProperties(
                ticket.Properties.Items
                    .Where(pair => !pair.Key.StartsWith("referenceBff.", StringComparison.Ordinal))
                    .ToDictionary(pair => pair.Key, pair => pair.Value)),
            ticket.AuthenticationScheme));

        using var admin = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        using var response = await browser.SendOnBffAsync(admin, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, TicketStore(bff).Count);
        AssertSignedOutCookieAsync(response);
    }

    [Fact]
    public async Task ATicketWithoutStoredToken_IsRejectedAndCleared()
    {
        await using var authority = await FakeAuthority.StartAsync();
        await using var database = await TempBffDatabase.CreateMigratedWithBindingAsync(
            FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject);
        await using var bff = CreateBff(authority, database);
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        await ReplaceTicketAsync(bff, browser, ticket => new AuthenticationTicket(
            ticket.Principal,
            // Tokens live inside Items under the ".Token." prefix: filtering them out yields a
            // ticket with the identity metadata but no stored token material.
            new AuthenticationProperties(
                ticket.Properties.Items
                    .Where(pair => !pair.Key.StartsWith(".Token.", StringComparison.Ordinal))
                    .ToDictionary(pair => pair.Key, pair => pair.Value)),
            ticket.AuthenticationScheme));

        using var admin = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        using var response = await browser.SendOnBffAsync(admin, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, TicketStore(bff).Count);
    }

    [Theory]
    [InlineData(FakeAuthority.UserInfoResponse.SubjectMismatch)]
    [InlineData(FakeAuthority.UserInfoResponse.SubjectMissing)]
    [InlineData(FakeAuthority.UserInfoResponse.SubjectDuplicate)]
    [InlineData(FakeAuthority.UserInfoResponse.SubjectNonString)]
    [InlineData(FakeAuthority.UserInfoResponse.Unauthorized)]
    public async Task AnUnconfirmedUpstreamSubject_ClearsTheTicket_AndNeverReachesLocalAuthorization(
        FakeAuthority.UserInfoResponse mode)
    {
        await using var authority = await FakeAuthority.StartAsync();
        authority.UserInfoMode = mode;
        // The local binding is valid for the signed-in identity: a 401 proves the request never
        // reached the local decision — had it been queried, the answer would have been 403/200.
        await using var database = await TempBffDatabase.CreateMigratedWithBindingAsync(
            FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject);
        await using var bff = CreateBff(authority, database);
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        using var admin = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        using var response = await browser.SendOnBffAsync(admin, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, TicketStore(bff).Count);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("a-different-upstream-subject", body, StringComparison.Ordinal);
    }

    // ---- The unavailable family: dependencies that cannot answer keep the ticket ----

    [Theory]
    [InlineData(FakeAuthority.UserInfoResponse.InvalidJson)]
    [InlineData(FakeAuthority.UserInfoResponse.InternalError)]
    public async Task AnUnusableUpstreamAnswer_IsAFixed503_AndKeepsTheTicket(
        FakeAuthority.UserInfoResponse mode)
    {
        await using var authority = await FakeAuthority.StartAsync();
        authority.UserInfoMode = mode;
        await using var database = await TempBffDatabase.CreateMigratedWithBindingAsync(
            FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject);
        await using var bff = CreateBff(authority, database);
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        using var admin = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        using var response = await browser.SendOnBffAsync(admin, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(1, TicketStore(bff).Count);
        await AssertStillSignedInAsync(browser);
    }

    [Fact]
    public async Task DiscoveryWithoutAUserInfoEndpoint_IsAFixed503()
    {
        await using var authority = await FakeAuthority.StartAsync();
        authority.OmitUserInfoEndpoint = true;
        await using var database = await TempBffDatabase.CreateMigratedWithBindingAsync(
            FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject);
        await using var bff = CreateBff(authority, database);
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        using var admin = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        using var response = await browser.SendOnBffAsync(admin, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(1, TicketStore(bff).Count);
    }

    [Fact]
    public async Task ANetworkFailureOnTheUserinfoLeg_IsAFixed503()
    {
        await using var authority = await FakeAuthority.StartAsync();
        await using var database = await TempBffDatabase.CreateMigratedWithBindingAsync(
            FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject);
        var failing = new ThrowingUserInfoHandler(authority.Server.CreateHandler());
        await using var bff = CreateBff(authority, database, failing);
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        using var admin = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        using var response = await browser.SendOnBffAsync(admin, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(1, TicketStore(bff).Count);
        Assert.Equal(0, authority.UserInfoCalls);
    }

    [Fact]
    public async Task ADatabaseWithoutTheMigratedSchema_IsAFixed503()
    {
        await using var authority = await FakeAuthority.StartAsync();
        await using var database = TempBffDatabase.CreateUnmigrated();
        await using var bff = CreateBff(authority, database);
        using var browser = CreateBrowser(bff, authority);

        using var admin = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        using var response = await browser.SendOnBffAsync(admin, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(0, TicketStore(bff).Count);
    }

    [Fact]
    public async Task WithoutAnyDatabaseConfiguration_TheLoginSampleRuns_AndManagementIsAFixed503()
    {
        await using var authority = await FakeAuthority.StartAsync();
        using var backchannel = authority.CreateClient();
        await using var bff = BffTestServer.Create(
            FakeAuthority.BaseAddress,
            ClientId,
            "reference-bff-test-secret",
            SignaCoreHostFixture.RedirectUri,
            backchannel,
            userInfoHandler: authority.Server.CreateHandler());
        using var browser = CreateBrowser(bff, authority);

        await SignInAsync(browser);
        using var admin = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        using var response = await browser.SendOnBffAsync(admin, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(1, TicketStore(bff).Count);
        await AssertStillSignedInAsync(browser);
    }

    // ---- Startup configuration contract ----

    [Fact]
    public async Task APartialDatabaseConfiguration_FailsStartup_WithoutEchoingValues()
    {
        await using var authority = await FakeAuthority.StartAsync();
        using var backchannel = authority.CreateClient();

        var connectionSecret = "Data Source=/tmp/never-created-4f6a2d9b7e1c.db";
        var factory = BffTestServer.Create(
            FakeAuthority.BaseAddress,
            ClientId,
            "reference-bff-test-secret",
            SignaCoreHostFixture.RedirectUri,
            backchannel,
            userInfoHandler: authority.Server.CreateHandler(),
            databaseConnectionString: connectionSecret);

        var failure = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains(
            "The reference BFF database configuration is invalid",
            failure.ToString(),
            StringComparison.Ordinal);
        Assert.DoesNotContain(connectionSecret, failure.ToString(), StringComparison.Ordinal);
        await factory.DisposeAsync();

        var providerOnly = BffTestServer.Create(
            FakeAuthority.BaseAddress,
            ClientId,
            "reference-bff-test-secret",
            SignaCoreHostFixture.RedirectUri,
            backchannel,
            userInfoHandler: authority.Server.CreateHandler(),
            databaseProvider: "SQLite");
        Assert.ThrowsAny<Exception>(() => providerOnly.CreateClient());
        await providerOnly.DisposeAsync();

        var unknownProvider = BffTestServer.Create(
            FakeAuthority.BaseAddress,
            ClientId,
            "reference-bff-test-secret",
            SignaCoreHostFixture.RedirectUri,
            backchannel,
            userInfoHandler: authority.Server.CreateHandler(),
            databaseProvider: "SqlServer",
            databaseConnectionString: connectionSecret);
        Assert.ThrowsAny<Exception>(() => unknownProvider.CreateClient());
        await unknownProvider.DisposeAsync();
    }

    // ---- Cancellation traverses every boundary ----

    [Fact]
    public async Task CallerCancellation_DuringTheUserinfoLeg_LeavesTheSessionUntouched()
    {
        await using var authority = await FakeAuthority.StartAsync();
        var gate = authority.HoldUserInfoRequests();
        await using var database = await TempBffDatabase.CreateMigratedWithBindingAsync(
            FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject);
        await using var bff = CreateBff(authority, database);
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        var operation = browser.SendOnBffAsync(request, cancellation.Token);

        // The request is parked on the deterministic UserInfo gate when it is abandoned —
        // arrival evidence, not a timer.
        await authority.UserInfoArrived.WaitAsync(TestContext.Current.CancellationToken);
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);

        // No session verdict happened: the ticket is intact and the binding still authorizes.
        Assert.Equal(1, TicketStore(bff).Count);
        gate.TrySetResult();
        using var retry = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        using var response = await browser.SendOnBffAsync(retry, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task CallerCancellation_DuringTheDatabaseQuery_LeavesNoHalfDecision()
    {
        var interceptor = new BlockingDbInterceptor();
        await using var authority = await FakeAuthority.StartAsync();
        await using var database = await TempBffDatabase.CreateMigratedWithBindingAsync(
            FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject);
        await using var bff = CreateBff(authority, database, dbInterceptor: interceptor);
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        var operation = browser.SendOnBffAsync(request, cancellation.Token);

        await interceptor.Entered.WaitAsync(TestContext.Current.CancellationToken);
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);
        _ = interceptor.Release;

        Assert.Equal(1, TicketStore(bff).Count);
    }

    [Fact]
    public async Task AnInternalCancellationWhileTheCallerStillWaits_IsAFixed503()
    {
        var interceptor = new InternallyCancellableDbInterceptor();
        await using var authority = await FakeAuthority.StartAsync();
        await using var database = await TempBffDatabase.CreateMigratedWithBindingAsync(
            FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject);
        await using var bff = CreateBff(authority, database, dbInterceptor: interceptor);
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        var operation = browser.SendOnBffAsync(request, cts.Token);

        await interceptor.Entered.WaitAsync(TestContext.Current.CancellationToken);
        interceptor.CancelInternally();

        using var response = await operation;
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(1, TicketStore(bff).Count);
    }

    [Fact]
    public async Task CallerCancellation_AfterDiscoveryCompleted_OutranksTheMissingEndpointVerdict()
    {
        await using var authority = await FakeAuthority.StartAsync();
        await using var database = await TempBffDatabase.CreateMigratedWithBindingAsync(
            FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject);
        await using var bff = CreateBff(authority, database);
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        // Service-level probe over the real host's DI and the signed-in session cookie,
        // mirroring the deterministic review experiment: Discovery's boundary parks, the
        // caller abandons the request, and only then does the boundary complete normally with
        // a configuration that carries no UserInfo endpoint. The observation after the
        // boundary must propagate the caller's cancellation — never an unavailable verdict.
        // Driving the check directly keeps the transport's own cancellation from masking the
        // server-side outcome.
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var oidcOptions = bff.Services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);
        oidcOptions.ConfigurationManager = new DiscoveryBoundaryProbeManager(
            oidcOptions.ConfigurationManager!, entered);
        using (var scope = bff.Services.CreateScope())
        {
            var http = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
            http.Request.Headers.Cookie = browser.Cookies.GetCookieHeader(browser.BffBase);
            var check = scope.ServiceProvider.GetRequiredService<BffIdentityCheckService>();

            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var operation = check.CheckAsync(http, cancellation.Token);

            await entered.Task.WaitAsync(TestContext.Current.CancellationToken);
            await cancellation.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);
        }

        // No verdict ran: the session is intact and the next request authorizes normally.
        Assert.Equal(1, TicketStore(bff).Count);
        using var retry = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/admin"));
        using var response = await browser.SendOnBffAsync(retry, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task CallerCancellation_AfterTheJsonRead_OutranksAnyProfileVerdict()
    {
        var callerSource = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await using var authority = await FakeAuthority.StartAsync();
        await using var database = await TempBffDatabase.CreateMigratedWithBindingAsync(
            FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject);
        await using var bff = CreateBff(
            authority, database, userInfoWrapper: new CancelOnContentReadHandler(callerSource));
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        // The UserInfo response arrives intact; the identity check's payload read cancels the
        // caller's own source and still completes. Observed at the service level — the
        // transport never masks it — the observation after the JSON read must propagate the
        // caller's cancellation: never a profile, a verdict, or a session teardown.
        using (var scope = bff.Services.CreateScope())
        {
            var http = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
            http.Request.Headers.Cookie = browser.Cookies.GetCookieHeader(browser.BffBase);
            var check = scope.ServiceProvider.GetRequiredService<BffIdentityCheckService>();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => check.CheckAsync(http, callerSource.Token));
        }

        Assert.Equal(1, TicketStore(bff).Count);
        using var retry = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/me"));
        using var response = await browser.SendOnBffAsync(retry, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ---- The route adds no state-changing surface ----

    [Fact]
    public async Task TheAdminRoute_IsStrictlyReadOnly()
    {
        await using var authority = await FakeAuthority.StartAsync();
        await using var database = await TempBffDatabase.CreateMigratedWithBindingAsync(
            FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject);
        await using var bff = CreateBff(authority, database);
        using var browser = CreateBrowser(bff, authority);
        await SignInAsync(browser);

        using var post = new HttpRequestMessage(HttpMethod.Post, new Uri(browser.BffBase, "/bff/admin"));
        using var response = await browser.SendOnBffAsync(post, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
    }

    // ---- Driving ----

    private static WebApplicationFactory<BffProgram> CreateBff(
        FakeAuthority authority,
        TempBffDatabase database,
        ThrowingUserInfoHandler? failingUserInfo = null,
        DbCommandInterceptor? dbInterceptor = null,
        DelegatingHandler? userInfoWrapper = null)
    {
        // The backchannel client intentionally outlives this method: the BFF's OIDC handler owns
        // it for the lifetime of the factory, and the authority disposes the underlying server.
        var backchannelClient = new HttpClient(authority.Server.CreateHandler(), disposeHandler: false)
        {
            BaseAddress = new Uri(FakeAuthority.BaseAddress)
        };

        HttpMessageHandler userInfo = authority.Server.CreateHandler();
        if (userInfoWrapper is not null)
        {
            userInfoWrapper.InnerHandler = userInfo;
            userInfo = userInfoWrapper;
        }

        return BffTestServer.Create(
            FakeAuthority.BaseAddress,
            ClientId,
            "reference-bff-test-secret",
            SignaCoreHostFixture.RedirectUri,
            backchannelClient,
            userInfoHandler: failingUserInfo ?? userInfo,
            databaseProvider: "SQLite",
            databaseConnectionString: database.ConnectionString,
            configureTestServices: dbInterceptor is null
                ? null
                : services =>
                {
                    // Replace the sample's context registration with the same wiring plus the
                    // boundary-controlling interceptor.
                    services.RemoveAll<ReferenceBffDbContext>();
                    services.RemoveAll<DbContextOptions>();
                    services.RemoveAll<DbContextOptions<ReferenceBffDbContext>>();
                    services.AddDbContext<ReferenceBffDbContext>(options => options
                        .UseSqlite(database.ConnectionString)
                        .AddInterceptors(dbInterceptor), optionsLifetime: ServiceLifetime.Singleton);
                });
    }

    private static CrossServerBrowser CreateBrowser(
        WebApplicationFactory<BffProgram> bff,
        FakeAuthority authority) =>
        BffTestServer.CreateBrowserOverAuthority(
            bff, authority.Server.CreateHandler(), new Uri(FakeAuthority.BaseAddress));

    private static BffMemoryTicketStore TicketStore(WebApplicationFactory<BffProgram> bff) =>
        bff.Services.GetRequiredService<BffMemoryTicketStore>();

    private static async Task SignInAsync(CrossServerBrowser browser)
    {
        var final = await DriveSignInAsync(browser);
        Assert.Contains("Signed in", final.Body, StringComparison.Ordinal);
    }

    private static async Task<(string Body, string Subject)> DriveSignInAsync(CrossServerBrowser browser)
    {
        using var challenge = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/login"));
        using var challengeResponse = await browser.SendOnBffAsync(challenge, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, challengeResponse.StatusCode);

        using var authorize = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.IdentityBase, challengeResponse.Headers.Location!.PathAndQuery));
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(authorize, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, authorizeResponse.StatusCode);

        using var callback = new HttpRequestMessage(
            HttpMethod.Get, new Uri(authorizeResponse.Headers.Location!.ToString()));
        using var callbackResponse = await browser.SendOnBffAsync(callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);

        using var finalRequest = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.BffBase, callbackResponse.Headers.Location!.ToString()));
        using var final = await browser.SendOnBffAsync(finalRequest, TestContext.Current.CancellationToken);
        var body = await final.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var subject = body.Contains("Signed in", StringComparison.Ordinal)
            ? body.Split("Subject: ")[1].Split("</p>")[0]
            : string.Empty;
        return (body, subject);
    }

    private static async Task AssertStillSignedInAsync(CrossServerBrowser browser)
    {
        using var home = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/"));
        using var response = await browser.SendOnBffAsync(home, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Signed in", body, StringComparison.Ordinal);
    }

    private static void AssertSignedOutCookieAsync(HttpResponseMessage response)
    {
        Assert.Contains(
            response.Headers.TryGetValues("Set-Cookie", out var cookies) ? cookies : [],
            cookie => cookie.StartsWith(SessionCookieName + "=", StringComparison.Ordinal)
                && cookie.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Replaces the browser's server-side ticket with a transformed copy (same principal shape,
    /// caller-controlled properties) so a test can present a legacy or token-less ticket. With a
    /// session store the browser cookie carries a protected stub whose single claim
    /// (<c>Microsoft.AspNetCore.Authentication.Cookies-SessionId</c>) is the store key; the
    /// sample's own TicketDataFormat is used to read and re-mint that stub.
    /// </summary>
    private static async Task ReplaceTicketAsync(
        WebApplicationFactory<BffProgram> bff,
        CrossServerBrowser browser,
        Func<AuthenticationTicket, AuthenticationTicket> transform)
    {
        const string sessionIdClaimType = "Microsoft.AspNetCore.Authentication.Cookies-SessionId";
        var store = TicketStore(bff);
        var cookieOptions = bff.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);
        var cookieValue = browser.Cookies.GetCookies(browser.BffBase)[SessionCookieName]?.Value;
        Assert.False(string.IsNullOrEmpty(cookieValue), "The browser held no BFF session cookie.");

        var stub = cookieOptions.TicketDataFormat!.Unprotect(cookieValue!);
        Assert.NotNull(stub);
        var key = Assert.Single(stub!.Principal.Claims, claim => claim.Type == sessionIdClaimType).Value;
        var ticket = await store.RetrieveAsync(key);
        Assert.NotNull(ticket);

        await store.RemoveAsync(key);
        var newKey = await store.StoreAsync(transform(ticket!));

        var newStub = new AuthenticationTicket(
            new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim(sessionIdClaimType, newKey)],
                authenticationType: "Cookies")),
            new AuthenticationProperties(),
            CookieAuthenticationDefaults.AuthenticationScheme);
        browser.Cookies.Add(
            browser.BffBase,
            new Cookie(SessionCookieName, cookieOptions.TicketDataFormat.Protect(newStub)));
    }

    private static async Task SeedCaseBindingAsync(TempBffDatabase database, string caseName)
    {
        var (issuer, subject, active) = caseName switch
        {
            "WrongSubject" => (FakeAuthority.BaseAddress, "a-different-bound-subject", true),
            "WrongIssuer" => ("https://someone-else.example", FakeAuthority.DefaultSubject, true),
            _ => (FakeAuthority.BaseAddress, FakeAuthority.DefaultSubject, false)
        };
        await database.SeedBindingAsync(issuer, subject, active);
    }

    /// <summary>An isolated SQLite database for one test, on its own temp file.</summary>
    private sealed class TempBffDatabase : IAsyncDisposable
    {
        private TempBffDatabase(string path)
        {
            Path = path;
            ConnectionString = $"Data Source={path};Pooling=false";
        }

        public string Path { get; }

        public string ConnectionString { get; }

        public static TempBffDatabase CreateUnmigrated() => new(
            System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"bff-admin-{Guid.NewGuid():N}.db"));

        public static async Task<TempBffDatabase> CreateMigratedAsync()
        {
            var database = CreateUnmigrated();
            await database.MigrateAsync();
            return database;
        }

        public static async Task<TempBffDatabase> CreateMigratedWithBindingAsync(string issuer, string subject)
        {
            var database = await CreateMigratedAsync();
            await database.SeedBindingAsync(issuer, subject, active: true);
            return database;
        }

        public async Task MigrateAsync()
        {
            var options = new DbContextOptionsBuilder<ReferenceBffDbContext>()
                .UseReferenceBffSqlite(ConnectionString)
                .Options;
            await using var context = new ReferenceBffDbContext(options);
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
            await new EfCoreServiceInstallationStore<ReferenceBffDbContext>(context)
                .CreatePendingAsync(ReferenceBffServiceMantle.ServiceId, TestContext.Current.CancellationToken);
        }

        public async Task SeedBindingAsync(string issuer, string subject, bool active)
        {
            var options = new DbContextOptionsBuilder<ReferenceBffDbContext>()
                .UseReferenceBffSqlite(ConnectionString)
                .Options;
            await using var context = new ReferenceBffDbContext(options);
            context.ManagementRoleBindings.Add(new ManagementRoleBindingEntity
            {
                Id = Guid.NewGuid(),
                Role = ManagementRoleBindingEntity.SystemAdministratorRole,
                Issuer = issuer,
                Subject = subject,
                IsActive = active,
                CreatedAtUtc = DateTimeOffset.UtcNow
            });
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        public async Task DeactivateBindingAsync()
        {
            var options = new DbContextOptionsBuilder<ReferenceBffDbContext>()
                .UseReferenceBffSqlite(ConnectionString)
                .Options;
            await using var context = new ReferenceBffDbContext(options);
            var binding = await context.ManagementRoleBindings
                .SingleAsync(TestContext.Current.CancellationToken);
            binding.IsActive = false;
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        public ValueTask DisposeAsync()
        {
            TryDelete(Path);
            TryDelete(Path + "-journal");
            TryDelete(Path + "-wal");
            TryDelete(Path + "-shm");
            return ValueTask.CompletedTask;
        }

        private static void TryDelete(string file)
        {
            try
            {
                if (File.Exists(file))
                {
                    File.Delete(file);
                }
            }
            catch (IOException)
            {
                // Best-effort cleanup of this test's isolated file.
            }
        }
    }

    /// <summary>
    /// Fails every UserInfo leg with a transport failure while leaving discovery traffic working.
    /// </summary>
    private sealed class ThrowingUserInfoHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            request.RequestUri!.AbsolutePath.EndsWith("/userinfo", StringComparison.Ordinal)
                ? Task.FromException<HttpResponseMessage>(
                    new HttpRequestException("The synthetic upstream transport failure."))
                : base.SendAsync(request, cancellationToken);
    }

    /// <summary>
    /// Holds the one binding query on a deterministic gate; the caller's token releases it.
    /// </summary>
    private sealed class BlockingDbInterceptor : DbCommandInterceptor
    {
        private readonly TaskCompletionSource release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private readonly TaskCompletionSource entered =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task Release => release.Task;

        /// <summary>Completes when the query has arrived and parked — the arrival evidence.</summary>
        public Task Entered => entered.Task;

        public bool Observed { get; private set; }

        public override ValueTask<InterceptionResult<System.Data.Common.DbDataReader>>
            ReaderExecutingAsync(
                DbCommand command,
                CommandEventData eventData,
                InterceptionResult<System.Data.Common.DbDataReader> result,
                CancellationToken cancellationToken = default)
        {
            if (!command.CommandText.Contains("management_role_bindings", StringComparison.Ordinal))
                return ValueTask.FromResult(result);
            Observed = true;
            entered.TrySetResult();
            return WaitAsync(cancellationToken);

            async ValueTask<InterceptionResult<System.Data.Common.DbDataReader>> WaitAsync(CancellationToken token)
            {
                await release.Task.WaitAsync(token);
                return result;
            }
        }
    }

    /// <summary>
    /// Cancels through an internal token — never the caller's — so the boundary maps to 503.
    /// </summary>
    private sealed class InternallyCancellableDbInterceptor : DbCommandInterceptor
    {
        private readonly CancellationTokenSource internalSource = new();

        private readonly TaskCompletionSource entered =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>Completes when the query has arrived and parked — the arrival evidence.</summary>
        public Task Entered => entered.Task;

        public bool Observed { get; private set; }

        public void CancelInternally() => internalSource.Cancel();

        public override ValueTask<InterceptionResult<System.Data.Common.DbDataReader>>
            ReaderExecutingAsync(
                DbCommand command,
                CommandEventData eventData,
                InterceptionResult<System.Data.Common.DbDataReader> result,
                CancellationToken cancellationToken = default)
        {
            if (!command.CommandText.Contains("management_role_bindings", StringComparison.Ordinal))
                return ValueTask.FromResult(result);
            Observed = true;
            entered.TrySetResult();
            return WaitAsync();

            async ValueTask<InterceptionResult<System.Data.Common.DbDataReader>> WaitAsync()
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, internalSource.Token);
                return result;
            }
        }
    }

    /// <summary>
    /// Replaces Discovery for one identity-check leg: the boundary signals its arrival, waits
    /// for the caller to abandon the request, and still completes normally with a configuration
    /// that carries no UserInfo endpoint. The observation after the boundary must throw, never
    /// classify the missing endpoint as unavailable.
    /// </summary>
    private sealed class DiscoveryBoundaryProbeManager(
        IConfigurationManager<OpenIdConnectConfiguration> inner,
        TaskCompletionSource entered) : IConfigurationManager<OpenIdConnectConfiguration>
    {
        private int _calls;

        public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
        {
            if (Interlocked.Increment(ref _calls) == 1)
            {
                entered.TrySetResult();
                try
                {
                    await Task.Delay(Timeout.InfiniteTimeSpan, cancel);
                }
                catch (OperationCanceledException)
                {
                    // The caller abandoned the request; the boundary completes anyway.
                }

                return new OpenIdConnectConfiguration();
            }

            return await inner.GetConfigurationAsync(cancel);
        }

        public void RequestRefresh() => inner.RequestRefresh();
    }

    /// <summary>
    /// Wraps the UserInfo leg so the response payload read cancels the caller's own source and
    /// still completes: the observation point after the JSON read must throw before any verdict.
    /// </summary>
    private sealed class CancelOnContentReadHandler(CancellationTokenSource callerSource) : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = await base.SendAsync(request, cancellationToken);
            var payload = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            response.Content = new PayloadCancellingContent(payload, callerSource);
            return response;
        }
    }

    /// <summary>
    /// A payload that abandons the caller at the exact moment the identity check reads it, then
    /// hands over the complete body — the deterministic "cancelled after the JSON read" shape.
    /// </summary>
    private sealed class PayloadCancellingContent(byte[] payload, CancellationTokenSource callerSource)
        : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            callerSource.Cancel();
            return stream.WriteAsync(payload).AsTask();
        }

        protected override bool TryComputeLength(out long length)
        {
            length = payload.Length;
            return true;
        }
    }
}
