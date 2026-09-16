using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host.Services;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The credential outcomes of <c>POST /oauth2/login</c>: the four <c>EV-17</c> failure classes are
/// one indistinguishable local answer with exactly one committed counter/audit unit behind each,
/// the shared lockout standard accumulates across this route and the existing Password grant, and
/// a passing credential check is answered with the fixed local 501 and zero writes because the
/// <c>EV-01</c> success transaction belongs to the orchestration slice.
/// </summary>
public sealed class OAuthLoginCredentialTests : IClassFixture<IdentityServerFixture>
{
    private const string ActiveUser = "login_active_user";
    private const string ActivePassword = "Login-Active-123!";
    private const string DisabledUser = "login_disabled_user";
    private const string DisabledPassword = "Login-Disabled-123!";
    private const string LockedUser = "login_locked_user";
    private const string LockedPassword = "Login-Locked-123!";
    private const string UnknownUser = "login-unknown-user";
    private const string LockoutUser = "login_lockout_user";
    private const string LockoutPassword = "Login-Lockout-123!";
    private const string MixedUser = "login_mixed_user";
    private const string MixedPassword = "Login-Mixed-123!";
    private const string PassUser = "login_pass_user";
    private const string PassPassword = "Login-Pass-123!";

    private readonly IdentityServerFixture _fixture;

    public OAuthLoginCredentialTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- Acceptance 9: the four failure classes are one local answer ----

    [Fact]
    public async Task TheFourFailureClasses_AreByteIdentical_AndCommitOneAuditUnitEach()
    {
        await SeedUserAsync(_fixture.Services, ActiveUser, ActivePassword);
        await SeedUserAsync(_fixture.Services, DisabledUser, DisabledPassword, isActive: false);
        await SeedUserAsync(_fixture.Services, LockedUser, LockedPassword);
        await SeedLoginAttemptAsync(
            _fixture.Services,
            LockedUser,
            failedAttempts: IdentityConstants.MaxFailedLoginAttempts,
            lockoutUntil: DateTimeOffset.UtcNow.AddMinutes(IdentityConstants.LoginLockoutMinutes));

        using var client = _fixture.CreateHttpClient();
        var session = await BeginLoginAsync(_fixture.Services, client);

        var submissions = new (string Username, string Password)[]
        {
            (UnknownUser, "Does-Not-Matter-1!"),
            (ActiveUser, "Wrong-Password-1!"),
            (DisabledUser, DisabledPassword),
            (LockedUser, LockedPassword),
        };

        var bodies = new List<string>();
        var headers = new List<IReadOnlyList<KeyValuePair<string, string>>>();
        foreach (var (username, password) in submissions)
        {
            using var request = CreateLoginPost(
                fields: LoginFields(session, username, password),
                cookieHeader: CookieHeaderFor(session),
                correlationId: FixedCorrelationId);
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            AssertLoginSecurityHeaders(response);
            // EV-17 keeps the browser's existing cookie; no response writes a new one.
            Assert.Null(GetSetCookieHeader(response, CookieName));
            bodies.Add(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            headers.Add(HeaderSnapshot(response));
        }

        // Status, header set (beyond Date), and body bytes are one answer for all four classes.
        Assert.All(bodies, body => Assert.Equal(bodies[0], body));
        Assert.All(headers, header => Assert.Equal(headers[0], header));

        // The generic page carries the fixed notice, the reusable pair, and no submitted value.
        Assert.Contains("Sign-in failed", bodies[0], StringComparison.Ordinal);
        Assert.Contains($"name=\"login_handle\" value=\"{session.Handle}\"", bodies[0], StringComparison.Ordinal);
        Assert.Contains($"value=\"{session.Token}\"", bodies[0], StringComparison.Ordinal);
        foreach (var (username, password) in submissions)
        {
            Assert.DoesNotContain(username, bodies[0], StringComparison.Ordinal);
            Assert.DoesNotContain(password, bodies[0], StringComparison.Ordinal);
        }

        Assert.DoesNotContain("Wrong username or password", bodies[0], StringComparison.Ordinal);
        Assert.DoesNotContain("Account is disabled", bodies[0], StringComparison.Ordinal);
        Assert.DoesNotContain("Account is locked", bodies[0], StringComparison.Ordinal);

        // Each submission committed exactly one audit row with the fixed EV-17 field set. The
        // fixture database is shared by the class, so the scan is scoped to this test's accounts.
        var scopedUsernames = submissions.Select(submission => submission.Username).ToHashSet();
        var histories = (await GetLoginHistoriesAsync(_fixture.Services))
            .Where(history => scopedUsernames.Contains(history.Username))
            .ToList();
        Assert.Equal(4, histories.Count);
        Assert.All(histories, history =>
        {
            Assert.Equal(OidcLoginFailureRecorder.OidcLoginAuthMethod, history.AuthMethod);
            Assert.Equal("login_failure", history.EventType);
            Assert.Null(history.AccountId);
            Assert.Equal(AppId, history.AppId);
            Assert.Equal(FixedCorrelationId, history.CorrelationId);
        });
        Assert.Equal(
            submissions.Select(submission => submission.Username),
            histories.Select(history => history.Username));
        Assert.Equal("Wrong username or password", histories[0].FailureReason);
        Assert.Equal("Wrong username or password", histories[1].FailureReason);
        Assert.Equal("Account is disabled", histories[2].FailureReason);
        Assert.StartsWith("Account is locked", histories[3].FailureReason, StringComparison.Ordinal);

        // Only the wrong-password class moved the shared counter; the pre-armed lock stayed put.
        var attempts = await GetLoginAttemptsAsync(_fixture.Services);
        var wrongPasswordAttempt = Assert.Single(attempts, attempt =>
            attempt.UsernameNormalized == IdentityValueNormalizer.Normalize(ActiveUser));
        Assert.Equal(1, wrongPasswordAttempt.FailedAttempts);
        Assert.Null(wrongPasswordAttempt.LockoutUntil);
        var lockedAttempt = Assert.Single(attempts, attempt =>
            attempt.UsernameNormalized == IdentityValueNormalizer.Normalize(LockedUser));
        Assert.Equal(IdentityConstants.MaxFailedLoginAttempts, lockedAttempt.FailedAttempts);
        Assert.NotNull(lockedAttempt.LockoutUntil);

        // The continuation stays unconsumed and admits another attempt.
        using var retry = CreateLoginPost(
            fields: LoginFields(session, UnknownUser, "Does-Not-Matter-2!"),
            cookieHeader: CookieHeaderFor(session),
            correlationId: FixedCorrelationId);
        using var retryResponse = await client.SendAsync(retry, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, retryResponse.StatusCode);
        Assert.Equal(
            5,
            (await GetLoginHistoriesAsync(_fixture.Services))
                .Count(history => scopedUsernames.Contains(history.Username)));
        await AssertContinuationUnconsumedAsync();
    }

    // ---- Acceptance 10: one shared lockout standard across both entry points ----

    [Fact]
    public async Task FiveRouteFailures_LockTheSharedCounterForTheRouteAndThePasswordGrant()
    {
        await SeedUserAsync(_fixture.Services, LockoutUser, LockoutPassword);
        using var client = _fixture.CreateHttpClient();
        var session = await BeginLoginAsync(_fixture.Services, client);

        var bodies = new List<string>();
        for (var attempt = 0; attempt < IdentityConstants.MaxFailedLoginAttempts; attempt++)
        {
            using var request = CreateLoginPost(
                fields: LoginFields(session, LockoutUser, "Wrong-Lockout-Pw!"),
                cookieHeader: CookieHeaderFor(session),
                correlationId: FixedCorrelationId);
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            bodies.Add(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }

        Assert.All(bodies, body => Assert.Equal(bodies[0], body));

        var locked = await GetLockedAttemptAsync(LockoutUser);
        Assert.Equal(IdentityConstants.MaxFailedLoginAttempts, locked.FailedAttempts);
        Assert.NotNull(locked.LockoutUntil);
        var window = locked.LockoutUntil!.Value - DateTimeOffset.UtcNow;
        Assert.InRange(
            window,
            TimeSpan.FromMinutes(IdentityConstants.LoginLockoutMinutes - 2),
            TimeSpan.FromMinutes(IdentityConstants.LoginLockoutMinutes + 1));

        // The locked-out account is rejected by both entry points even with the right password,
        // and neither rejection moves the counter.
        using var routeRequest = CreateLoginPost(
            fields: LoginFields(session, LockoutUser, LockoutPassword),
            cookieHeader: CookieHeaderFor(session),
            correlationId: FixedCorrelationId);
        using var routeResponse = await client.SendAsync(routeRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, routeResponse.StatusCode);
        Assert.Equal(
            bodies[0],
            await routeResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        using var grantResponse = await PostPasswordGrantAsync(LockoutUser, LockoutPassword);
        Assert.Equal(HttpStatusCode.BadRequest, grantResponse.StatusCode);

        var stillLocked = await GetLockedAttemptAsync(LockoutUser);
        Assert.Equal(IdentityConstants.MaxFailedLoginAttempts, stillLocked.FailedAttempts);
        Assert.Equal(locked.LockoutUntil, stillLocked.LockoutUntil);
        await AssertContinuationUnconsumedAsync();
    }

    [Fact]
    public async Task RouteAndGrantFailures_AccumulateIntoTheSameCounter()
    {
        await SeedUserAsync(_fixture.Services, MixedUser, MixedPassword);

        // Two failures through the existing Password grant...
        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var response = await PostPasswordGrantAsync(MixedUser, "Wrong-Mixed-Pw!");
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        var afterGrant = await GetLockedAttemptAsync(MixedUser);
        Assert.Equal(2, afterGrant.FailedAttempts);
        Assert.Null(afterGrant.LockoutUntil);

        // ...plus three through this route lock the one shared counter row.
        using var client = _fixture.CreateHttpClient();
        var session = await BeginLoginAsync(_fixture.Services, client);
        for (var attempt = 0; attempt < 3; attempt++)
        {
            using var request = CreateLoginPost(
                fields: LoginFields(session, MixedUser, "Wrong-Mixed-Pw!"),
                cookieHeader: CookieHeaderFor(session),
                correlationId: FixedCorrelationId);
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        var afterRoute = await GetLockedAttemptAsync(MixedUser);
        Assert.Equal(IdentityConstants.MaxFailedLoginAttempts, afterRoute.FailedAttempts);
        Assert.NotNull(afterRoute.LockoutUntil);
        var attempts = await GetLoginAttemptsAsync(_fixture.Services);
        Assert.Single(attempts, attempt =>
            attempt.UsernameNormalized == IdentityValueNormalizer.Normalize(MixedUser));
    }

    // ---- Acceptance 11: the not-yet-implemented success path changes nothing ----

    [Fact]
    public async Task PassingCredentials_AreAnsweredWithTheFixed501AndChangeNothing()
    {
        await SeedUserAsync(_fixture.Services, PassUser, PassPassword);
        await SeedLoginAttemptAsync(_fixture.Services, PassUser, failedAttempts: 2);

        using var client = _fixture.CreateHttpClient();
        var session = await BeginLoginAsync(_fixture.Services, client);
        var cancelSession = await BeginLoginAsync(_fixture.Services, client);
        var before = await DumpLoginTablesAsync(_fixture.Services);

        using var request = CreateLoginPost(
            fields: LoginFields(session, PassUser, PassPassword),
            cookieHeader: CookieHeaderFor(session),
            correlationId: FixedCorrelationId);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotImplemented, response.StatusCode);
        AssertLoginSecurityHeaders(response);
        Assert.Null(GetSetCookieHeader(response, CookieName));
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("Login is not available", body, StringComparison.Ordinal);

        // The cancel exit on this canary continuation revalidates to a local error (the client
        // never registered the stored redirect URI) and writes nothing; the passing-credential
        // exit keeps the fixed 501.
        using var cancelRequest = CreateLoginPost(
            fields: CancelFields(cancelSession),
            cookieHeader: CookieHeaderFor(cancelSession),
            correlationId: FixedCorrelationId);
        using var cancelResponse = await client.SendAsync(cancelRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, cancelResponse.StatusCode);
        AssertLoginSecurityHeaders(cancelResponse);
        Assert.Null(cancelResponse.Headers.Location);

        // Zero writes: the prior failure count survives (no Clear), no success audit exists, and
        // the continuation stays unconsumed for the orchestration slice.
        Assert.Equal(before, await DumpLoginTablesAsync(_fixture.Services));
        var attempt = await GetLockedAttemptAsync(PassUser);
        Assert.Equal(2, attempt.FailedAttempts);
        Assert.Null(attempt.LockoutUntil);
        var histories = await GetLoginHistoriesAsync(_fixture.Services);
        Assert.DoesNotContain(histories, history => history.EventType == "login_success");
    }

    private async Task<HttpResponseMessage> PostPasswordGrantAsync(string username, string password)
    {
        var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"{IdentityServerFixture.GatewayAppId}:{IdentityServerFixture.GatewayAppSecret}")));
        return await http.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = IdentityConstants.GrantTypePassword,
                ["username"] = username,
                ["password"] = password
            }),
            TestContext.Current.CancellationToken);
    }

    private async Task<LoginAttemptEntity> GetLockedAttemptAsync(string username)
    {
        var normalized = IdentityValueNormalizer.Normalize(username);
        var attempts = await GetLoginAttemptsAsync(_fixture.Services);
        return attempts.Single(attempt => attempt.UsernameNormalized == normalized);
    }

    private async Task AssertContinuationUnconsumedAsync()
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        Assert.All(
            await dbContext.AuthorizationRequests.AsNoTracking()
                .ToListAsync(TestContext.Current.CancellationToken),
            continuation => Assert.Null(continuation.ConsumedAt));
    }
}
