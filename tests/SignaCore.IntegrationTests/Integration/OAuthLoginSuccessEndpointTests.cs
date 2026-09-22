using System.Data.Common;
using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ServiceMantle.AspNetCore.Management;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Security;
using SignaCore.Host.Services;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The <c>EV-01</c> success contract of <c>POST /oauth2/login</c>, driven through the real
/// <c>GET /oauth2/authorize</c> → <c>GET /oauth2/login</c> → <c>POST /oauth2/login</c> browser
/// front half (<c>SC-01</c>, <c>AC-05</c>): the current-policy revalidation, the single success
/// transaction (continuation consumption, <c>PS-04</c> session, <c>PS-05</c> code, failure-counter
/// clear, login info, and <c>login_success</c> audit), the post-commit <c>PS-18</c> identity
/// cookie, and the <c>PS-17</c> redirect with <c>code</c>, the byte-for-byte <c>state</c>, and
/// <c>iss</c>. Drift after the form was opened answers locally (<c>SC-02</c>/<c>SC-03</c>) or as
/// the safe scope error (<c>SC-04</c>) with zero writes; concurrent duplicate submissions produce
/// exactly one winner (<c>EV-03</c> race); cancellation before the commit rolls the whole unit
/// back and the same handle retries successfully (<c>EV-18</c>/<c>SC-20</c>).
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class OAuthLoginSuccessEndpointTests : IClassFixture<IdentityServerFixture>
{
    private const string SuccessUser = "login_success_user";
    private const string SuccessPassword = "Login-Success-123!";
    private const string CookieUser = "login_cookie_user";
    private const string CookiePassword = "Login-Cookie-123!";
    private const string DriftPassword = "Login-Drift-123!";
    private const string ScopeDriftUser = "login_scope_drift_user";
    private const string ScopeDriftPassword = "Login-ScopeDrift-1!";
    private const string FailureUser = "login_ev17_user";
    private const string FailurePassword = "Login-Ev17-123!";
    private const string ConcurrentUser = "login_concurrent_user";
    private const string ConcurrentPassword = "Login-Concurrent-1!";
    private const string TwoFlowUser = "login_two_flow_user";
    private const string TwoFlowPassword = "Login-TwoFlow-123!";
    private const string CommitUser = "login_commit_user";
    private const string CommitPassword = "Login-Commit-123!";
    private const string AuditFailUser = "login_audit_fail_user";
    private const string AuditFailPassword = "Login-AuditFail-1!";

    private const string SecondState = "success-second-state-0123456789";
    private const string SecondNonce = "success-second-nonce-0123456789";

    private readonly IdentityServerFixture _fixture;

    public OAuthLoginSuccessEndpointTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- Acceptance 1: the committed success transaction and the PS-17 redirect ----

    [Fact]
    public async Task Success_CommitsTheWholeTransaction_AndRedirectsWithCodeStateAndIss()
    {
        var accountId = await SeedUserAsync(_fixture.Services, SuccessUser, SuccessPassword);
        await SeedLoginAttemptAsync(_fixture.Services, SuccessUser, failedAttempts: 2);
        using var client = _fixture.CreateNonRedirectingHttpClient();
        var session = await BeginSuccessLoginViaAuthorizeAsync(_fixture.Services, client);

        var before = DateTimeOffset.UtcNow;
        using var response = await client.SendAsync(
            CreateLoginPost(
                fields: LoginFields(session, SuccessUser, SuccessPassword),
                cookieHeader: CookieHeaderFor(session),
                correlationId: FixedCorrelationId),
            TestContext.Current.CancellationToken);
        var after = DateTimeOffset.UtcNow;

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var code = AssertSuccessLocation(response.Headers.Location!.ToString(), SuccessState);

        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var cancellationToken = TestContext.Current.CancellationToken;

        // The continuation is consumed at the single captured instant of the request.
        var continuation = await GetContinuationAsync(dbContext, session.Handle);
        Assert.NotNull(continuation.ConsumedAt);

        // Exactly one session, bound to the credential that passed, at the same instant.
        var credential = await dbContext.PasswordCredentials.AsNoTracking()
            .SingleAsync(row => row.AccountId == accountId, cancellationToken);
        var dbSession = Assert.Single(await GetSessionsAsync(dbContext, accountId));
        Assert.Equal(credential.Id, dbSession.PasswordCredentialId);
        Assert.Equal(IdentityConstants.AuthMethodPassword, dbSession.AuthMethod);
        Assert.Equal(continuation.ConsumedAt, dbSession.AuthTime);
        Assert.Equal(dbSession.AuthTime, dbSession.LastSeenAt);
        Assert.InRange(dbSession.AuthTime, before, after);
        Assert.Equal(
            IdentityConstants.IdentitySessionIdleTimeoutMinutes,
            (dbSession.IdleExpiresAt - dbSession.AuthTime).TotalMinutes);
        Assert.Equal(
            IdentityConstants.MaxIdentitySessionAgeSeconds,
            (dbSession.AbsoluteExpiresAt - dbSession.AuthTime).TotalSeconds);

        // Exactly one code, bound to that session and to the revalidated request snapshot.
        var dbCode = Assert.Single(await GetCodesAsync(dbContext, accountId));
        Assert.Equal(dbSession.Id, dbCode.IdentitySessionId);
        Assert.Equal(continuation.AppRegistrationId, dbCode.AppRegistrationId);
        Assert.Equal(SuccessRegisteredUri, dbCode.RedirectUri);
        Assert.Equal(SuccessScope, dbCode.Scope);
        Assert.Equal(SuccessNonce, dbCode.Nonce);
        Assert.Equal(SuccessChallenge, dbCode.CodeChallenge);
        Assert.Equal(dbSession.AuthTime, dbCode.AuthTime);
        Assert.Equal(dbSession.AuthTime, dbCode.CreatedAt);
        Assert.Null(dbCode.ConsumedAt);
        Assert.Equal(
            IdentityConstants.AuthorizationCodeLifetimeSeconds,
            (dbCode.ExpiresAt - dbCode.CreatedAt).TotalSeconds);

        // The plaintext code from the Location resolves to exactly this row, unconsumed.
        var codeStore = scope.ServiceProvider.GetRequiredService<IAuthorizationCodeStore>();
        var lookup = await codeStore.FindAsync(code, DateTimeOffset.UtcNow, cancellationToken);
        Assert.Equal(AuthorizationCodeState.Unconsumed, lookup.State);
        Assert.Equal(dbCode.Id, lookup.Entity!.Id);

        // The prior failure counter is cleared and the login info is updated in the same unit.
        Assert.DoesNotContain(
            await dbContext.LoginAttempts.AsNoTracking().ToListAsync(cancellationToken),
            attempt => attempt.UsernameNormalized == IdentityValueNormalizer.Normalize(SuccessUser));
        var account = await dbContext.Accounts.AsNoTracking()
            .SingleAsync(row => row.Id == accountId, cancellationToken);
        Assert.Equal(IdentityConstants.AuthMethodPassword, account.LastLoginMethod);
        Assert.Equal(1, account.TotalLoginCount);
        Assert.NotNull(account.LastLoginAt);

        // Exactly one oidc_login/login_success history row with the fixed field set.
        var history = Assert.Single(await dbContext.LoginHistories.AsNoTracking()
            .Where(row => row.AccountId == accountId)
            .ToListAsync(cancellationToken));
        Assert.Equal(OidcLoginFailureRecorder.OidcLoginAuthMethod, history.AuthMethod);
        Assert.Equal("login_success", history.EventType);
        Assert.Equal(SuccessUser, history.Username);
        Assert.Null(history.FailureReason);
        Assert.Equal(SuccessAppId, history.AppId);
        Assert.Equal(FixedCorrelationId, history.CorrelationId);

        // A replay of the same handle after the commit is the local 400 of EV-03.
        using var replay = await client.SendAsync(
            CreateLoginPost(
                fields: LoginFields(session, SuccessUser, SuccessPassword),
                cookieHeader: CookieHeaderFor(session)),
            cancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.False(replay.Headers.Contains("Location"));
        Assert.Null(GetSetCookieHeader(replay, IdentitySessionDefaults.CookieName));
        Assert.Equal(1, (await GetSessionsAsync(dbContext, accountId)).Count);
        Assert.Equal(1, (await GetCodesAsync(dbContext, accountId)).Count);
    }

    // ---- Acceptance 2 + 12: the post-commit PS-18 identity cookie ----

    [Fact]
    public async Task Success_WritesExactlyOneIdentityCookie_WithTheFreshSessionId()
    {
        var accountId = await SeedUserAsync(_fixture.Services, CookieUser, CookiePassword);
        using var client = _fixture.CreateNonRedirectingHttpClient();
        var session = await BeginSuccessLoginViaAuthorizeAsync(_fixture.Services, client);

        // The browser may present an old identity cookie; its session id is never reused.
        var staleSessionId = Guid.NewGuid();
        var staleCookie = await IssueIdentityCookieAsync(_fixture.Services, staleSessionId);

        using var response = await client.SendAsync(
            CreateLoginPost(
                fields: LoginFields(session, CookieUser, CookiePassword),
                cookieHeader: CookieHeaderFor(session) + "; " + staleCookie,
                correlationId: FixedCorrelationId),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);

        // Exactly one Set-Cookie: the identity cookie, never the management cookie.
        var setCookies = response.Headers.NonValidated
            .Where(header => string.Equals(header.Key, "Set-Cookie", StringComparison.OrdinalIgnoreCase))
            .SelectMany(header => header.Value!)
            .ToList();
        var identitySetCookie = Assert.Single(setCookies);
        Assert.StartsWith(
            IdentitySessionDefaults.CookieName + "=", identitySetCookie, StringComparison.Ordinal);
        Assert.Null(GetSetCookieHeader(response, "__Host-ServiceMantle.Management"));

        // The PS-18 wire attributes: host-only, secure, http-only, lax, root path, no domain, and
        // no expiry (IsPersistent = false keeps it a browser session cookie).
        Assert.Contains("; path=/", identitySetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("; secure", identitySetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("; samesite=lax", identitySetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("; httponly", identitySetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("; domain", identitySetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("; expires", identitySetCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("; max-age", identitySetCookie, StringComparison.OrdinalIgnoreCase);

        // The payload the identity scheme reads back is exactly one opaque session id claim, and
        // it is the fresh database session, not the stale presented one.
        var cookieHeader = identitySetCookie.Split(';')[0];
        var authenticated = await AuthenticateIdentityCookieAsync(_fixture.Services, cookieHeader);
        Assert.True(authenticated.Succeeded);
        var identity = Assert.Single(authenticated.Principal!.Identities);
        Assert.Equal(IdentitySessionDefaults.AuthenticationScheme, identity.AuthenticationType);
        var claim = Assert.Single(identity.Claims);
        Assert.Equal(IdentitySessionDefaults.SessionIdClaim, claim.Type);

        using (var scope = _fixture.Services.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var dbSession = Assert.Single(await GetSessionsAsync(dbContext, accountId));
            Assert.Equal(dbSession.Id.ToString(), claim.Value);
            Assert.NotEqual(staleSessionId, dbSession.Id);
        }

        // The identity payload never unprotects under the management purpose.
        var identityValue = cookieHeader[(IdentitySessionDefaults.CookieName.Length + 1)..];
        using (var scope = _fixture.Services.CreateScope())
        {
            var monitor = scope.ServiceProvider
                .GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>();
            var managementFormat =
                monitor.Get(ManagementSessionDefaults.AuthenticationScheme).TicketDataFormat!;
            Assert.Null(managementFormat.Unprotect(identityValue));
        }
    }

    // ---- Acceptance 3: SC-02/SC-03 drift is a local 400 with zero writes ----

    [Theory]
    [InlineData("deactivate")]
    [InlineData("disable-authorization-code")]
    [InlineData("remove-redirect-uri")]
    public async Task Success_WhenRedirectTrustDrifted_IsALocal400WithZeroWrites(string drift)
    {
        // One dedicated account per theory case: the class shares its fixture database.
        var username = "login_drift_" + drift.Replace('-', '_');
        var accountId = await SeedUserAsync(_fixture.Services, username, DriftPassword);
        await SeedLoginAttemptAsync(_fixture.Services, username, failedAttempts: 2);
        using var client = _fixture.CreateNonRedirectingHttpClient();
        var session = await BeginSuccessLoginViaAuthorizeAsync(_fixture.Services, client);
        await ApplyDriftAsync(drift);

        try
        {
            using var response = await client.SendAsync(
                CreateLoginPost(
                    fields: LoginFields(session, username, DriftPassword),
                    cookieHeader: CookieHeaderFor(session),
                    correlationId: FixedCorrelationId),
                TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.False(response.Headers.Contains("Location"));
            Assert.Null(GetSetCookieHeader(response, IdentitySessionDefaults.CookieName));
            AssertLoginSecurityHeaders(response);
            await AssertZeroWritesAsync(accountId, session.Handle, username, expectFailedAttempts: 2);
        }
        finally
        {
            await RestoreDriftAsync(drift);
        }
    }

    // ---- Acceptance 4: SC-04 scope drift is the safe error redirect with zero writes ----

    [Fact]
    public async Task Success_WhenTheScopeDrifted_RedirectsInvalidScopeWithZeroWrites()
    {
        var accountId = await SeedUserAsync(_fixture.Services, ScopeDriftUser, ScopeDriftPassword);
        await SeedLoginAttemptAsync(_fixture.Services, ScopeDriftUser, failedAttempts: 2);
        using var client = _fixture.CreateNonRedirectingHttpClient();
        var session = await BeginSuccessLoginViaAuthorizeAsync(_fixture.Services, client);
        await MutateSuccessAppAsync(app => app.AllowedScopes = "openid");

        try
        {
            using var response = await client.SendAsync(
                CreateLoginPost(
                    fields: LoginFields(session, ScopeDriftUser, ScopeDriftPassword),
                    cookieHeader: CookieHeaderFor(session),
                    correlationId: FixedCorrelationId),
                TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.Null(GetSetCookieHeader(response, IdentitySessionDefaults.CookieName));
            var issuer = _fixture.Services.GetRequiredService<JwtOptions>().Issuer;
            var expectedLocation =
                SuccessRegisteredUri
                + "&error=invalid_scope"
                + $"&error_description={Uri.EscapeDataString(OidcAuthorizationErrorDescriptions.InvalidScope)}"
                + $"&state={Uri.EscapeDataString(SuccessState)}"
                + $"&iss={Uri.EscapeDataString(issuer)}";
            Assert.Equal(expectedLocation, response.Headers.Location!.AbsoluteUri);

            // No code was issued — not even a narrowed one — and nothing was consumed or counted.
            await AssertZeroWritesAsync(accountId, session.Handle, ScopeDriftUser, expectFailedAttempts: 2);
        }
        finally
        {
            await MutateSuccessAppAsync(app => app.AllowedScopes = SuccessScope);
        }
    }

    // ---- Acceptance 5: the EV-17 contract survives on a trusted continuation ----

    [Fact]
    public async Task WrongPassword_OnASuccessContinuation_KeepsTheEv17Contract()
    {
        var accountId = await SeedUserAsync(_fixture.Services, FailureUser, FailurePassword);
        using var client = _fixture.CreateNonRedirectingHttpClient();
        var session = await BeginSuccessLoginViaAuthorizeAsync(_fixture.Services, client);

        using var response = await client.SendAsync(
            CreateLoginPost(
                fields: LoginFields(session, FailureUser, "Wrong-Password-1!"),
                cookieHeader: CookieHeaderFor(session),
                correlationId: FixedCorrelationId),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.Contains("Location"));
        Assert.Null(GetSetCookieHeader(response, IdentitySessionDefaults.CookieName));
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("Sign-in failed", body, StringComparison.Ordinal);

        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var cancellationToken = TestContext.Current.CancellationToken;
        Assert.Null((await GetContinuationAsync(dbContext, session.Handle)).ConsumedAt);
        Assert.Empty(await GetSessionsAsync(dbContext, accountId));
        Assert.Empty(await GetCodesAsync(dbContext, accountId));
        var history = Assert.Single(await dbContext.LoginHistories.AsNoTracking()
            .Where(row => row.AccountId == null && row.Username == FailureUser)
            .ToListAsync(cancellationToken));
        Assert.Equal("login_failure", history.EventType);
        Assert.Equal(OidcLoginFailureRecorder.OidcLoginAuthMethod, history.AuthMethod);
        var attempt = Assert.Single(await dbContext.LoginAttempts.AsNoTracking()
            .Where(row => row.UsernameNormalized == IdentityValueNormalizer.Normalize(FailureUser))
            .ToListAsync(cancellationToken));
        Assert.Equal(1, attempt.FailedAttempts);
    }

    // ---- Acceptance 6 (SQLite): concurrent duplicate submissions, exactly one winner ----

    [Fact]
    public async Task Success_Concurrently_ExactlyOneRedirectOneSessionOneCode()
    {
        var accountId = await SeedUserAsync(_fixture.Services, ConcurrentUser, ConcurrentPassword);
        using var client = _fixture.CreateNonRedirectingHttpClient();
        var session = await BeginSuccessLoginViaAuthorizeAsync(_fixture.Services, client);

        var responses = await Task.WhenAll(
            client.SendAsync(
                CreateLoginPost(
                    fields: LoginFields(session, ConcurrentUser, ConcurrentPassword),
                    cookieHeader: CookieHeaderFor(session)),
                TestContext.Current.CancellationToken),
            client.SendAsync(
                CreateLoginPost(
                    fields: LoginFields(session, ConcurrentUser, ConcurrentPassword),
                    cookieHeader: CookieHeaderFor(session)),
                TestContext.Current.CancellationToken));

        var winner = Assert.Single(responses, response => response.StatusCode == HttpStatusCode.Found);
        var loser = Assert.Single(responses, response => response.StatusCode == HttpStatusCode.BadRequest);
        Assert.False(loser.Headers.Contains("Location"));
        Assert.Null(GetSetCookieHeader(loser, IdentitySessionDefaults.CookieName));
        Assert.NotNull(GetSetCookieHeader(winner, IdentitySessionDefaults.CookieName));
        AssertSuccessLocation(winner.Headers.Location!.ToString(), SuccessState);

        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        Assert.Single(await GetSessionsAsync(dbContext, accountId));
        Assert.Single(await GetCodesAsync(dbContext, accountId));
        Assert.NotNull((await GetContinuationAsync(dbContext, session.Handle)).ConsumedAt);
        var history = Assert.Single(await dbContext.LoginHistories.AsNoTracking()
            .Where(row => row.AccountId == accountId)
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal("login_success", history.EventType);
    }

    // ---- Acceptance 8: SC-07, two independent continuations in one browser ----

    [Fact]
    public async Task Success_TwoIndependentContinuations_ProduceTwoSessionsAndTwoCodes()
    {
        var accountId = await SeedUserAsync(_fixture.Services, TwoFlowUser, TwoFlowPassword);
        using var client = _fixture.CreateNonRedirectingHttpClient();
        var first = await BeginSuccessLoginViaAuthorizeAsync(_fixture.Services, client);
        var second = await BeginSuccessLoginViaAuthorizeAsync(
            _fixture.Services,
            client,
            state: SecondState,
            nonce: SecondNonce,
            existingCookieValue: first.CookieValue);
        Assert.NotEqual(first.Handle, second.Handle);

        using var firstResponse = await client.SendAsync(
            CreateLoginPost(
                fields: LoginFields(first, TwoFlowUser, TwoFlowPassword),
                cookieHeader: CookieHeaderFor(first),
                correlationId: FixedCorrelationId),
            TestContext.Current.CancellationToken);
        using var secondResponse = await client.SendAsync(
            CreateLoginPost(
                fields: LoginFields(second, TwoFlowUser, TwoFlowPassword),
                cookieHeader: CookieHeaderFor(second),
                correlationId: FixedCorrelationId),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, firstResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Found, secondResponse.StatusCode);
        var firstCode = AssertSuccessLocation(firstResponse.Headers.Location!.ToString(), SuccessState);
        var secondCode = AssertSuccessLocation(secondResponse.Headers.Location!.ToString(), SecondState);
        Assert.NotEqual(firstCode, secondCode);

        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var cancellationToken = TestContext.Current.CancellationToken;
        Assert.Equal(2, (await GetSessionsAsync(dbContext, accountId)).Count);
        Assert.Equal(2, (await GetCodesAsync(dbContext, accountId)).Count);
        Assert.NotNull((await GetContinuationAsync(dbContext, first.Handle)).ConsumedAt);
        Assert.NotNull((await GetContinuationAsync(dbContext, second.Handle)).ConsumedAt);

        // Each code binds its own continuation snapshot and its own session.
        var codeStore = scope.ServiceProvider.GetRequiredService<IAuthorizationCodeStore>();
        var firstLookup = await codeStore.FindAsync(firstCode, DateTimeOffset.UtcNow, cancellationToken);
        var secondLookup = await codeStore.FindAsync(secondCode, DateTimeOffset.UtcNow, cancellationToken);
        Assert.Equal(AuthorizationCodeState.Unconsumed, firstLookup.State);
        Assert.Equal(AuthorizationCodeState.Unconsumed, secondLookup.State);
        Assert.Equal(SuccessNonce, firstLookup.Entity!.Nonce);
        Assert.Equal(SecondNonce, secondLookup.Entity!.Nonce);
        Assert.NotEqual(firstLookup.Entity.IdentitySessionId, secondLookup.Entity.IdentitySessionId);

        // The browser's identity cookie is the later session.
        var secondCookie = GetSetCookieHeader(secondResponse, IdentitySessionDefaults.CookieName);
        Assert.NotNull(secondCookie);
        var authenticated = await AuthenticateIdentityCookieAsync(
            _fixture.Services, secondCookie!.Split(';')[0]);
        Assert.True(authenticated.Succeeded);
        Assert.Equal(
            secondLookup.Entity.IdentitySessionId.ToString(),
            authenticated.Principal!.FindFirst(IdentitySessionDefaults.SessionIdClaim)!.Value);
    }

    // ---- Acceptance 9: SC-20, cancellation before the commit rolls everything back ----

    [Fact]
    public async Task Success_CancelledBeforeTheCommit_RollsBackAndRetriesSuccessfully()
    {
        var accountId = await SeedUserAsync(_fixture.Services, CommitUser, CommitPassword);
        using var cancellation = new CancellationTokenSource();
        var gate = new CompletionCommitGate();
        using var factory = _fixture.WithTestServices(services =>
            services.ConfigureDbContext<IdentityDbContext>(optionsBuilder =>
                optionsBuilder.AddInterceptors(
                    new ArmOnConsumptionUpdateInterceptor(gate),
                    new CancelOnceAtCommitInterceptor(gate, cancellation))));
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        var session = await BeginSuccessLoginViaAuthorizeAsync(factory.Services, client);

        using var cancelled = await client.SendAsync(
            CreateLoginPost(
                fields: LoginFields(session, CommitUser, CommitPassword),
                cookieHeader: CookieHeaderFor(session),
                correlationId: FixedCorrelationId),
            TestContext.Current.CancellationToken);

        Assert.NotEqual(HttpStatusCode.Found, cancelled.StatusCode);
        Assert.False(cancelled.Headers.Contains("Location"));
        Assert.Null(GetSetCookieHeader(cancelled, IdentitySessionDefaults.CookieName));
        Assert.Equal(1, gate.Cancellations);
        await AssertZeroWritesAsync(accountId, session.Handle, CommitUser, expectFailedAttempts: null);

        // The same handle, cookie, and token retry successfully once the unit is no longer
        // cancelled at its commit.
        using var retry = await client.SendAsync(
            CreateLoginPost(
                fields: LoginFields(session, CommitUser, CommitPassword),
                cookieHeader: CookieHeaderFor(session),
                correlationId: FixedCorrelationId),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, retry.StatusCode);
        var code = AssertSuccessLocation(retry.Headers.Location!.ToString(), SuccessState);
        Assert.NotNull(GetSetCookieHeader(retry, IdentitySessionDefaults.CookieName));

        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        Assert.NotNull((await GetContinuationAsync(dbContext, session.Handle)).ConsumedAt);
        var dbSession = Assert.Single(await GetSessionsAsync(dbContext, accountId));
        var dbCode = Assert.Single(await GetCodesAsync(dbContext, accountId));
        Assert.Equal(dbSession.Id, dbCode.IdentitySessionId);
        var codeStore = scope.ServiceProvider.GetRequiredService<IAuthorizationCodeStore>();
        var lookup = await codeStore.FindAsync(code, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
        Assert.Equal(AuthorizationCodeState.Unconsumed, lookup.State);
    }

    // ---- Acceptance 9: an audit failure inside the transaction is atomic ----

    [Fact]
    public async Task Success_WhenTheSuccessAuditFails_IsA500WithZeroWrites()
    {
        var accountId = await SeedUserAsync(_fixture.Services, AuditFailUser, AuditFailPassword);
        using var factory = _fixture.WithTestServices(services =>
        {
            services.RemoveAll<IAuditService>();
            services.AddScoped<IAuditService>(scope => new FailingSuccessAuditService(
                new AuditService(scope.GetRequiredService<ILoginHistoryRepository>())));
        });
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        var session = await BeginSuccessLoginViaAuthorizeAsync(factory.Services, client);

        using var response = await client.SendAsync(
            CreateLoginPost(
                fields: LoginFields(session, AuditFailUser, AuditFailPassword),
                cookieHeader: CookieHeaderFor(session),
                correlationId: FixedCorrelationId),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.False(response.Headers.Contains("Location"));
        Assert.Null(GetSetCookieHeader(response, IdentitySessionDefaults.CookieName));
        await AssertZeroWritesAsync(accountId, session.Handle, AuditFailUser, expectFailedAttempts: null);
    }

    // ---- Helpers ----

    /// <summary>
    /// Asserts the exact <c>PS-17</c> success location — the registered URI (with its own query)
    /// joined by '&amp;', then <c>code</c>, <c>state</c>, and <c>iss</c> in that fixed order — and
    /// returns the plaintext code. The state and code alphabets are URI-unreserved, so the
    /// escaped bytes equal the originals.
    /// </summary>
    private string AssertSuccessLocation(string location, string expectedState)
    {
        var issuer = _fixture.Services.GetRequiredService<JwtOptions>().Issuer;
        var prefix = SuccessRegisteredUri + "&code=";
        var suffix = $"&state={Uri.EscapeDataString(expectedState)}&iss={Uri.EscapeDataString(issuer)}";
        Assert.StartsWith(prefix, location, StringComparison.Ordinal);
        Assert.EndsWith(suffix, location, StringComparison.Ordinal);
        Assert.True(location.Length > prefix.Length + suffix.Length);

        var code = location[prefix.Length..^suffix.Length];
        Assert.Equal(IdentityConstants.AuthorizationCodeLength, code.Length);
        Assert.All(code, character =>
            Assert.True(char.IsAsciiLetterOrDigit(character) || character is '-' or '_'));
        return code;
    }

    /// <summary>
    /// The shared zero-write proof of every rejected success path: the continuation stays
    /// unconsumed, no session or code exists for the account, the failure counter is untouched,
    /// the account login info is untouched, and no <c>login_success</c> audit was written.
    /// </summary>
    private async Task AssertZeroWritesAsync(
        Guid accountId, string handle, string username, int? expectFailedAttempts)
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var cancellationToken = TestContext.Current.CancellationToken;

        Assert.Null((await GetContinuationAsync(dbContext, handle)).ConsumedAt);
        Assert.Empty(await GetSessionsAsync(dbContext, accountId));
        Assert.Empty(await GetCodesAsync(dbContext, accountId));
        Assert.Empty(await dbContext.LoginHistories.AsNoTracking()
            .Where(row => row.EventType == "login_success" && row.AccountId == accountId)
            .ToListAsync(cancellationToken));

        var normalized = IdentityValueNormalizer.Normalize(username);
        var attempts = await dbContext.LoginAttempts.AsNoTracking()
            .Where(row => row.UsernameNormalized == normalized)
            .ToListAsync(cancellationToken);
        if (expectFailedAttempts is { } expected)
        {
            Assert.Equal(expected, Assert.Single(attempts).FailedAttempts);
        }
        else
        {
            Assert.Empty(attempts);
        }

        var account = await dbContext.Accounts.AsNoTracking()
            .SingleAsync(row => row.Id == accountId, cancellationToken);
        Assert.Equal(0, account.TotalLoginCount);
        Assert.Null(account.LastLoginAt);
        Assert.Null(account.LastLoginMethod);
    }

    private static async Task<AuthorizationRequestEntity> GetContinuationAsync(
        IdentityDbContext dbContext, string handle) =>
        await dbContext.AuthorizationRequests.AsNoTracking()
            .SingleAsync(
                row => row.HandleDigest == LoginHandleDigest.Compute(handle),
                TestContext.Current.CancellationToken);

    private static async Task<List<IdentitySessionEntity>> GetSessionsAsync(
        IdentityDbContext dbContext, Guid accountId) =>
        await dbContext.IdentitySessions.AsNoTracking()
            .Where(row => row.AccountId == accountId)
            .ToListAsync(TestContext.Current.CancellationToken);

    private static async Task<List<AuthorizationCodeEntity>> GetCodesAsync(
        IdentityDbContext dbContext, Guid accountId) =>
        await dbContext.AuthorizationCodes.AsNoTracking()
            .Where(row => row.AccountId == accountId)
            .ToListAsync(TestContext.Current.CancellationToken);

    private async Task MutateSuccessAppAsync(Action<AppRegistrationEntity> mutate)
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var app = await dbContext.AppRegistrations
            .SingleAsync(app => app.AppId == SuccessAppId, TestContext.Current.CancellationToken);
        mutate(app);
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    private async Task ApplyDriftAsync(string drift)
    {
        switch (drift)
        {
            case "deactivate":
                await MutateSuccessAppAsync(app => app.IsActive = false);
                break;
            case "disable-authorization-code":
                await MutateSuccessAppAsync(app => app.AllowAuthorizationCode = false);
                break;
            case "remove-redirect-uri":
                using (var scope = _fixture.Services.CreateScope())
                {
                    var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
                    var app = await dbContext.AppRegistrations
                        .Include(entity => entity.RedirectUris)
                        .SingleAsync(
                            app => app.AppId == SuccessAppId,
                            TestContext.Current.CancellationToken);
                    dbContext.AppRedirectUris.RemoveRange(
                        app.RedirectUris.Where(uri => uri.Kind == RedirectUriKind.Redirect));
                    await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
                }

                break;
        }
    }

    private async Task RestoreDriftAsync(string drift)
    {
        switch (drift)
        {
            case "deactivate":
                await MutateSuccessAppAsync(app => app.IsActive = true);
                break;
            case "disable-authorization-code":
                await MutateSuccessAppAsync(app => app.AllowAuthorizationCode = true);
                break;
            case "remove-redirect-uri":
                using (var scope = _fixture.Services.CreateScope())
                {
                    var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
                    var appId = await dbContext.AppRegistrations
                        .Where(app => app.AppId == SuccessAppId)
                        .Select(app => app.Id)
                        .SingleAsync(TestContext.Current.CancellationToken);
                    var exists = await dbContext.AppRedirectUris.AsNoTracking()
                        .AnyAsync(
                            uri => uri.AppRegistrationId == appId
                                && uri.CanonicalUri == SuccessRegisteredUri,
                            TestContext.Current.CancellationToken);
                    if (!exists)
                    {
                        dbContext.AppRedirectUris.Add(new AppRedirectUriEntity
                        {
                            Id = Guid.NewGuid(),
                            AppRegistrationId = appId,
                            Kind = RedirectUriKind.Redirect,
                            CanonicalUri = SuccessRegisteredUri
                        });
                        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
                    }
                }

                break;
        }
    }

    private static async Task<string> IssueIdentityCookieAsync(
        IServiceProvider services, Guid sessionId)
    {
        using var scope = services.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        await context.SignInAsync(
            IdentitySessionDefaults.AuthenticationScheme,
            IdentitySessionPrincipal.Create(sessionId));
        var setCookie = Assert.Single(context.Response.Headers["Set-Cookie"].ToArray());
        return setCookie.Split(';')[0];
    }

    private static async Task<AuthenticateResult> AuthenticateIdentityCookieAsync(
        IServiceProvider services, string cookieHeader)
    {
        using var scope = services.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        context.Request.Headers.Cookie = cookieHeader;
        return await context.AuthenticateAsync(IdentitySessionDefaults.AuthenticationScheme);
    }

    private sealed class CompletionCommitGate
    {
        public bool Armed;
        public int Cancellations;
    }

    /// <summary>Arms the gate when the continuation consumption UPDATE runs.</summary>
    private sealed class ArmOnConsumptionUpdateInterceptor(CompletionCommitGate gate)
        : DbCommandInterceptor
    {
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            ArmIfConsumptionUpdate(command);
            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            ArmIfConsumptionUpdate(command);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }

        private void ArmIfConsumptionUpdate(DbCommand command)
        {
            if (!gate.Armed
                && command.CommandText.StartsWith("UPDATE", StringComparison.OrdinalIgnoreCase)
                && command.CommandText.Contains(
                    "authorization_requests", StringComparison.OrdinalIgnoreCase))
            {
                gate.Armed = true;
            }
        }
    }

    /// <summary>
    /// Cancels exactly once at the armed success-transaction commit (<c>EV-18</c>): the whole unit
    /// rolls back, and a later submission of the same handle commits normally.
    /// </summary>
    private sealed class CancelOnceAtCommitInterceptor(
        CompletionCommitGate gate,
        CancellationTokenSource cancellation) : DbTransactionInterceptor
    {
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(
            DbTransaction transaction,
            TransactionEventData eventData,
            InterceptionResult result,
            CancellationToken cancellationToken = default)
        {
            if (gate.Armed && gate.Cancellations == 0)
            {
                gate.Cancellations++;
                cancellation.Cancel();
                throw new OperationCanceledException(
                    "The success transaction was cancelled before its commit.", cancellation.Token);
            }

            return ValueTask.FromResult(result);
        }
    }

    /// <summary>
    /// Fails only the <c>login_success</c> audit staging, so the injected failure lands inside the
    /// <c>EV-01</c> transaction and proves its atomicity; every other audit write passes through.
    /// </summary>
    private sealed class FailingSuccessAuditService(AuditService inner) : IAuditService
    {
        public Task RecordLoginAsync(
            Guid? accountId,
            string username,
            string authMethod,
            string eventType,
            string? clientIp,
            string? userAgent,
            string? failureReason = null,
            string? appId = null,
            string? correlationId = null,
            CancellationToken cancellationToken = default) =>
            eventType == "login_success"
                ? Task.FromException(new InvalidOperationException(
                    "The success audit save was injected to fail."))
                : inner.RecordLoginAsync(
                    accountId, username, authMethod, eventType, clientIp, userAgent,
                    failureReason, appId, correlationId, cancellationToken);

    }
}
