using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Security;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The SQLite HTTP contract of the authorize-side session reuse (<c>AC-09</c>): a browser whose
/// identity cookie names a still-usable server-side session receives a code without another
/// login; the bounded activity slide (<c>PS-04</c>); every unusable shape — revocation, idle and
/// absolute expiry (inclusive), a deactivated account, the application's max-age, a missing row,
/// a tampered cookie, a management-only cookie — falls back to the login continuation with the
/// identical result of a cookie-less request and zero session writes; the <c>EV-05</c>
/// application isolation; the single-instance concurrency shape (<c>SC-07</c>) with at most one
/// touch; the fail-closed persistence failure; the canary scan; and the byte-identical
/// continuation behavior of a cookie-less accepted request.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class OAuthAuthorizationSessionReuseTests : IClassFixture<IdentityServerFixture>
{
    private const string ReuseUser = "authorize_reuse_user";
    private const string ReusePassword = "Authorize-Reuse-123!";

    private const string OtherAppId = "authorize-reuse-other-app";
    private const string OtherRegisteredUri = "https://bff.reuse-other.test/callback?tenant=two";
    private const string MaxAgeAppId = "authorize-reuse-maxage-app";
    private const string MaxAgeRegisteredUri = "https://bff.reuse-maxage.test/callback?tenant=age";

    private readonly IdentityServerFixture _fixture;

    public OAuthAuthorizationSessionReuseTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- Acceptance 1: the successful reuse ----

    [Fact]
    public async Task Authorize_WithAUsableIdentityCookie_ReturnsTheCodeWithoutALogin()
    {
        var accountId = await SeedReuseUserAsync();
        using var client = _fixture.CreateNonRedirectingHttpClient(handleCookies: false);
        var cookieValue = await CompleteSuccessLoginAndGetIdentityCookieValueAsync(
            _fixture.Services, client, ReuseUser, ReusePassword);
        var session = await GetLatestSessionAsync(accountId);
        var sessionCount = await CountRowsAsync(db => db.IdentitySessions
            .CountAsync(row => row.AccountId == accountId));
        // The login itself already created one code for this session; the reuse adds exactly one.
        var codeCount = await CountRowsAsync(db => db.AuthorizationCodes
            .CountAsync(row => row.IdentitySessionId == session.Id));
        var continuationCount = await CountRowsAsync(db => db.AuthorizationRequests.CountAsync());
        var acceptedAudits = await CountRowsAsync(async db =>
            (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(db))
                .Count(row => row.Action == "oidc.authorize.validated"));

        using var response = await client.SendAsync(
            AuthorizeRequest(BuildSuccessAuthorizeUrl(), cookieValue),
            TestContext.Current.CancellationToken);

        AssertRedirectWithCode(response, out var code);
        // No new session, no new continuation; the plaintext code resolves to exactly the row
        // bound to the original session, still unconsumed.
        using (var scope = _fixture.Services.CreateScope())
        {
            var codes = scope.ServiceProvider.GetRequiredService<IAuthorizationCodeStore>();
            var lookup = await codes.FindAsync(code, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
            Assert.Equal(AuthorizationCodeState.Unconsumed, lookup.State);
            Assert.Equal(session.Id, lookup.Entity!.IdentitySessionId);
            Assert.Null(lookup.Entity.ConsumedAt);
        }

        await AssertAsync(async db =>
        {
            // No new session and no new continuation; the code is the only new row.
            Assert.Equal(sessionCount, await db.IdentitySessions.CountAsync(row => row.AccountId == accountId));
            Assert.Equal(continuationCount, await db.AuthorizationRequests.CountAsync());
            Assert.Equal(codeCount + 1, await db.AuthorizationCodes
                .CountAsync(row => row.IdentitySessionId == session.Id));
        });
        Assert.Equal(acceptedAudits + 1, await CountRowsAsync(db =>
            SharedSettingTestDatabase.LoadSharedAuditRowsAsync(db)
                .ContinueWith(task => task.Result.Count(row => row.Action == "oidc.authorize.validated"))));
    }

    [Fact]
    public async Task Authorize_ForAnotherApplicationWithoutMaxAge_ReusesTheSameSession()
    {
        var accountId = await SeedReuseUserAsync();
        var otherApplicationId = await SeedInteractiveAppAsync(OtherAppId, OtherRegisteredUri);
        using var client = _fixture.CreateNonRedirectingHttpClient(handleCookies: false);
        var cookieValue = await CompleteSuccessLoginAndGetIdentityCookieValueAsync(
            _fixture.Services, client, ReuseUser, ReusePassword);
        var session = await GetLatestSessionAsync(accountId);
        var sessionCount = await CountRowsAsync(db => db.IdentitySessions
            .CountAsync(row => row.AccountId == accountId));
        var codeCount = await CountRowsAsync(db => db.AuthorizationCodes
            .CountAsync(row => row.IdentitySessionId == session.Id));

        using var response = await client.SendAsync(
            AuthorizeRequest(BuildAuthorizeUrl(OtherAppId, OtherRegisteredUri, "other-state-0123456789ab"), cookieValue),
            TestContext.Current.CancellationToken);

        Assert.True(response.StatusCode == HttpStatusCode.Found, $"Unexpected {response.StatusCode}");
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith(OtherRegisteredUri.Split('?')[0], location, StringComparison.Ordinal);
        Assert.Contains("code=", location, StringComparison.Ordinal);
        Assert.Contains("state=other-state-0123456789ab", location, StringComparison.Ordinal);
        Assert.Equal(sessionCount, await CountRowsAsync(db => db.IdentitySessions
            .CountAsync(row => row.AccountId == accountId)));
        Assert.Equal(codeCount + 1, await CountRowsAsync(db => db.AuthorizationCodes
            .CountAsync(row => row.IdentitySessionId == session.Id)));
    }

    [Fact]
    public async Task Authorize_WithoutACookie_StillCreatesTheLoginContinuation()
    {
        await SeedReuseUserAsync();
        using var client = _fixture.CreateNonRedirectingHttpClient(handleCookies: false);
        await CompleteSuccessLoginAndGetIdentityCookieValueAsync(
            _fixture.Services, client, ReuseUser, ReusePassword);
        var continuationCount = await CountRowsAsync(db => db.AuthorizationRequests.CountAsync());

        using var response = await client.GetAsync(
            BuildSuccessAuthorizeUrl(), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith("/oauth2/login?login_handle=", location, StringComparison.Ordinal);
        Assert.Equal(continuationCount + 1, await CountRowsAsync(db => db.AuthorizationRequests.CountAsync()));
    }

    // ---- Acceptance 2: the bounded activity slide ----

    [Fact]
    public async Task Authorize_WithAStaleSession_SlidesTheIdleDeadline()
    {
        var accountId = await SeedReuseUserAsync();
        using var client = _fixture.CreateNonRedirectingHttpClient(handleCookies: false);
        var cookieValue = await CompleteSuccessLoginAndGetIdentityCookieValueAsync(
            _fixture.Services, client, ReuseUser, ReusePassword);
        var session = await GetLatestSessionAsync(accountId);
        var before = DateTimeOffset.UtcNow.AddMinutes(-2);
        await ExecuteAsync(db => db.IdentitySessions
            .Where(row => row.Id == session.Id)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.LastSeenAt, before)
                .SetProperty(row => row.IdleExpiresAt, before.AddMinutes(30))));

        using var response = await client.SendAsync(
            AuthorizeRequest(BuildSuccessAuthorizeUrl(), cookieValue),
            TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.Found);

        var updated = await GetLatestSessionAsync(accountId);
        Assert.True(updated.LastSeenAt > before);
        Assert.Null(updated.RevokedAt);
        // The slide is capped at the absolute deadline, which is hours away here.
        Assert.True(updated.IdleExpiresAt <= updated.AbsoluteExpiresAt);
    }

    [Fact]
    public async Task Authorize_WithAFreshSession_DoesNotWriteActivity()
    {
        var accountId = await SeedReuseUserAsync();
        using var client = _fixture.CreateNonRedirectingHttpClient(handleCookies: false);
        var cookieValue = await CompleteSuccessLoginAndGetIdentityCookieValueAsync(
            _fixture.Services, client, ReuseUser, ReusePassword);
        var session = await GetLatestSessionAsync(accountId);

        using var response = await client.SendAsync(
            AuthorizeRequest(BuildSuccessAuthorizeUrl(), cookieValue),
            TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.Found);

        var updated = await GetLatestSessionAsync(accountId);
        Assert.Equal(session.LastSeenAt.UtcTicks / 10, updated.LastSeenAt.UtcTicks / 10);
        Assert.Equal(session.IdleExpiresAt.UtcTicks / 10, updated.IdleExpiresAt.UtcTicks / 10);
        Assert.Equal(session.AbsoluteExpiresAt.UtcTicks / 10, updated.AbsoluteExpiresAt.UtcTicks / 10);
    }

    // ---- Acceptance 3: every unusable shape falls back identically, with zero session writes ----

    [Fact]
    public async Task Authorize_ForARevokedSession_FallsBackWithoutTouchingTheRow()
    {
        await AssertFallbackWithoutWriteAsync(async (accountId, session) =>
        {
            await ExecuteAsync(db => db.IdentitySessions
                .Where(row => row.Id == session.Id)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(row => row.RevokedAt, DateTimeOffset.UtcNow)
                    .SetProperty(row => row.RevocationReason, "administrative")));
        });
    }

    [Fact]
    public async Task Authorize_ForAnIdleExpiredSession_FallsBackWithoutTouchingTheRow()
    {
        await AssertFallbackWithoutWriteAsync(async (accountId, session) =>
        {
            await ExecuteAsync(db => db.IdentitySessions
                .Where(row => row.Id == session.Id)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(row => row.IdleExpiresAt, DateTimeOffset.UtcNow)));
        });
    }

    [Fact]
    public async Task Authorize_ForAnAbsolutelyExpiredSession_FallsBackWithoutTouchingTheRow()
    {
        await AssertFallbackWithoutWriteAsync(async (accountId, session) =>
        {
            await ExecuteAsync(db => db.IdentitySessions
                .Where(row => row.Id == session.Id)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(row => row.AbsoluteExpiresAt, DateTimeOffset.UtcNow)));
        });
    }

    [Fact]
    public async Task Authorize_ForADeactivatedAccount_FallsBackWithoutTouchingTheRow()
    {
        await AssertFallbackWithoutWriteAsync(async (accountId, session) =>
        {
            await ExecuteAsync(db => db.Accounts
                .Where(row => row.Id == accountId)
                .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsActive, false)));
        });
    }

    [Fact]
    public async Task Authorize_WithATamperedCookie_FallsBackLikeACookielessRequest()
    {
        await SeedReuseUserAsync();
        using var client = _fixture.CreateNonRedirectingHttpClient(handleCookies: false);
        await CompleteSuccessLoginAndGetIdentityCookieValueAsync(
            _fixture.Services, client, ReuseUser, ReusePassword);

        using var response = await client.SendAsync(
            AuthorizeRequest(BuildSuccessAuthorizeUrl(), "tampered-cookie-value-0123456789"),
            TestContext.Current.CancellationToken);

        await AssertLoginFallbackAsync(response);
    }

    [Fact]
    public async Task Authorize_WithOnlyTheManagementCookie_FallsBackLikeACookielessRequest()
    {
        await SeedReuseUserAsync();
        using var client = _fixture.CreateNonRedirectingHttpClient(handleCookies: false);
        await CompleteSuccessLoginAndGetIdentityCookieValueAsync(
            _fixture.Services, client, ReuseUser, ReusePassword);

        using var response = await client.SendAsync(
            AuthorizeRequest(BuildSuccessAuthorizeUrl(), managementCookie: "__Host-ServiceMantle.Management=management-value"),
            TestContext.Current.CancellationToken);

        await AssertLoginFallbackAsync(response);
    }

    [Fact]
    public async Task Authorize_ForAMissingSessionRow_FallsBackWithoutInventingState()
    {
        await AssertFallbackWithoutWriteAsync(async (accountId, session) =>
        {
            // The code rows referencing the session go first: the restrictive reference forbids
            // deleting a referenced session.
            await ExecuteAsync(async db =>
            {
                await db.AuthorizationCodes
                    .Where(row => row.IdentitySessionId == session.Id)
                    .ExecuteDeleteAsync();
                await db.IdentitySessions
                    .Where(row => row.Id == session.Id)
                    .ExecuteDeleteAsync();
            });
        });
    }

    // ---- Acceptance 4: the EV-05 application isolation ----

    [Fact]
    public async Task Authorize_MaxAgeReachedForOneApplication_StillReusesForAnother()
    {
        var accountId = await SeedReuseUserAsync();
        var maxAgeApplicationId = await SeedInteractiveAppAsync(
            MaxAgeAppId, MaxAgeRegisteredUri, maxAgeSeconds: 1);
        using var client = _fixture.CreateNonRedirectingHttpClient(handleCookies: false);
        var cookieValue = await CompleteSuccessLoginAndGetIdentityCookieValueAsync(
            _fixture.Services, client, ReuseUser, ReusePassword);
        var session = await GetLatestSessionAsync(accountId);
        var codeCount = await CountRowsAsync(db => db.AuthorizationCodes
            .CountAsync(row => row.IdentitySessionId == session.Id));
        await Task.Delay(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);

        // This application's max-age has been reached: the login continuation, no session write.
        using var agedResponse = await client.SendAsync(
            AuthorizeRequest(BuildAuthorizeUrl(MaxAgeAppId, MaxAgeRegisteredUri, "aged-state-0123456789a"), cookieValue),
            TestContext.Current.CancellationToken);
        await AssertLoginFallbackAsync(agedResponse);
        var afterAged = await GetLatestSessionAsync(accountId);
        Assert.Null(afterAged.RevokedAt);

        // The same session is still reusable for an application without a max-age.
        using var otherResponse = await client.SendAsync(
            AuthorizeRequest(BuildSuccessAuthorizeUrl(), cookieValue),
            TestContext.Current.CancellationToken);
        AssertRedirectWithCode(otherResponse, out _);
        Assert.Equal(codeCount + 1, await CountRowsAsync(db => db.AuthorizationCodes
            .CountAsync(row => row.IdentitySessionId == session.Id)));
    }

    // ---- Acceptance 6: the single-instance concurrency shape ----

    [Fact]
    public async Task Authorize_ConcurrentlyWithTheSameSession_ProducesTwoCodesAndOneTouch()
    {
        var accountId = await SeedReuseUserAsync();
        using var client = _fixture.CreateNonRedirectingHttpClient(handleCookies: false);
        var cookieValue = await CompleteSuccessLoginAndGetIdentityCookieValueAsync(
            _fixture.Services, client, ReuseUser, ReusePassword);
        var session = await GetLatestSessionAsync(accountId);
        var loginCodeCount = await CountRowsAsync(db => db.AuthorizationCodes
            .CountAsync(row => row.IdentitySessionId == session.Id));
        var before = DateTimeOffset.UtcNow.AddMinutes(-2);
        await ExecuteAsync(db => db.IdentitySessions
            .Where(row => row.Id == session.Id)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.LastSeenAt, before)
                .SetProperty(row => row.IdleExpiresAt, before.AddMinutes(30))));

        var responses = await Task.WhenAll(
            client.SendAsync(AuthorizeRequest(BuildSuccessAuthorizeUrl(), cookieValue), TestContext.Current.CancellationToken),
            client.SendAsync(AuthorizeRequest(BuildSuccessAuthorizeUrl(), cookieValue), TestContext.Current.CancellationToken));

        Assert.All(responses, response => Assert.Equal(HttpStatusCode.Found, response.StatusCode));
        var updated = await GetLatestSessionAsync(accountId);
        // At most one touch: the stale activity slid once (to the request instant), not twice.
        Assert.True(updated.LastSeenAt > before);
        Assert.True(updated.LastSeenAt <= DateTimeOffset.UtcNow);
        // The login's own code plus exactly one per concurrent request.
        var codeCount = await CountRowsAsync(db => db.AuthorizationCodes
            .CountAsync(row => row.IdentitySessionId == session.Id));
        Assert.Equal(loginCodeCount + 2, codeCount);
    }

    // ---- Acceptance 7: the fail-closed persistence failure ----

    [Fact]
    public async Task Authorize_WhenReusePersistenceFails_Answers500WithoutALocation()
    {
        await SeedReuseUserAsync();
        using var loginClient = _fixture.CreateNonRedirectingHttpClient(handleCookies: false);
        var cookieValue = await CompleteSuccessLoginAndGetIdentityCookieValueAsync(
            _fixture.Services, loginClient, ReuseUser, ReusePassword);
        var continuationCount = await CountRowsAsync(db => db.AuthorizationRequests.CountAsync());

        using var factory = _fixture.WithTestServices(services =>
        {
            services.RemoveAll<IAuthorizationCodeStore>();
            services.AddScoped<IAuthorizationCodeStore>(_ => new ThrowingCodeStore());
        });
        using var client = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });
        using var response = await client.SendAsync(
            AuthorizeRequest(BuildSuccessAuthorizeUrl(), cookieValue),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.False(response.Headers.Contains("Location"), "A failed reuse must not redirect.");
        Assert.Equal(continuationCount, await CountRowsAsync(db => db.AuthorizationRequests.CountAsync()));
    }

    // ---- Acceptance 8: the canary scan ----

    [Fact]
    public async Task Authorize_ReuseNeverLogsTheCookieStateNonceCodeOrRedirectUri()
    {
        await SeedReuseUserAsync();
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
        using var loginClient = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });
        var cookieValue = await CompleteSuccessLoginAndGetIdentityCookieValueAsync(
            _fixture.Services, loginClient, ReuseUser, ReusePassword);
        var accountId = await GetAccountIdOfAsync(ReuseUser);
        var session = await GetLatestSessionAsync(accountId);

        using var client = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });
        using var response = await client.SendAsync(
            AuthorizeRequest(BuildSuccessAuthorizeUrl(), cookieValue),
            TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.Found);

        Assert.Contains(capture.Messages, message =>
            message.Contains("session_reused", StringComparison.Ordinal));

        var dump = new StringBuilder();
        foreach (var message in capture.Messages)
        {
            dump.AppendLine(message);
        }

        foreach (var audit in await QueryAsync(async db =>
                     (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(db))
                     .Where(row => row.Action == "oidc.authorize.validated")
                     .ToList()))
        {
            dump.Append("audit|").Append(audit.Action).Append('|').Append(audit.TargetType).Append('|')
                .Append(audit.TargetId).Append('|').Append(audit.SecurityDescription).AppendLine();
        }

        var dumpText = dump.ToString();
        Assert.DoesNotContain(cookieValue, dumpText, StringComparison.Ordinal);
        Assert.DoesNotContain(session.Id.ToString(), dumpText, StringComparison.Ordinal);
        Assert.DoesNotContain(SuccessState, dumpText, StringComparison.Ordinal);
        Assert.DoesNotContain(SuccessNonce, dumpText, StringComparison.Ordinal);
        Assert.DoesNotContain(SuccessRegisteredUri, dumpText, StringComparison.Ordinal);
        foreach (var code in await QueryAsync(db => db.AuthorizationCodes.AsNoTracking()
                     .Where(row => row.IdentitySessionId == session.Id)
                     .Select(row => row.Id)
                     .ToListAsync()))
        {
            Assert.DoesNotContain(code.ToString(), dumpText, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Seeds the shared reuse user idempotently: the whole class shares one fixture database, so
    /// every test logs in as the same account instead of one account per test.
    /// </summary>
    private async Task<Guid> SeedReuseUserAsync()
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var existing = await dbContext.PasswordCredentials
            .AsNoTracking()
            .FirstOrDefaultAsync(item => item.Username == ReuseUser, TestContext.Current.CancellationToken);
        if (existing is not null)
        {
            // A test that deactivated the shared account must not poison the ones after it.
            var account = await dbContext.Accounts
                .SingleAsync(row => row.Id == existing.AccountId, TestContext.Current.CancellationToken);
            account.IsActive = true;
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
            return existing.AccountId;
        }

        var accountId = Guid.NewGuid();
        dbContext.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        dbContext.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = ReuseUser,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(ReusePassword),
            CreatedAt = DateTimeOffset.UtcNow
        });
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        return accountId;
    }

    // ---- Helpers ----

    private static HttpRequestMessage AuthorizeRequest(
        string url,
        string? cookieValue = null,
        string? managementCookie = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        var cookies = new List<string>();
        if (cookieValue is not null)
        {
            cookies.Add($"{IdentitySessionDefaults.CookieName}={cookieValue}");
        }

        if (managementCookie is not null)
        {
            cookies.Add(managementCookie);
        }

        if (cookies.Count > 0)
        {
            request.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", cookies));
        }

        return request;
    }

    private static string BuildAuthorizeUrl(string appId, string redirectUri, string state) =>
        "/oauth2/authorize?" + string.Join('&', new[]
        {
            ("response_type", "code"),
            ("client_id", appId),
            ("redirect_uri", redirectUri),
            ("scope", SuccessScope),
            ("state", state),
            ("nonce", SuccessNonce),
            ("code_challenge", SuccessChallenge),
            ("code_challenge_method", "S256"),
        }.Select(pair => $"{Uri.EscapeDataString(pair.Item1)}={Uri.EscapeDataString(pair.Item2)}"));

    private async Task<Guid> SeedInteractiveAppAsync(
        string appId,
        string registeredUri,
        int? maxAgeSeconds = null)
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var existing = await dbContext.AppRegistrations
            .AsNoTracking()
            .FirstOrDefaultAsync(app => app.AppId == appId, TestContext.Current.CancellationToken);
        if (existing is not null)
        {
            return existing.Id;
        }

        var application = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = appId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword("authorize-reuse-secret"),
            AppName = $"Authorize Reuse {appId}",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = SuccessScope,
            AllowRefreshToken = false,
            IdentitySessionMaxAgeSeconds = maxAgeSeconds
        };
        application.RedirectUris =
        [
            new AppRedirectUriEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = application.Id,
                Kind = RedirectUriKind.Redirect,
                CanonicalUri = registeredUri
            }
        ];
        dbContext.AppRegistrations.Add(application);
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        return application.Id;
    }

    /// <summary>
    /// Drives one full unusable-shape scenario: log in, apply the mutation, request authorize
    /// with the cookie, and prove the answer is the cookie-less continuation shape with zero
    /// session-row writes and no code.
    /// </summary>
    private async Task AssertFallbackWithoutWriteAsync(
        Func<Guid, IdentitySessionEntity, Task> mutate)
    {
        var accountId = await SeedReuseUserAsync();
        using var client = _fixture.CreateNonRedirectingHttpClient(handleCookies: false);
        var cookieValue = await CompleteSuccessLoginAndGetIdentityCookieValueAsync(
            _fixture.Services, client, ReuseUser, ReusePassword);
        var session = await GetLatestSessionAsync(accountId);

        await mutate(accountId, session);
        // The snapshot follows the mutation, which is test setup: only the authorize request's
        // writes are under assertion.
        var codeCount = await CountRowsAsync(db => db.AuthorizationCodes
            .CountAsync(row => row.IdentitySessionId == session.Id));
        var mutated = await GetLatestSessionAsync(accountId);

        using var response = await client.SendAsync(
            AuthorizeRequest(BuildSuccessAuthorizeUrl(), cookieValue),
            TestContext.Current.CancellationToken);

        await AssertLoginFallbackAsync(response);

        var after = await GetLatestSessionAsync(accountId);
        if (after is not null && mutated is not null)
        {
            Assert.Equal(mutated.RevokedAt, after.RevokedAt);
            Assert.Equal(mutated.RevocationReason, after.RevocationReason);
            Assert.Equal(mutated.LastSeenAt.UtcTicks / 10, after.LastSeenAt.UtcTicks / 10);
            Assert.Equal(mutated.IdleExpiresAt.UtcTicks / 10, after.IdleExpiresAt.UtcTicks / 10);
        }

        Assert.Equal(codeCount, await CountRowsAsync(db => db.AuthorizationCodes
            .CountAsync(row => row.IdentitySessionId == session.Id)));
    }

    private static async Task AssertLoginFallbackAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith("/oauth2/login?login_handle=", location, StringComparison.Ordinal);
        Assert.DoesNotContain("code=", location, StringComparison.Ordinal);
    }

    private static void AssertRedirectWithCode(HttpResponseMessage response, out string code)
    {
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith(SuccessRegisteredUri.Split('?')[0], location, StringComparison.Ordinal);
        Assert.Contains("state=" + Uri.EscapeDataString(SuccessState), location, StringComparison.Ordinal);
        Assert.Contains("iss=", location, StringComparison.Ordinal);
        var query = location[location.IndexOf('?', StringComparison.Ordinal)..];
        code = Microsoft.AspNetCore.WebUtilities.QueryHelpers
            .ParseQuery(query)["code"].ToString();
        Assert.Equal(43, code.Length);
    }

    /// <summary>
    /// The session the latest login's cookie names: the shared account accumulates one session
    /// per login across the class, so the newest row by authentication time is the live one.
    /// </summary>
    private Task<IdentitySessionEntity?> GetLatestSessionAsync(Guid accountId) =>
        QueryAsync(async db => await db.IdentitySessions.AsNoTracking()
            .Where(row => row.AccountId == accountId)
            .OrderByDescending(row => row.AuthTime)
            .ThenByDescending(row => row.Id)
            .FirstOrDefaultAsync(TestContext.Current.CancellationToken));

    private async Task<Guid> GetAccountIdOfAsync(string username)
    {
        using var scope = _fixture.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var credential = await db.PasswordCredentials.AsNoTracking()
            .SingleAsync(item => item.Username == username, TestContext.Current.CancellationToken);
        return credential.AccountId;
    }

    private Task<bool> CodeExistsForSessionAsync(Guid sessionId) =>
        QueryAsync(db => db.AuthorizationCodes.AsNoTracking()
            .AnyAsync(row => row.IdentitySessionId == sessionId));

    private Task<int> CountRowsAsync(Func<IdentityDbContext, Task<int>> count) =>
        QueryAsync(count);

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

    private async Task AssertAsync(Func<IdentityDbContext, Task> assert)
    {
        using var scope = _fixture.Services.CreateScope();
        await assert(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }

    private sealed class ThrowingCodeStore : IAuthorizationCodeStore
    {
        public Task<AuthorizationCodeCreation> CreateAsync(
            IdentitySessionEntity session,
            AuthorizationCodeBinding binding,
            DateTimeOffset now,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("The code persistence failed.");

        public Task<AuthorizationCodeLookup> FindAsync(
            string code,
            DateTimeOffset now,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Not used by the reuse path.");

        public bool VerifyBinding(
            AuthorizationCodeEntity code,
            Guid applicationId,
            string redirectUri,
            string codeVerifier) => false;

        public Task<AuthorizationCodeEntity?> LockAsync(
            Guid codeId,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Not used by the reuse path.");

        public Task<bool> TryConsumeAsync(
            Guid codeId,
            DateTimeOffset now,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Not used by the reuse path.");

        public Task<bool> LinkRefreshFamilyAsync(
            Guid codeId,
            Guid rootId,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Not used by the reuse path.");

        public Task<int> CleanupExpiredAsync(
            DateTimeOffset now,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Not used by the reuse path.");
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<string> _messages = new();

        public IReadOnlyCollection<string> Messages => _messages;

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, _messages);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(
            string categoryName,
            ConcurrentQueue<string> messages) : ILogger
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
                var message = formatter(state, exception);
                messages.Enqueue(exception is null
                    ? $"[{logLevel}] {categoryName}: {message}"
                    : $"[{logLevel}] {categoryName}: {message}{Environment.NewLine}{exception}");
            }
        }
    }
}
