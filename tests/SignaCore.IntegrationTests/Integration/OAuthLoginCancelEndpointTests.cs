using System.Net;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Models;
using SignaCore.Domain.Validators;
using SignaCore.Host;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The <c>EV-02</c> cancel contract of <c>POST /oauth2/login</c>: the revalidation of the current
/// client and the exact redirect URI against the stored snapshot, the one-time consumption, the
/// <c>access_denied</c> safe redirect (<c>PS-17</c>) with the byte-for-byte state and the issuer,
/// the local answer for every drift that removes redirect trust, the exactly-one-winner
/// consumption under concurrency, the commit-boundary cancellation, and the zero-side-effect /
/// sensitive-value guarantees. Every session here uses a revalidatable continuation
/// (<see cref="SeedLegalContinuationAsync"/>) unless a test says otherwise.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class OAuthLoginCancelEndpointTests : IClassFixture<IdentityServerFixture>
{
    private const string LocalErrorPage =
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        + "<title>Invalid login request</title></head><body>"
        + "<h1>Invalid login request</h1>"
        + "<p>The login request could not be processed. Return to the application that "
        + "sent you here and start again.</p></body></html>";

    private readonly IdentityServerFixture _fixture;

    public OAuthLoginCancelEndpointTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- Acceptance 2 (+5): the redirect itself ----

    [Fact]
    public async Task Cancel_RevalidatesConsumesAndRedirectsAccessDenied()
    {
        using var client = _fixture.CreateNonRedirectingHttpClient();
        var session = await BeginLegalLoginAsync(_fixture.Services, client);

        using var request = CreateLoginPost(
            fields: CancelFields(session),
            cookieHeader: CookieHeaderFor(session));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var issuer = _fixture.Services.GetRequiredService<JwtOptions>().Issuer;
        var expectedLocation =
            $"{LegalRegisteredUri}"
            + $"&error=access_denied"
            + $"&error_description={Uri.EscapeDataString(OidcAuthorizationErrorDescriptions.AccessDenied)}"
            + $"&state={Uri.EscapeDataString(LegalState)}"
            + $"&iss={Uri.EscapeDataString(issuer)}";
        Assert.Equal(expectedLocation, response.Headers.Location!.AbsoluteUri);

        // The stored query of the registered URI survives and the appended fields start with '&'.
        Assert.StartsWith(
            "https://bff.cancel.test/callback?tenant=unit&error=access_denied",
            response.Headers.Location.ToString(),
            StringComparison.Ordinal);

        // The continuation is consumed exactly once: both a GET and a fresh POST now answer 400.
        Assert.NotNull(await GetConsumedAtAsync(session.Handle));
        using var replayGet = await client.GetAsync(
            $"/oauth2/login?login_handle={session.Handle}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, replayGet.StatusCode);
        using var replayPost = await client.SendAsync(
            CreateLoginPost(fields: CancelFields(session), cookieHeader: CookieHeaderFor(session)),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, replayPost.StatusCode);
    }

    // ---- Acceptance 3: drift that removes redirect trust is a local error ----

    [Theory]
    [InlineData("deactivate")]
    [InlineData("disable-authorization-code")]
    [InlineData("remove-redirect-uri")]
    public async Task Cancel_WhenRedirectTrustDrifted_IsALocalErrorAndConsumesNothing(string drift)
    {
        using var client = _fixture.CreateNonRedirectingHttpClient();
        var session = await BeginLegalLoginAsync(_fixture.Services, client);
        await ApplyDriftAsync(drift);

        try
        {
            using var drifted = await client.SendAsync(
                CreateLoginPost(fields: CancelFields(session), cookieHeader: CookieHeaderFor(session)),
                TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.BadRequest, drifted.StatusCode);
            Assert.False(drifted.Headers.Contains("Location"));
            Assert.Equal(
                LocalErrorPage,
                await drifted.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            Assert.Null(await GetConsumedAtAsync(session.Handle));
        }
        finally
        {
            await RestoreDriftAsync(drift);
        }

        // The continuation was never consumed, so after the restore the same handle cancels.
        using var restored = await client.SendAsync(
            CreateLoginPost(fields: CancelFields(session), cookieHeader: CookieHeaderFor(session)),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, restored.StatusCode);
    }

    // ---- Acceptance 4: policy drift after stage 3 does not block a cancel ----

    [Fact]
    public async Task Cancel_WhenOnlyTheScopeDrifted_StillRedirectsAccessDenied()
    {
        using var client = _fixture.CreateNonRedirectingHttpClient();
        var session = await BeginLegalLoginAsync(_fixture.Services, client);
        await MutateLegalAppAsync(app => app.AllowedScopes = "openid");

        try
        {
            using var response = await client.SendAsync(
                CreateLoginPost(fields: CancelFields(session), cookieHeader: CookieHeaderFor(session)),
                TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.NotNull(await GetConsumedAtAsync(session.Handle));
        }
        finally
        {
            await MutateLegalAppAsync(app => app.AllowedScopes = "openid profile");
        }
    }

    // ---- Acceptance 6: concurrency ----

    [Fact]
    public async Task Cancel_Concurrently_ExactlyOneRedirectAndOneConsumption()
    {
        using var client = _fixture.CreateNonRedirectingHttpClient();
        var session = await BeginLegalLoginAsync(_fixture.Services, client);

        var before = DateTimeOffset.UtcNow;
        var responses = await Task.WhenAll(
            client.SendAsync(
                CreateLoginPost(fields: CancelFields(session), cookieHeader: CookieHeaderFor(session)),
                TestContext.Current.CancellationToken),
            client.SendAsync(
                CreateLoginPost(fields: CancelFields(session), cookieHeader: CookieHeaderFor(session)),
                TestContext.Current.CancellationToken));
        var after = DateTimeOffset.UtcNow;

        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.Found));
        Assert.Equal(1, responses.Count(response => response.StatusCode == HttpStatusCode.BadRequest));

        // The single consumption lies between the first submission and the last completion, on the
        // microsecond grid SQLite stores.
        var consumedAt = await GetConsumedAtAsync(session.Handle);
        Assert.NotNull(consumedAt);
        Assert.True(consumedAt >= before, "The consumption predates the concurrent submissions.");
        Assert.True(consumedAt <= after, "The consumption postdates the concurrent submissions.");
    }

    // ---- Acceptance 7: commit-boundary cancellation ----

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Cancel_AtTheConsumptionCommitBoundary_IsBounded(bool afterCommit)
    {
        using var cancellation = new CancellationTokenSource();
        var gate = new ConsumptionCommitGate();
        using var factory = CreateHostWithDbInterceptor(
            new ArmOnConsumptionUpdateInterceptor(gate),
            new ConsumptionCommitCancellationInterceptor(gate, cancellation, afterCommit));
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var session = await BeginLegalLoginAsync(factory.Services, client);

        if (afterCommit)
        {
            using var response = await client.SendAsync(
                CreateLoginPost(fields: CancelFields(session), cookieHeader: CookieHeaderFor(session)),
                TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Assert.NotNull(await GetConsumedAtAsync(session.Handle));
        }
        else
        {
            using var response = await client.SendAsync(
                CreateLoginPost(fields: CancelFields(session), cookieHeader: CookieHeaderFor(session)),
                TestContext.Current.CancellationToken);
            Assert.NotEqual(HttpStatusCode.Found, response.StatusCode);
            Assert.False(response.Headers.Contains("Location"));
            Assert.Null(await GetConsumedAtAsync(session.Handle));
        }

        Assert.Equal(1, gate.CommitAttempts);
    }

    // ---- Acceptance 8: zero side effects ----

    [Fact]
    public async Task Cancel_WritesOnlyTheConsumption()
    {
        using var client = _fixture.CreateNonRedirectingHttpClient();
        var session = await BeginLegalLoginAsync(_fixture.Services, client);
        var before = await CountSideEffectTablesAsync();

        using var response = await client.SendAsync(
            CreateLoginPost(fields: CancelFields(session), cookieHeader: CookieHeaderFor(session)),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Null(GetSetCookieHeader(response, CookieName));
        Assert.Equal(before, await CountSideEffectTablesAsync());
    }

    // ---- Acceptance 9: sensitive values ----

    [Fact]
    public async Task Cancel_LeaksNoSnapshotValuesIntoLogsOrAudits()
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
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var session = await BeginLegalLoginAsync(factory.Services, client);

        using var response = await client.SendAsync(
            CreateLoginPost(fields: CancelFields(session), cookieHeader: CookieHeaderFor(session)),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var location = response.Headers.Location!.ToString();

        // The location carries exactly the registered URI, the fixed error fields, the state, and
        // the issuer — never the handle, the nonce, the challenge, or the scope.
        Assert.Contains(LegalState, location, StringComparison.Ordinal);
        Assert.DoesNotContain(session.Handle, location, StringComparison.Ordinal);
        Assert.DoesNotContain(LegalNonce, location, StringComparison.Ordinal);
        Assert.DoesNotContain(LegalChallenge, location, StringComparison.Ordinal);
        Assert.DoesNotContain(LegalScope, location, StringComparison.Ordinal);

        foreach (var message in capture.Messages)
        {
            Assert.DoesNotContain(session.Handle, message, StringComparison.Ordinal);
            Assert.DoesNotContain(LegalNonce, message, StringComparison.Ordinal);
            Assert.DoesNotContain(LegalChallenge, message, StringComparison.Ordinal);
            Assert.DoesNotContain(LegalState, message, StringComparison.Ordinal);
        }

        using (var scope = _fixture.Services.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            Assert.Empty(await dbContext.AuditLogs.AsNoTracking()
                .Where(log => log.Action.StartsWith("oidc.login") || log.Action.StartsWith("oidc.cancel"))
                .ToListAsync(TestContext.Current.CancellationToken));
            var serializedAudit = string.Join(
                ' ',
                (await dbContext.AuditLogs.AsNoTracking()
                    .ToListAsync(TestContext.Current.CancellationToken))
                .Select(log => $"{log.Action}|{log.Description}|{log.TargetId}|{log.CorrelationId}"));
            Assert.DoesNotContain(session.Handle, serializedAudit, StringComparison.Ordinal);
            Assert.DoesNotContain(LegalNonce, serializedAudit, StringComparison.Ordinal);
            Assert.DoesNotContain(LegalChallenge, serializedAudit, StringComparison.Ordinal);
        }
    }

    // ---- Helpers ----

    private async Task<DateTimeOffset?> GetConsumedAtAsync(string handle)
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var continuation = await dbContext.AuthorizationRequests.AsNoTracking()
            .SingleAsync(
                row => row.HandleDigest == LoginHandleDigest.Compute(handle),
                TestContext.Current.CancellationToken);
        return continuation.ConsumedAt;
    }

    private async Task<(int Sessions, int Attempts, int Histories, int Audits)> CountSideEffectTablesAsync()
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var cancellationToken = TestContext.Current.CancellationToken;
        return (
            await dbContext.IdentitySessions.AsNoTracking().CountAsync(cancellationToken),
            await dbContext.LoginAttempts.AsNoTracking().CountAsync(cancellationToken),
            await dbContext.LoginHistories.AsNoTracking().CountAsync(cancellationToken),
            await dbContext.AuditLogs.AsNoTracking().CountAsync(cancellationToken));
    }

    private async Task MutateLegalAppAsync(Action<AppRegistrationEntity> mutate)
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var app = await dbContext.AppRegistrations
            .SingleAsync(app => app.AppId == LegalAppId, TestContext.Current.CancellationToken);
        mutate(app);
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    private async Task ApplyDriftAsync(string drift)
    {
        switch (drift)
        {
            case "deactivate":
                await MutateLegalAppAsync(app => app.IsActive = false);
                break;
            case "disable-authorization-code":
                await MutateLegalAppAsync(app => app.AllowAuthorizationCode = false);
                break;
            case "remove-redirect-uri":
                using (var scope = _fixture.Services.CreateScope())
                {
                    var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
                    var app = await dbContext.AppRegistrations
                        .Include(entity => entity.RedirectUris)
                        .SingleAsync(
                            app => app.AppId == LegalAppId,
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
                await MutateLegalAppAsync(app => app.IsActive = true);
                break;
            case "disable-authorization-code":
                await MutateLegalAppAsync(app => app.AllowAuthorizationCode = true);
                break;
            case "remove-redirect-uri":
                using (var scope = _fixture.Services.CreateScope())
                {
                    var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
                    var appId = await dbContext.AppRegistrations
                        .Where(app => app.AppId == LegalAppId)
                        .Select(app => app.Id)
                        .SingleAsync(TestContext.Current.CancellationToken);
                    var exists = await dbContext.AppRedirectUris.AsNoTracking()
                        .AnyAsync(
                            uri => uri.AppRegistrationId == appId && uri.CanonicalUri == LegalRegisteredUri,
                            TestContext.Current.CancellationToken);
                    if (!exists)
                    {
                        dbContext.AppRedirectUris.Add(new AppRedirectUriEntity
                        {
                            Id = Guid.NewGuid(),
                            AppRegistrationId = appId,
                            Kind = RedirectUriKind.Redirect,
                            CanonicalUri = LegalRegisteredUri
                        });
                        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
                    }
                }

                break;
        }
    }

    private WebApplicationFactory<Program> CreateHostWithDbInterceptor(
        params IInterceptor[] interceptors) =>
        _fixture.WithTestServices(services =>
            services.ConfigureDbContext<IdentityDbContext>(
                optionsBuilder => optionsBuilder.AddInterceptors(interceptors)));

    private sealed class ConsumptionCommitGate
    {
        public bool Armed;
        public int CommitAttempts;
    }

    /// <summary>Arms the gate when the continuation consumption UPDATE runs.</summary>
    private sealed class ArmOnConsumptionUpdateInterceptor(ConsumptionCommitGate gate)
        : DbCommandInterceptor
    {
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            System.Data.Common.DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            ArmIfConsumptionUpdate(command);
            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }

        public override ValueTask<InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
            System.Data.Common.DbCommand command,
            CommandEventData eventData,
            InterceptionResult<System.Data.Common.DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            ArmIfConsumptionUpdate(command);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }

        private void ArmIfConsumptionUpdate(System.Data.Common.DbCommand command)
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
    /// Cancels at the armed consumption commit: before the commit nothing is consumed, after the
    /// commit the consumption stays authoritative.
    /// </summary>
    private sealed class ConsumptionCommitCancellationInterceptor(
        ConsumptionCommitGate gate,
        CancellationTokenSource cancellation,
        bool afterCommit) : DbTransactionInterceptor
    {
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(
            System.Data.Common.DbTransaction transaction,
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
                    "The consumption was cancelled before its commit.", cancellation.Token);
            }

            return ValueTask.FromResult(result);
        }

        public override Task TransactionCommittedAsync(
            System.Data.Common.DbTransaction transaction,
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
}
