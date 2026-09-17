using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.Tests.Host.Services;

/// <summary>
/// The <c>EV-01</c> success transaction as a unit: <see cref="OidcLoginCompletionService"/>
/// commits the continuation consumption, the session, the code, the counter clear, the login
/// info, and the success audit as one unit; the consumed-continuation and deactivated-account
/// races answer with the single <c>null</c> and roll the whole unit back; cancellation observed
/// before the commit leaves zero writes (<c>EV-18</c>/<c>SC-20</c>); and a failing credential
/// result or a missing credential id is a programming error, never a write.
/// </summary>
public sealed class OidcLoginCompletionServiceTests
{
    private const string ClientId = "completion-client";
    private const string RedirectUri = "https://bff.completion.test/callback";
    private const string Scope = "openid profile";
    private const string State = "completion-state-0123456789abcdef";
    private const string Nonce = "completion-nonce-0123456789abcdef";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string Username = "completion_user";
    private const string CorrelationId = "completion-correlation-1234567890";

    [Fact]
    public async Task CompleteAsync_CommitsTheWholeUnit_AndReturnsTheSessionAndCode()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context);
        var attemptRow = new LoginAttemptEntity
        {
            Id = Guid.NewGuid(),
            Username = Username,
            UsernameNormalized = IdentityValueNormalizer.Normalize(Username),
            LastAttemptAt = DateTimeOffset.UtcNow,
            FailedAttempts = 2
        };
        database.Context.LoginAttempts.Add(attemptRow);
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        database.Context.ChangeTracker.Clear();

        // SQLite stores instants on a whole-microsecond grid, so the captured instant is aligned
        // to it: a Linux clock ticks at 100ns and would otherwise be truncated on the round trip
        // and fail the exact-equality assertions below.
        var now = new DateTimeOffset(
            DateTimeOffset.UtcNow.UtcTicks / 10 * 10, TimeSpan.Zero);
        var completion = await database.Service.CompleteAsync(
            seed.Handle,
            CreateAccepted(seed.ApplicationId),
            CreateSuccess(seed, withCounterClear: true),
            ClientId,
            "203.0.113.9",
            "test-agent",
            CorrelationId,
            now,
            TestContext.Current.CancellationToken);

        Assert.NotNull(completion);
        var context = database.Context;
        var cancellationToken = TestContext.Current.CancellationToken;

        var continuation = await context.AuthorizationRequests.AsNoTracking()
            .SingleAsync(row => row.Id == seed.ContinuationId, cancellationToken);
        Assert.Equal(now, continuation.ConsumedAt);

        var session = await context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == completion!.SessionId, cancellationToken);
        Assert.Equal(seed.AccountId, session.AccountId);
        Assert.Equal(seed.CredentialId, session.PasswordCredentialId);
        Assert.Equal(IdentityConstants.AuthMethodPassword, session.AuthMethod);
        Assert.Equal(now, session.AuthTime);
        Assert.Equal(now, session.LastSeenAt);

        var code = await context.AuthorizationCodes.AsNoTracking()
            .SingleAsync(row => row.IdentitySessionId == session.Id, cancellationToken);
        Assert.Equal(seed.ApplicationId, code.AppRegistrationId);
        Assert.Equal(RedirectUri, code.RedirectUri);
        Assert.Equal(Scope, code.Scope);
        Assert.Equal(Nonce, code.Nonce);
        Assert.Equal(Challenge, code.CodeChallenge);
        Assert.Equal(now, session.AuthTime);
        Assert.Null(code.ConsumedAt);
        Assert.Equal(
            IdentityConstants.AuthorizationCodeLifetimeSeconds,
            (code.ExpiresAt - code.CreatedAt).TotalSeconds);

        // The returned plaintext code resolves to exactly this row through the shared store.
        var store = new AuthorizationCodeStore(
            new AuthorizationCodeRepository(context), new EfCoreUnitOfWork(context));
        var lookup = await store.FindAsync(completion.Code, now, cancellationToken);
        Assert.Equal(AuthorizationCodeState.Unconsumed, lookup.State);
        Assert.Equal(code.Id, lookup.Entity!.Id);

        Assert.Empty(await context.LoginAttempts.AsNoTracking().ToListAsync(cancellationToken));

        var account = await context.Accounts.AsNoTracking()
            .SingleAsync(row => row.Id == seed.AccountId, cancellationToken);
        Assert.Equal(IdentityConstants.AuthMethodPassword, account.LastLoginMethod);
        Assert.Equal(1, account.TotalLoginCount);
        Assert.Equal("203.0.113.9", account.LastLoginIp);

        var history = Assert.Single(await context.LoginHistories.AsNoTracking()
            .ToListAsync(cancellationToken));
        Assert.Equal(seed.AccountId, history.AccountId);
        Assert.Equal(Username, history.Username);
        Assert.Equal(OidcLoginFailureRecorder.OidcLoginAuthMethod, history.AuthMethod);
        Assert.Equal("login_success", history.EventType);
        Assert.Null(history.FailureReason);
        Assert.Equal(ClientId, history.AppId);
        Assert.Equal(CorrelationId, history.CorrelationId);
    }

    [Fact]
    public async Task CompleteAsync_OnAConsumedContinuation_ReturnsNullAndWritesNothing()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context);

        // A concurrent winner consumed the continuation first and committed.
        var consumed = await database.Continuations.TryConsumeAsync(
            seed.Handle, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
        Assert.True(consumed);
        database.Context.ChangeTracker.Clear();

        var completion = await database.Service.CompleteAsync(
            seed.Handle,
            CreateAccepted(seed.ApplicationId),
            CreateSuccess(seed, withCounterClear: false),
            ClientId,
            null,
            null,
            CorrelationId,
            DateTimeOffset.UtcNow,
            TestContext.Current.CancellationToken);

        Assert.Null(completion);
        await AssertOnlyTheExistingRowsAsync(database.Context, seed);
    }

    [Fact]
    public async Task CompleteAsync_WhenTheAccountWasDeactivated_RollsTheConsumptionBack()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context);

        // The account was deactivated after the credential check passed.
        var account = await database.Context.Accounts
            .SingleAsync(row => row.Id == seed.AccountId, TestContext.Current.CancellationToken);
        account.IsActive = false;
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        database.Context.ChangeTracker.Clear();

        var completion = await database.Service.CompleteAsync(
            seed.Handle,
            CreateAccepted(seed.ApplicationId),
            CreateSuccess(seed, withCounterClear: false),
            ClientId,
            null,
            null,
            CorrelationId,
            DateTimeOffset.UtcNow,
            TestContext.Current.CancellationToken);

        Assert.Null(completion);

        // The rollback restores the unconsumed continuation, so the same handle can still succeed.
        var continuation = await database.Context.AuthorizationRequests.AsNoTracking()
            .SingleAsync(row => row.Id == seed.ContinuationId, TestContext.Current.CancellationToken);
        Assert.Null(continuation.ConsumedAt);
        await AssertOnlyTheExistingRowsAsync(database.Context, seed);
    }

    [Fact]
    public async Task CompleteAsync_WithACancelledToken_ThrowsAndWritesNothing()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            database.Service.CompleteAsync(
                seed.Handle,
                CreateAccepted(seed.ApplicationId),
                CreateSuccess(seed, withCounterClear: false),
                ClientId,
                null,
                null,
                CorrelationId,
                DateTimeOffset.UtcNow,
                cancellation.Token));

        var continuation = await database.Context.AuthorizationRequests.AsNoTracking()
            .SingleAsync(row => row.Id == seed.ContinuationId, TestContext.Current.CancellationToken);
        Assert.Null(continuation.ConsumedAt);
        await AssertOnlyTheExistingRowsAsync(database.Context, seed);
    }

    [Fact]
    public async Task CompleteAsync_RejectsAFailureResultWithoutAnyWrite()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context);

        var failure = ValidationResult.Failure("Wrong username or password");
        await Assert.ThrowsAsync<ArgumentException>(() =>
            database.Service.CompleteAsync(
                seed.Handle,
                CreateAccepted(seed.ApplicationId),
                failure,
                ClientId,
                null,
                null,
                CorrelationId,
                DateTimeOffset.UtcNow,
                TestContext.Current.CancellationToken));
        await AssertOnlyTheExistingRowsAsync(database.Context, seed);
    }

    [Fact]
    public async Task CompleteAsync_WithoutThePasswordCredentialId_ThrowsBeforeAnyWrite()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context);

        // A success that does not carry the credential it passed on is a programming error.
        var success = ValidationResult.Success(
            new AccountEntity { Id = seed.AccountId, IsActive = true },
            IdentityConstants.AuthMethodPassword,
            Username);
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            database.Service.CompleteAsync(
                seed.Handle,
                CreateAccepted(seed.ApplicationId),
                success,
                ClientId,
                null,
                null,
                CorrelationId,
                DateTimeOffset.UtcNow,
                TestContext.Current.CancellationToken));
        Assert.DoesNotContain(seed.AccountId.ToString(), exception.Message, StringComparison.Ordinal);
        await AssertOnlyTheExistingRowsAsync(database.Context, seed);
    }

    // ---- Helpers ----

    private sealed record Seed(
        Guid ApplicationId,
        Guid AccountId,
        Guid CredentialId,
        Guid ContinuationId,
        string Handle);

    private sealed class CompletionDatabase(
        SqliteConnection connection,
        IdentityDbContext context,
        OidcLoginCompletionService service,
        IAuthorizationRequestStore continuations) : IAsyncDisposable
    {
        public SqliteConnection Connection { get; } = connection;
        public IdentityDbContext Context { get; } = context;
        public OidcLoginCompletionService Service { get; } = service;
        public IAuthorizationRequestStore Continuations { get; } = continuations;

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }

    private static async Task<CompletionDatabase> CreateDatabaseAsync()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var context = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(connection).Options);
        await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);

        var unitOfWork = new EfCoreUnitOfWork(context);
        var accountRepository = new AccountRepository(context);
        var continuations = new AuthorizationRequestStore(
            new AuthorizationRequestRepository(context), unitOfWork);
        var service = new OidcLoginCompletionService(
            continuations,
            accountRepository,
            new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork),
            new AuthorizationCodeStore(new AuthorizationCodeRepository(context), unitOfWork),
            new LoginAttemptRepository(context),
            new AccountLoginInfoService(accountRepository),
            new AuditService(
                new LoginHistoryRepository(context),
                new AuditLogRepository(context)),
            unitOfWork,
            context);
        return new CompletionDatabase(connection, context, service, continuations);
    }

    private static async Task<Seed> SeedAsync(IdentityDbContext context)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var applicationId = Guid.NewGuid();
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = applicationId,
            AppId = ClientId,
            AppSecretHash = "hash",
            AppName = "Completion Client",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = Scope,
            AllowRefreshToken = false
        });
        context.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = credentialId,
            AccountId = accountId,
            Username = Username,
            UsernameNormalized = IdentityValueNormalizer.Normalize(Username),
            PasswordHash = "hash",
            CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(cancellationToken);

        var creation = await new AuthorizationRequestStore(
            new AuthorizationRequestRepository(context), new EfCoreUnitOfWork(context))
            .CreateAsync(CreateAccepted(applicationId), DateTimeOffset.UtcNow, cancellationToken);
        var continuationId = await context.AuthorizationRequests.AsNoTracking()
            .Where(row => row.HandleDigest == LoginHandleDigest.Compute(creation.LoginHandle))
            .Select(row => row.Id)
            .SingleAsync(cancellationToken);
        context.ChangeTracker.Clear();
        return new Seed(applicationId, accountId, credentialId, continuationId, creation.LoginHandle);
    }

    private static OidcAuthorizationValidationResult.Accepted CreateAccepted(Guid applicationId) =>
        new(ClientId, applicationId, RedirectUri, Scope, State, Nonce, Challenge);

    private static ValidationResult CreateSuccess(Seed seed, bool withCounterClear)
    {
        var result = ValidationResult.Success(
            new AccountEntity { Id = seed.AccountId, IsActive = true },
            IdentityConstants.AuthMethodPassword,
            Username,
            passwordCredentialId: seed.CredentialId);
        return withCounterClear
            ? result.WithLoginAttemptChange(new LoginAttemptChange(
                LoginAttemptChangeKind.Clear, Username))
            : result;
    }

    /// <summary>The rollback proof: no session, code, history, audit, or counter change exists.</summary>
    private static async Task AssertOnlyTheExistingRowsAsync(IdentityDbContext context, Seed seed)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        Assert.Empty(await context.IdentitySessions.AsNoTracking().ToListAsync(cancellationToken));
        Assert.Empty(await context.AuthorizationCodes.AsNoTracking().ToListAsync(cancellationToken));
        Assert.Empty(await context.LoginHistories.AsNoTracking().ToListAsync(cancellationToken));
        Assert.Empty(await context.AuditLogs.AsNoTracking().ToListAsync(cancellationToken));
        var account = await context.Accounts.AsNoTracking()
            .SingleAsync(row => row.Id == seed.AccountId, cancellationToken);
        Assert.Equal(0, account.TotalLoginCount);
        Assert.Null(account.LastLoginAt);
    }
}
