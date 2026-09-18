using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.Tests.Host.Services;

/// <summary>
/// The authorize-side reuse transaction as a unit: the committed shape (bounded slide, code row
/// bound to the locked session, one continuation-shaped <c>accepted</c> audit row, plaintext code
/// only after the commit), the rolled-back <c>null</c> for a revoked session with zero writes
/// (<c>EV-04</c>), and the <c>EV-18</c> cancellation observed before the commit leaving no code,
/// no touch, and no audit behind.
/// </summary>
public sealed class OidcAuthorizationSessionReuseServiceTests
{
    private const string ClientId = "reuse-unit-app";
    private const string RedirectUri = "https://bff.reuse.unit.test/callback";
    private const string Nonce = "reuse-unit-nonce";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string Username = "reuse_unit_user";

    [Fact]
    public async Task TryIssueAsync_CommitsTheSlideTheCodeAndTheAudit()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context);
        var now = DateTimeOffset.UtcNow;

        var code = await database.Service.TryIssueAsync(
            CreateAccepted(seed.ApplicationId),
            seed.SessionId,
            now,
            "203.0.113.9",
            "reuse-unit-correlation",
            TestContext.Current.CancellationToken);

        Assert.NotNull(code);
        var cancellationToken = TestContext.Current.CancellationToken;

        // The plaintext code resolves to exactly the row bound to the locked session.
        var lookup = await database.Codes.FindAsync(code!, now, cancellationToken);
        Assert.Equal(AuthorizationCodeState.Unconsumed, lookup.State);
        Assert.Equal(seed.SessionId, lookup.Entity!.IdentitySessionId);
        Assert.Equal(seed.ApplicationId, lookup.Entity.AppRegistrationId);
        Assert.Equal(RedirectUri, lookup.Entity.RedirectUri);
        Assert.Equal("openid profile", lookup.Entity.Scope);

        var audit = Assert.Single(await database.Context.AuditLogs.AsNoTracking()
            .ToListAsync(cancellationToken));
        Assert.Equal("oidc.authorize.validated", audit.Action);
        Assert.Equal("OidcAuthorizationRequest", audit.TargetType);
        Assert.Equal(seed.ApplicationId.ToString("D"), audit.TargetId);
        Assert.Equal("accepted", audit.Description);

        // A fresh session is under the one-minute write threshold: no activity write.
        var session = await database.Context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, cancellationToken);
        Assert.Equal(seed.AuthTime.UtcTicks / 10, session.LastSeenAt.UtcTicks / 10);
    }

    [Fact]
    public async Task TryIssueAsync_ForARevokedSession_ReturnsNullAndWritesNothing()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context);

        await database.Sessions.RevokeAsync(
            seed.SessionId,
            IdentitySessionRevocationReason.Administrative,
            DateTimeOffset.UtcNow,
            TestContext.Current.CancellationToken);

        var code = await database.Service.TryIssueAsync(
            CreateAccepted(seed.ApplicationId),
            seed.SessionId,
            DateTimeOffset.UtcNow,
            null,
            null,
            TestContext.Current.CancellationToken);

        Assert.Null(code);
        Assert.Empty(await database.Context.AuthorizationCodes.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await database.Context.AuditLogs.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TryIssueAsync_WithACancelledToken_ThrowsAndWritesNothing()
    {
        await using var database = await CreateDatabaseAsync();
        var seed = await SeedAsync(database.Context);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            database.Service.TryIssueAsync(
                CreateAccepted(seed.ApplicationId),
                seed.SessionId,
                DateTimeOffset.UtcNow,
                null,
                null,
                cancellation.Token));

        Assert.Empty(await database.Context.AuthorizationCodes.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await database.Context.AuditLogs.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        var session = await database.Context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, TestContext.Current.CancellationToken);
        Assert.Equal(seed.AuthTime.UtcTicks / 10, session.LastSeenAt.UtcTicks / 10);
    }

    // ---- Harness ----

    private sealed record Seed(Guid ApplicationId, Guid AccountId, Guid CredentialId, Guid SessionId, DateTimeOffset AuthTime);

    private static OidcAuthorizationValidationResult.Accepted CreateAccepted(Guid applicationId) =>
        new(ClientId, applicationId, RedirectUri, "openid profile", "reuse-state", Nonce, Challenge);

    private sealed class ReuseDatabase(
        SqliteConnection connection,
        IdentityDbContext context,
        OidcAuthorizationSessionReuseService service,
        IIdentitySessionStore sessions,
        IAuthorizationCodeStore codes) : IAsyncDisposable
    {
        public SqliteConnection Connection { get; } = connection;
        public IdentityDbContext Context { get; } = context;
        public OidcAuthorizationSessionReuseService Service { get; } = service;
        public IIdentitySessionStore Sessions { get; } = sessions;
        public IAuthorizationCodeStore Codes { get; } = codes;

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }

    private static async Task<ReuseDatabase> CreateDatabaseAsync()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var context = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(connection).Options);
        await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);

        var unitOfWork = new EfCoreUnitOfWork(context);
        var accountRepository = new AccountRepository(context);
        var sessions = new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork);
        var codes = new AuthorizationCodeStore(new AuthorizationCodeRepository(context), unitOfWork);
        var service = new OidcAuthorizationSessionReuseService(
            sessions,
            codes,
            accountRepository,
            new AuditService(new LoginHistoryRepository(context), new AuditLogRepository(context)),
            unitOfWork,
            context);
        return new ReuseDatabase(connection, context, service, sessions, codes);
    }

    private static async Task<Seed> SeedAsync(IdentityDbContext context)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var applicationId = Guid.NewGuid();
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = applicationId,
            AppId = ClientId,
            AppSecretHash = "hash",
            AppName = "Reuse Unit Client",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = "openid profile",
            AllowRefreshToken = false
        });
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
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
            PasswordHash = "hash",
            CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(cancellationToken);
        context.ChangeTracker.Clear();

        var unitOfWork = new EfCoreUnitOfWork(context);
        var sessions = new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork);
        var session = await sessions.CreateAsync(accountId, credentialId, DateTimeOffset.UtcNow, cancellationToken);
        return new Seed(applicationId, accountId, credentialId, session.Id, session.AuthTime);
    }
}
