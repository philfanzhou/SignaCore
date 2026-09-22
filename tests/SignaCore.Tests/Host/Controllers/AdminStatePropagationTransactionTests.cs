using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Host.Controllers;
using SignaCore.Host.Models;
using Xunit;

using ServiceMantle.Audit;
using System.Diagnostics;
using ServiceMantle.Persistence.EntityFrameworkCore;

using SignaCore.Tests.TestSupport;

namespace SignaCore.Tests.Host.Controllers;

/// <summary>
/// The commit boundary of the three state-propagation admin transactions (<c>EV-08</c>,
/// <c>EV-09</c>, <c>EV-11</c>): the state change, every promised revocation, and the audit row
/// are one unit on the production migration chain — a failed audit write or caller cancellation
/// before the commit persists neither the flag change nor any revocation, and a repeated disable
/// of an already-disabled account performs no writes at all.
/// </summary>
public sealed class AdminStatePropagationTransactionTests
{
    private const string AppId = "state-propagation-app";

    [Theory]
    [InlineData("user-status")]
    [InlineData("app-callback")]
    [InlineData("oidc-policy")]
    public async Task StateChanges_WhenTheAuditWriteFails_RollBackEverything(string endpoint)
    {
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        var seed = await SeedAsync(database.Context);
        var audit = new ThrowingAuditService();
        IActionResult? response = null;

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            response = await InvokeAsync(
                endpoint, database.Context, audit, seed, TestContext.Current.CancellationToken));

        Assert.Null(response);
        await AssertCleanRollbackAsync(database.Context, seed);
        // The throwing audit service never turned the failure into an audit row either.
        Assert.False(audit.Completed);
    }

    [Theory]
    [InlineData("user-status")]
    [InlineData("app-callback")]
    [InlineData("oidc-policy")]
    public async Task StateChanges_WhenCanceledBeforeCommit_RollBackEverything(string endpoint)
    {
        using var cancellation = new CancellationTokenSource();
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        var seed = await SeedAsync(database.Context);
        // EV-18: the operation token is cancelled while the audit row is staged — before the
        // single commit that carries the flag change and the revocations.
        var audit = new CancelingAuditService(cancellation);
        IActionResult? response = null;

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            response = await InvokeAsync(
                endpoint, database.Context, audit, seed, cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Null(response);
        await AssertCleanRollbackAsync(database.Context, seed);
    }

    [Fact]
    public async Task DisablingAnAccount_RevokeSessionsAndFamiliesWithTheCanonicalReason()
    {
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        var seed = await SeedAsync(database.Context);
        var now = DateTimeOffset.UtcNow;

        var result = await InvokeAsync(
            "user-status", database.Context, new EfCoreManagementAuditWriter<IdentityDbContext>(database.Context),
            seed, TestContext.Current.CancellationToken);

        Assert.IsType<OkObjectResult>(result);
        database.Context.ChangeTracker.Clear();
        var session = await database.Context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, TestContext.Current.CancellationToken);
        Assert.NotNull(session.RevokedAt);
        Assert.Equal("account_disabled", session.RevocationReason);
        var member = await database.Context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == seed.FamilyRootId, TestContext.Current.CancellationToken);
        Assert.True(member.IsRevoked);
        var account = await database.Context.Accounts.AsNoTracking()
            .SingleAsync(row => row.Id == seed.AccountId, TestContext.Current.CancellationToken);
        Assert.False(account.IsActive);
        var audit = Assert.Single(
            (await SharedAuditTable.ReadAsync(database.Context, TestContext.Current.CancellationToken))
            .Where(row => row.Action == "account_disabled"));
        Assert.Contains("revoked sessions: 1", audit.SecurityDescription, StringComparison.Ordinal);
        Assert.Contains("revoked family members: 1", audit.SecurityDescription, StringComparison.Ordinal);

        // The idempotent repeat disable keeps the first revocation facts.
        var firstRevokedAt = session.RevokedAt;
        var repeat = await InvokeAsync(
            "user-status", database.Context, new EfCoreManagementAuditWriter<IdentityDbContext>(database.Context),
            seed, TestContext.Current.CancellationToken);
        Assert.IsType<OkObjectResult>(repeat);
        database.Context.ChangeTracker.Clear();
        var revisited = await database.Context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, TestContext.Current.CancellationToken);
        Assert.Equal(firstRevokedAt, revisited.RevokedAt);
        Assert.Equal("account_disabled", revisited.RevocationReason);
    }

    /// <summary>A legacy refresh row is structurally out of reach of the account revocation.</summary>
    [Fact]
    public async Task DisablingAnAccount_DoesNotRevokeALegacyRefreshRow()
    {
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        var seed = await SeedAsync(database.Context);
        var legacyId = Guid.NewGuid();
        database.Context.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = legacyId,
            FamilyId = legacyId,
            AccountId = seed.AccountId,
            AppId = AppId,
            TokenValue = RefreshTokenDigest.Compute("state-propagation-legacy-token"),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            IsRevoked = false
        });
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        database.Context.ChangeTracker.Clear();

        var result = await InvokeAsync(
            "user-status", database.Context, new EfCoreManagementAuditWriter<IdentityDbContext>(database.Context),
            seed, TestContext.Current.CancellationToken);

        Assert.IsType<OkObjectResult>(result);
        database.Context.ChangeTracker.Clear();
        var legacy = await database.Context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == legacyId, TestContext.Current.CancellationToken);
        Assert.False(legacy.IsRevoked);
    }

    // ---- Harness ----

    private static async Task<IActionResult> InvokeAsync(
        string endpoint,
        IdentityDbContext context,
        IManagementAuditWriter audit,
        Seed seed,
        CancellationToken cancellationToken)
    {
        var controller = AuthTestDoubles.CreateAdminController();
        controller.HttpContext.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.46");
        var accounts = new AccountRepository(context);
        var apps = new AppRegistrationRepository(context);
        var unitOfWork = new EfCoreUnitOfWork(context);
        var sessions = new IdentitySessionRepository(context);
        var families = new RefreshTokenFamilyStore(
            new RefreshTokenRepository(context), unitOfWork, NullLogger<RefreshTokenFamilyStore>.Instance);
        return endpoint switch
        {
            "user-status" => await controller.UpdateUserStatus(
                seed.AccountId,
                new AdminUpdateStatusRequest(false),
                accounts, unitOfWork, audit, context, sessions, families,
                cancellationToken),
            "app-callback" => await controller.UpdateCallback(
                AppId,
                new AdminUpdateCallbackRequest(null, 0, false),
                apps, new CallbackUrlValidator(), unitOfWork, audit, context, families,
                cancellationToken),
            _ => await controller.UpdateOidcPolicy(
                AppId,
                new AdminUpdateOidcPolicyRequest("Confidential", true, ["openid"], false, null),
                apps, unitOfWork, audit,
                ProductionEnvironment(),
                context, families,
                cancellationToken)
        };
    }

    private static IWebHostEnvironment ProductionEnvironment()
    {
        var environment = new Mock<IWebHostEnvironment>();
        environment.SetupGet(item => item.EnvironmentName).Returns("Production");
        environment.SetupGet(item => item.ApplicationName).Returns("SignaCore.Tests");
        environment.SetupGet(item => item.ContentRootPath).Returns(AppContext.BaseDirectory);
        environment.SetupGet(item => item.ContentRootFileProvider)
            .Returns(new Microsoft.Extensions.FileProviders.NullFileProvider());
        environment.SetupGet(item => item.WebRootPath).Returns(AppContext.BaseDirectory);
        environment.SetupGet(item => item.WebRootFileProvider)
            .Returns(new Microsoft.Extensions.FileProviders.NullFileProvider());
        return environment.Object;
    }

    private sealed record Seed(
        Guid AccountId,
        Guid SessionId,
        Guid FamilyRootId,
        Guid AppRowId);

    /// <summary>
    /// Seeds the exact pre-state of all three transactions: an active account with a live session
    /// and a live interactive family, and an application whose callback state is active and whose
    /// refresh capability is on.
    /// </summary>
    private static async Task<Seed> SeedAsync(IdentityDbContext context)
    {
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var appRowId = Guid.NewGuid();
        var familyRootId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = now });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = credentialId,
            AccountId = accountId,
            Username = $"state_prop_{accountId:N}",
            PasswordHash = "hash",
            CreatedAt = now
        });
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = appRowId,
            AppId = AppId,
            AppSecretHash = "hash",
            AppName = "State Propagation App",
            IsActive = true,
            CreatedAt = now,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = "openid profile offline_access",
            AllowRefreshToken = true
        });
        context.AppRedirectUris.Add(new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = appRowId,
            Kind = RedirectUriKind.Redirect,
            CanonicalUri = "https://bff.state-propagation.test/callback"
        });
        var sessionId = Guid.NewGuid();
        context.IdentitySessions.Add(new IdentitySessionEntity
        {
            Id = sessionId,
            AccountId = accountId,
            PasswordCredentialId = credentialId,
            AuthMethod = "Password",
            AuthTime = now,
            LastSeenAt = now,
            IdleExpiresAt = now.AddMinutes(30),
            AbsoluteExpiresAt = now.AddHours(12)
        });
        context.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = familyRootId,
            FamilyId = familyRootId,
            AccountId = accountId,
            AppId = AppId,
            TokenValue = RefreshTokenDigest.Compute("state-propagation-family-" + familyRootId.ToString("N")),
            CreatedAt = now,
            ExpiresAt = now.AddDays(7),
            IsRevoked = false,
            IdentitySessionId = sessionId,
            Scope = "openid profile offline_access",
            AuthTime = now.AddMinutes(-5)
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
        return new Seed(accountId, sessionId, familyRootId, appRowId);
    }

    private static async Task AssertCleanRollbackAsync(IdentityDbContext context, Seed seed)
    {
        context.ChangeTracker.Clear();
        var account = await context.Accounts.AsNoTracking()
            .SingleAsync(row => row.Id == seed.AccountId, TestContext.Current.CancellationToken);
        Assert.True(account.IsActive);
        var session = await context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, TestContext.Current.CancellationToken);
        Assert.Null(session.RevokedAt);
        var member = await context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == seed.FamilyRootId, TestContext.Current.CancellationToken);
        Assert.False(member.IsRevoked);
        var application = await context.AppRegistrations.AsNoTracking()
            .SingleAsync(row => row.Id == seed.AppRowId, TestContext.Current.CancellationToken);
        Assert.True(application.IsActive);
        Assert.True(application.AllowRefreshToken);
        Assert.Empty(await SharedAuditTable.ReadAsync(context, TestContext.Current.CancellationToken));
    }

    private sealed class ThrowingAuditService : IManagementAuditWriter
    {
        public bool Completed { get; private set; }

        public ValueTask<ManagementAuditRecord> RecordAsync(
            ManagementAuditEvent auditEvent,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Injected audit write failure.");
    }

    private sealed class CancelingAuditService(CancellationTokenSource cancellation) : IManagementAuditWriter
    {
        public bool Completed { get; private set; }

        public async ValueTask<ManagementAuditRecord> RecordAsync(
            ManagementAuditEvent auditEvent,
            CancellationToken cancellationToken = default)
        {
            await cancellation.CancelAsync();
            cancellationToken.ThrowIfCancellationRequested();
            throw new UnreachableException("The cancellation check above must have thrown.");
        }
    }

    private sealed class MigratedSqliteTestDatabase : IAsyncDisposable
    {
        private MigratedSqliteTestDatabase(SqliteConnection connection, IdentityDbContext context)
        {
            Connection = connection;
            Context = context;
        }

        private SqliteConnection Connection { get; }

        public IdentityDbContext Context { get; }

        public static async Task<MigratedSqliteTestDatabase> CreateAsync(IInterceptor? interceptor = null)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            var builder = new DbContextOptionsBuilder<IdentityDbContext>()
                .UseSqlite(
                    connection,
                    providerOptions => providerOptions.MigrationsAssembly(
                        "SignaCore.Database.Migrations.Sqlite"));
            if (interceptor != null) builder.AddInterceptors(interceptor);
            var context = new IdentityDbContext(builder.Options);
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
            return new MigratedSqliteTestDatabase(connection, context);
        }

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }
}
