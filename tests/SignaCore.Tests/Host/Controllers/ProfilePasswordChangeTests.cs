using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host.Controllers;
using SignaCore.Host.Models;
using SignaCore.Tests.Host;
using Xunit;

using ServiceMantle.Audit;
using System.Diagnostics;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Tests.TestSupport;

namespace SignaCore.Tests.Host.Controllers;

/// <summary>
/// The self-service password change (<c>POST /api/profile/password</c>): the single transaction
/// that owns the new credential hash, every promised revocation (all identity sessions with the
/// canonical reason <c>password_changed</c> including the caller's own, all interactive families,
/// all legacy refresh tokens), and the audit row — plus the re-authentication boundary: a wrong
/// current password is a generic failure on the shared failed-attempt path with no writes, and it
/// is indistinguishable from an account without a password credential. No plaintext password or
/// hash may reach the audit snapshot or the response.
/// </summary>
public sealed class ProfilePasswordChangeTests
{
    private const string CurrentPassword = "Current-Secret-123";
    private const string NewPassword = "Brand-New-Secret-1";
    private const string WrongPassword = "Not-The-Current-One-1";

    [Fact]
    public async Task ChangePassword_WritesTheNewHash_AndRevokesEverythingInOneTransaction()
    {
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        var seed = await SeedAsync(database.Context);
        var hasher = FastHasher();

        var result = await InvokeAsync(database.Context, seed.AccountId, hasher,
            new EfCoreManagementAuditWriter<IdentityDbContext>(database.Context),
            new ChangePasswordRequest(CurrentPassword, NewPassword),
            TestContext.Current.CancellationToken);

        var ok = Assert.IsType<OkObjectResult>(result);
        var operation = Assert.IsType<OperationResponse>(ok.Value);
        Assert.True(operation.Success);

        database.Context.ChangeTracker.Clear();

        // The hash write: the new password verifies, the old one does not.
        var credential = await database.Context.PasswordCredentials.AsNoTracking()
            .SingleAsync(row => row.Id == seed.CredentialId, TestContext.Current.CancellationToken);
        Assert.True(hasher.VerifyPassword(NewPassword, credential.PasswordHash));
        Assert.False(hasher.VerifyPassword(CurrentPassword, credential.PasswordHash));

        // Every session of the account is revoked with the canonical reason, the caller's own
        // included (the seed session is the only one and stands for "all of them").
        var session = await database.Context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, TestContext.Current.CancellationToken);
        Assert.NotNull(session.RevokedAt);
        Assert.Equal("password_changed", session.RevocationReason);

        // Interactive family and legacy rows are both revoked.
        var familyRoot = await database.Context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == seed.FamilyRootId, TestContext.Current.CancellationToken);
        Assert.True(familyRoot.IsRevoked);
        var legacy = await database.Context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == seed.LegacyTokenId, TestContext.Current.CancellationToken);
        Assert.True(legacy.IsRevoked);

        // The audit row committed with the state, carrying only bounded counts in the description.
        var audit = Assert.Single(await SharedAuditTable.ReadAsync(
            database.Context, TestContext.Current.CancellationToken));
        Assert.Equal("password_changed", audit.Action);
        Assert.Contains("revoked sessions: 1", audit.SecurityDescription, StringComparison.Ordinal);
        Assert.Contains("revoked family members: 1", audit.SecurityDescription, StringComparison.Ordinal);
        Assert.Contains("revoked legacy tokens: 1", audit.SecurityDescription, StringComparison.Ordinal);

        // Canary: no plaintext password and no hash in the audit row or the response.
        foreach (var canary in new[] { CurrentPassword, NewPassword, credential.PasswordHash })
        {
            Assert.DoesNotContain(canary, audit.SecurityDescription ?? string.Empty, StringComparison.Ordinal);
            Assert.DoesNotContain(canary, operation.Message ?? string.Empty, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task ChangePassword_WhenTheAuditWriteFails_RollsBackEverything()
    {
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        var seed = await SeedAsync(database.Context);
        var hasher = FastHasher();
        var audit = new ThrowingAuditService();

        await Assert.ThrowsAsync<InvalidOperationException>(() => InvokeAsync(
            database.Context, seed.AccountId, hasher, audit,
            new ChangePasswordRequest(CurrentPassword, NewPassword),
            TestContext.Current.CancellationToken));

        await AssertCleanRollbackAsync(database.Context, seed, hasher);
    }

    [Fact]
    public async Task ChangePassword_WhenCanceledBeforeCommit_RollsBackEverything()
    {
        using var cancellation = new CancellationTokenSource();
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        var seed = await SeedAsync(database.Context);
        var hasher = FastHasher();
        // EV-18: the operation token is cancelled while the audit row is staged — before the
        // single commit that carries the hash write and the revocations.
        var audit = new CancelingAuditService(cancellation);

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => InvokeAsync(
            database.Context, seed.AccountId, hasher, audit,
            new ChangePasswordRequest(CurrentPassword, NewPassword),
            cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        await AssertCleanRollbackAsync(database.Context, seed, hasher);
    }

    [Fact]
    public async Task ChangePassword_WrongCurrentPassword_GenericFailureCountsTheAttemptAndWritesNothingElse()
    {
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        var seed = await SeedAsync(database.Context);
        var hasher = FastHasher();

        var result = await InvokeAsync(database.Context, seed.AccountId, hasher,
            new EfCoreManagementAuditWriter<IdentityDbContext>(database.Context),
            new ChangePasswordRequest(WrongPassword, NewPassword),
            TestContext.Current.CancellationToken);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        var error = Assert.IsType<ErrorResponse>(bad.Value);
        Assert.Equal("Wrong current password.", error.Message);

        // The shared failed-attempt path: exactly one counted failure for the credential username.
        var attempt = await database.Context.LoginAttempts.AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(IdentityValueNormalizer.Normalize(seed.Username), attempt.UsernameNormalized);
        Assert.Equal(1, attempt.FailedAttempts);

        await AssertCleanRollbackAsync(database.Context, seed, hasher, expectLoginAttempt: true);
    }

    [Fact]
    public async Task ChangePassword_WithoutAPasswordCredential_IsIndistinguishableFromAWrongPassword()
    {
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        // An account that authenticates with a token but carries no password credential at all.
        var bareAccountId = Guid.NewGuid();
        database.Context.Accounts.Add(new AccountEntity
        {
            Id = bareAccountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        database.Context.ChangeTracker.Clear();
        var hasher = FastHasher();

        var result = await InvokeAsync(database.Context, bareAccountId, hasher,
            new EfCoreManagementAuditWriter<IdentityDbContext>(database.Context),
            new ChangePasswordRequest(WrongPassword, NewPassword),
            TestContext.Current.CancellationToken);

        // The exact same status and message as the wrong-password branch, and no failure count
        // (there is no username to count) and no state change.
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("Wrong current password.", Assert.IsType<ErrorResponse>(bad.Value).Message);
        Assert.Empty(await database.Context.LoginAttempts.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await SharedAuditTable.ReadAsync(database.Context, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ChangePassword_WeakNewPassword_FailsTheExistingPolicyWithoutAnyWrite()
    {
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        var seed = await SeedAsync(database.Context);
        var hasher = FastHasher();

        var result = await InvokeAsync(database.Context, seed.AccountId, hasher,
            new EfCoreManagementAuditWriter<IdentityDbContext>(database.Context),
            new ChangePasswordRequest(CurrentPassword, "weak"),
            TestContext.Current.CancellationToken);

        var bad = Assert.IsType<BadRequestObjectResult>(result);
        var error = Assert.IsType<ErrorResponse>(bad.Value);
        // The reused creation-path policy speaks; nothing is written and no attempt is counted.
        Assert.Contains("at least", error.Message, StringComparison.Ordinal);
        await AssertCleanRollbackAsync(database.Context, seed, hasher);
    }

    [Fact]
    public async Task ChangePassword_EmptyInput_FailsWithoutAnyLookupOrWrite()
    {
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        var seed = await SeedAsync(database.Context);

        var result = await InvokeAsync(database.Context, seed.AccountId, FastHasher(),
            new EfCoreManagementAuditWriter<IdentityDbContext>(database.Context),
            new ChangePasswordRequest(CurrentPassword, string.Empty),
            TestContext.Current.CancellationToken);

        Assert.IsType<BadRequestObjectResult>(result);
        Assert.Empty(await database.Context.LoginAttempts.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        await AssertCleanRollbackAsync(database.Context, seed, FastHasher());
    }

    [Fact]
    public async Task ChangePassword_WithoutAuthentication_ReturnsUnauthorized()
    {
        var controller = CreateController(user: null);
        // The unauthorized path resolves the account id before touching any service, so the
        // collaborators are never reached.
        var result = await controller.ChangePassword(
            new ChangePasswordRequest(CurrentPassword, NewPassword),
            null!, null!, null!, null!, null!, null!, null!, null!, null!, null!, null!,
            TestContext.Current.CancellationToken);

        Assert.IsType<UnauthorizedResult>(result);
    }

    // ---- Harness ----

    private static async Task<IActionResult> InvokeAsync(
        IdentityDbContext context,
        Guid accountId,
        IPasswordHasher hasher,
        IManagementAuditWriter audit,
        ChangePasswordRequest request,
        CancellationToken cancellationToken)
    {
        var controller = CreateController(CreateAuthenticatedUser(accountId));
        controller.HttpContext.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.46");
        var unitOfWork = new EfCoreUnitOfWork(context);
        var refreshTokens = new RefreshTokenRepository(context);
        return await controller.ChangePassword(
            request,
            new PasswordCredentialRepository(context),
            hasher,
            new DefaultPasswordPolicy(),
            new PasswordDecoyHash(new PasswordHasherOptions { WorkFactor = 4 }),
            new LoginAttemptRepository(context),
            new IdentitySessionRepository(context),
            new RefreshTokenFamilyStore(
                refreshTokens, unitOfWork,
                Microsoft.Extensions.Logging.Abstractions.NullLogger<RefreshTokenFamilyStore>.Instance),
            refreshTokens,
            context,
            unitOfWork,
            audit,
            cancellationToken);
    }

    private static ProfileController CreateController(ClaimsPrincipal? user)
    {
        var controller = new ProfileController();
        var httpContext = new DefaultHttpContext();
        if (user != null)
        {
            httpContext.User = user;
        }

        // ChangePassword records the correlation id; establish it with the real middleware as
        // production does.
        CorrelationTestPipeline.Establish(httpContext);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };
        return controller;
    }

    private static ClaimsPrincipal CreateAuthenticatedUser(Guid accountId) =>
        new(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, accountId.ToString())],
            "Test"));

    private static IPasswordHasher FastHasher() =>
        new BCryptPasswordHasher(new PasswordHasherOptions { WorkFactor = 4 });

    private sealed record Seed(
        Guid AccountId,
        Guid CredentialId,
        string Username,
        Guid SessionId,
        Guid FamilyRootId,
        Guid LegacyTokenId);

    private static async Task<Seed> SeedAsync(IdentityDbContext context)
    {
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var username = $"pwd_change_{accountId:N}";
        var sessionId = Guid.NewGuid();
        var familyRootId = Guid.NewGuid();
        var legacyTokenId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var hasher = FastHasher();
        context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = now });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = credentialId,
            AccountId = accountId,
            Username = username,
            PasswordHash = hasher.HashPassword(CurrentPassword),
            CreatedAt = now
        });
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
            AppId = "pwd-change-app",
            TokenValue = RefreshTokenDigest.Compute("pwd-change-family-" + familyRootId.ToString("N")),
            CreatedAt = now,
            ExpiresAt = now.AddDays(7),
            IsRevoked = false,
            IdentitySessionId = sessionId,
            Scope = "openid profile offline_access",
            AuthTime = now.AddMinutes(-5)
        });
        context.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = legacyTokenId,
            FamilyId = legacyTokenId,
            AccountId = accountId,
            AppId = "pwd-change-app",
            TokenValue = RefreshTokenDigest.Compute("pwd-change-legacy-" + legacyTokenId.ToString("N")),
            CreatedAt = now,
            ExpiresAt = now.AddDays(7),
            IsRevoked = false
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
        return new Seed(accountId, credentialId, username, sessionId, familyRootId, legacyTokenId);
    }

    private static async Task AssertCleanRollbackAsync(
        IdentityDbContext context,
        Seed seed,
        IPasswordHasher hasher,
        bool expectLoginAttempt = false)
    {
        context.ChangeTracker.Clear();

        // The hash is untouched: the current password still verifies, the new one does not.
        var credential = await context.PasswordCredentials.AsNoTracking()
            .SingleAsync(row => row.Id == seed.CredentialId, TestContext.Current.CancellationToken);
        Assert.True(hasher.VerifyPassword(CurrentPassword, credential.PasswordHash));
        Assert.False(hasher.VerifyPassword(NewPassword, credential.PasswordHash));

        var session = await context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == seed.SessionId, TestContext.Current.CancellationToken);
        Assert.Null(session.RevokedAt);
        var familyRoot = await context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == seed.FamilyRootId, TestContext.Current.CancellationToken);
        Assert.False(familyRoot.IsRevoked);
        var legacy = await context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == seed.LegacyTokenId, TestContext.Current.CancellationToken);
        Assert.False(legacy.IsRevoked);

        Assert.Empty(await SharedAuditTable.ReadAsync(context, TestContext.Current.CancellationToken));

        var attempts = await context.LoginAttempts.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken);
        if (expectLoginAttempt)
        {
            Assert.Equal(1, Assert.Single(attempts).FailedAttempts);
        }
        else
        {
            Assert.Empty(attempts);
        }
    }

    private sealed class ThrowingAuditService : IManagementAuditWriter
    {
        public ValueTask<ManagementAuditRecord> RecordAsync(
            ManagementAuditEvent auditEvent,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("Injected audit write failure.");
    }

    private sealed class CancelingAuditService(CancellationTokenSource cancellation) : IManagementAuditWriter
    {
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

        public static async Task<MigratedSqliteTestDatabase> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            var builder = new DbContextOptionsBuilder<IdentityDbContext>()
                .UseSqlite(
                    connection,
                    providerOptions => providerOptions.MigrationsAssembly(
                        "SignaCore.Database.Migrations.Sqlite"));
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
