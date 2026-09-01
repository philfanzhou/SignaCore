using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using Xunit;

namespace SignaCore.Tests.Database;

public sealed class RepositoryCancellationTests
{
    private static readonly CancellationToken CanceledToken = new(canceled: true);

    [Fact]
    public async Task AccountRepository_PreCanceledAdd_DoesNotStageAccount()
    {
        await using var database = await TestDatabase.CreateAsync();
        var repository = new AccountRepository(database.Context);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await repository.AddAsync(CreateAccount(), CanceledToken));

        Assert.Empty(database.Context.Accounts.Local);
        Assert.Empty(await database.Context.Accounts.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AppExchangeTrustRepository_PreCanceledAdd_DoesNotCreateTrust()
    {
        await using var database = await TestDatabase.CreateAsync();
        var app = CreateApp("accepting-app");
        var sourceApp = CreateApp("source-app");
        database.Context.AppRegistrations.AddRange(app, sourceApp);
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        database.Context.ChangeTracker.Clear();
        var repository = new AppExchangeTrustRepository(database.Context);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await repository.AddAsync(app, sourceApp, approvedBy: null, CanceledToken));

        Assert.Empty(await database.Context.AppExchangeTrusts.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AppRegistrationRepository_PreCanceledAdd_DoesNotStageApplication()
    {
        await using var database = await TestDatabase.CreateAsync();
        var repository = new AppRegistrationRepository(database.Context);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await repository.AddAsync(CreateApp("canceled-app"), CanceledToken));

        Assert.Empty(database.Context.AppRegistrations.Local);
        Assert.Empty(await database.Context.AppRegistrations.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AuditLogRepository_PreCanceledAdd_DoesNotStageAudit()
    {
        await using var database = await TestDatabase.CreateAsync();
        var repository = new AuditLogRepository(database.Context);
        var audit = new AuditLogEntity
        {
            Id = Guid.NewGuid(),
            Action = "repository_cancellation_test",
            TargetType = "TestArtifact",
            TargetId = Guid.NewGuid().ToString(),
            CreatedAt = DateTimeOffset.UtcNow
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await repository.AddAsync(audit, CanceledToken));

        Assert.Empty(database.Context.AuditLogs.Local);
        Assert.Empty(await database.Context.AuditLogs.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LoginAttemptRepository_PreCanceledFailure_DoesNotCreateAttempt()
    {
        await using var database = await TestDatabase.CreateAsync();
        var repository = new LoginAttemptRepository(database.Context);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await repository.RecordFailureAsync(
                "canceled-user",
                DateTimeOffset.UtcNow,
                CanceledToken));

        Assert.Empty(await database.Context.LoginAttempts.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LoginHistoryRepository_PreCanceledAdd_DoesNotStageHistory()
    {
        await using var database = await TestDatabase.CreateAsync();
        var repository = new LoginHistoryRepository(database.Context);
        var history = new LoginHistoryEntity
        {
            Id = Guid.NewGuid(),
            Username = "canceled-user",
            AuthMethod = "test",
            EventType = "test",
            CreatedAt = DateTimeOffset.UtcNow
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await repository.AddAsync(history, CanceledToken));

        Assert.Empty(database.Context.LoginHistories.Local);
        Assert.Empty(await database.Context.LoginHistories.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task OtpRepository_PreCanceledConsume_DoesNotConsumeOtp()
    {
        await using var database = await TestDatabase.CreateAsync();
        var app = CreateApp("otp-app");
        var now = DateTimeOffset.UtcNow;
        database.Context.AppRegistrations.Add(app);
        database.Context.Otps.Add(new OtpEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = app.Id,
            Phone = "test-phone",
            CodeMac = "test-code-mac",
            Status = OtpStatus.Sent,
            ExpiresAt = now.AddMinutes(5),
            LockoutUntil = DateTimeOffset.UnixEpoch,
            HourWindowStartedAt = now,
            DayWindowStartedAt = now,
            Provider = "Test",
            ProfileKey = "test",
            CreatedAt = now
        });
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        database.Context.ChangeTracker.Clear();
        var repository = new OtpRepository(database.Context);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await repository.TryConsumeAsync(
                app.Id,
                "test-phone",
                "test-code-mac",
                now,
                maxAttempts: 5,
                CanceledToken));

        var stored = await database.Context.Otps.AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(OtpStatus.Sent, stored.Status);
    }

    [Fact]
    public async Task PasswordCredentialRepository_PreCanceledAdd_DoesNotStageCredential()
    {
        await using var database = await TestDatabase.CreateAsync();
        var repository = new PasswordCredentialRepository(database.Context);
        var credential = new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = Guid.NewGuid(),
            Username = "canceled-user",
            PasswordHash = "not-persisted",
            CreatedAt = DateTimeOffset.UtcNow
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await repository.AddAsync(credential, CanceledToken));

        Assert.Empty(database.Context.PasswordCredentials.Local);
        Assert.Empty(await database.Context.PasswordCredentials.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RefreshTokenRepository_PreCanceledRevoke_DoesNotRevokeToken()
    {
        await using var database = await TestDatabase.CreateAsync();
        const string presentedToken = "repository-cancellation-revoke-token";
        var source = await SeedRefreshTokenAsync(database.Context, presentedToken);
        var repository = new RefreshTokenRepository(database.Context);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await repository.TryRevokeAsync(presentedToken, CanceledToken));

        var stored = await database.Context.RefreshTokens.AsNoTracking()
            .SingleAsync(
                token => token.Id == source.Id,
                TestContext.Current.CancellationToken);
        Assert.False(stored.IsRevoked);
    }

    [Fact]
    public async Task RefreshTokenRepository_PreCanceledAmbientRotation_DoesNotRotateToken()
    {
        await using var database = await TestDatabase.CreateAsync();
        const string presentedToken = "repository-cancellation-ambient-rotation-token";
        var source = await SeedRefreshTokenAsync(database.Context, presentedToken);
        var replacement = CreateRefreshToken(source.AccountId, "unused-ambient-replacement-token");
        var repository = new RefreshTokenRepository(database.Context);
        await using var transaction = await database.Context.Database.BeginTransactionAsync(
            TestContext.Current.CancellationToken);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await repository.TryRotateAsync(
                presentedToken,
                replacement,
                CanceledToken));

        Assert.Equal(EntityState.Detached, database.Context.Entry(replacement).State);
        var storedSource = await database.Context.RefreshTokens.AsNoTracking()
            .SingleAsync(
                token => token.Id == source.Id,
                TestContext.Current.CancellationToken);
        Assert.False(storedSource.IsRevoked);
        Assert.False(await database.Context.RefreshTokens.AsNoTracking()
            .AnyAsync(
                token => token.Id == replacement.Id,
                TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RefreshTokenRepository_CanceledBeforeCommit_RollsBackSourceAndReplacement()
    {
        using var cancellationSource = new CancellationTokenSource();
        var interceptor = new CancelBeforeCommitInterceptor(cancellationSource);
        await using var database = await TestDatabase.CreateAsync(interceptor);
        const string presentedToken = "repository-cancellation-rotate-token";
        var source = await SeedRefreshTokenAsync(database.Context, presentedToken);
        var replacement = CreateRefreshToken(source.AccountId, "unused-replacement-token");
        var repository = new RefreshTokenRepository(database.Context);
        interceptor.Arm();
        Assert.False(cancellationSource.IsCancellationRequested);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await repository.TryRotateAsync(
                presentedToken,
                replacement,
                cancellationSource.Token));

        Assert.True(cancellationSource.IsCancellationRequested);
        Assert.Equal(1, interceptor.CanceledCommits);
        await using var assertionContext = database.CreateContext();
        var storedSource = await assertionContext.RefreshTokens.AsNoTracking()
            .SingleAsync(
                token => token.Id == source.Id,
                TestContext.Current.CancellationToken);
        Assert.False(storedSource.IsRevoked);
        Assert.False(await assertionContext.RefreshTokens.AsNoTracking()
            .AnyAsync(
                token => token.Id == replacement.Id,
                TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SecurityKeyRepository_PreCanceledDeactivation_DoesNotDeactivateKey()
    {
        await using var database = await TestDatabase.CreateAsync();
        var key = new SecurityKeyEntity
        {
            Id = Guid.NewGuid(),
            KeyId = "cancellation-test-key",
            PublicKeyExponent = "test",
            PublicKeyModulus = "test",
            EncryptedPrivateKeyParams = "test",
            EncryptionSalt = "test",
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
            IsActive = true
        };
        database.Context.SecurityKeys.Add(key);
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        database.Context.ChangeTracker.Clear();
        var repository = new SecurityKeyRepository(database.Context);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await repository.DeactivateAllActiveAsync(CanceledToken));

        var stored = await database.Context.SecurityKeys.AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.True(stored.IsActive);
    }

    [Fact]
    public async Task UserLoginRepository_PreCanceledAdd_DoesNotStageLogin()
    {
        await using var database = await TestDatabase.CreateAsync();
        var repository = new UserLoginRepository(database.Context);
        var login = new UserLoginEntity
        {
            Id = Guid.NewGuid(),
            AccountId = Guid.NewGuid(),
            ProviderName = "Test",
            ProviderUserId = "test-user"
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await repository.AddAsync(login, CanceledToken));

        Assert.Empty(database.Context.UserLogins.Local);
        Assert.Empty(await database.Context.UserLogins.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    private static AccountEntity CreateAccount() => new()
    {
        Id = Guid.NewGuid(),
        IsActive = true,
        CreatedAt = DateTimeOffset.UtcNow
    };

    private static AppRegistrationEntity CreateApp(string appId) => new()
    {
        Id = Guid.NewGuid(),
        AppId = appId,
        AppSecretHash = "not-a-secret",
        AppName = "Cancellation Test Application",
        IsActive = true,
        CreatedAt = DateTimeOffset.UtcNow
    };

    private static async Task<RefreshTokenEntity> SeedRefreshTokenAsync(
        IdentityDbContext context,
        string tokenValue)
    {
        var account = CreateAccount();
        var token = CreateRefreshToken(account.Id, tokenValue);
        token.TokenValue = RefreshTokenDigest.Compute(token.TokenValue);
        context.Accounts.Add(account);
        context.RefreshTokens.Add(token);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
        return token;
    }

    private static RefreshTokenEntity CreateRefreshToken(Guid accountId, string tokenValue) => new()
    {
        Id = Guid.NewGuid(),
        AccountId = accountId,
        TokenValue = tokenValue,
        AppId = "repository-cancellation-app",
        CreatedAt = DateTimeOffset.UtcNow,
        ExpiresAt = DateTimeOffset.UtcNow.AddDays(1)
    };

    private sealed class TestDatabase : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly DbContextOptions<IdentityDbContext> _options;

        private TestDatabase(
            SqliteConnection connection,
            DbContextOptions<IdentityDbContext> options,
            IdentityDbContext context)
        {
            _connection = connection;
            _options = options;
            Context = context;
        }

        public IdentityDbContext Context { get; }

        public IdentityDbContext CreateContext() => new(_options);

        public static async Task<TestDatabase> CreateAsync(IInterceptor? interceptor = null)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>()
                .UseSqlite(connection);
            if (interceptor != null)
            {
                optionsBuilder.AddInterceptors(interceptor);
            }

            var options = optionsBuilder.Options;
            var context = new IdentityDbContext(options);
            await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
            return new TestDatabase(connection, options, context);
        }

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }

    private sealed class CancelBeforeCommitInterceptor : DbTransactionInterceptor
    {
        private readonly CancellationTokenSource _cancellationSource;
        private bool _armed;

        public CancelBeforeCommitInterceptor(CancellationTokenSource cancellationSource)
        {
            _cancellationSource = cancellationSource;
        }

        public int CanceledCommits { get; private set; }

        public void Arm()
        {
            _armed = true;
        }

        public override ValueTask<InterceptionResult> TransactionCommittingAsync(
            DbTransaction transaction,
            TransactionEventData eventData,
            InterceptionResult result,
            CancellationToken cancellationToken = default)
        {
            if (_armed)
            {
                _armed = false;
                CanceledCommits++;
                _cancellationSource.Cancel();
            }

            return base.TransactionCommittingAsync(
                transaction,
                eventData,
                result,
                cancellationToken);
        }
    }
}
