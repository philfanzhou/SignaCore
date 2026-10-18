using Microsoft.AspNetCore.Builder;
using ServiceMantle.Web;
using SignaCore.Host;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using ServiceMantle.Audit;
using ServiceMantle.Management;
using ServiceMantle.Persistence.Relational.Stores;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Host.Controllers;
using SignaCore.Host.Management;
using SignaCore.Host.Models;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

public sealed class AdminPasswordResetDatabaseContractTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private const string OldPassword = "Reset-Old-123";
    private const string NewPassword = " weak ";
    private static readonly BCryptPasswordHasher Hasher = new(new PasswordHasherOptions { WorkFactor = 4 });

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Reset_OnlyChangesTheHash_AndCommitsWithOneBoundedAudit(string provider)
    {
        await using var database = await Database.CreateAsync(provider);
        foreach (var active in new[] { true, false })
        {
            var seed = await SeedAsync(database.Options, active);
            await using (var context = new IdentityDbContext(database.Options))
            {
                Assert.IsType<OkObjectResult>(await ResetAsync(context, seed.Id));
            }
            await using var verify = new IdentityDbContext(database.Options);
            var credential = await verify.PasswordCredentials.AsNoTracking().SingleAsync(c => c.AccountId == seed.Id, Ct);
            Assert.True(Hasher.VerifyPassword(NewPassword, credential.PasswordHash));
            Assert.False(Hasher.VerifyPassword(OldPassword, credential.PasswordHash));
            Assert.False(Hasher.VerifyPassword(NewPassword.Trim(), credential.PasswordHash));
            Assert.Equal(seed.CredentialId, credential.Id);
            Assert.Equal(seed.Username, credential.Username);
            Assert.Equal(seed.CreatedAt, credential.CreatedAt);
            var account = await verify.Accounts.AsNoTracking().SingleAsync(a => a.Id == seed.Id, Ct);
            Assert.Equal(active, account.IsActive);
            Assert.Equal("retained nickname", account.Nickname);
            Assert.Equal("retained remark", account.Remark);
            var attempt = await verify.LoginAttempts.AsNoTracking().SingleAsync(a => a.Username == seed.Username, Ct);
            Assert.Equal(4, attempt.FailedAttempts);
            Assert.Equal(seed.LockoutUntil, attempt.LockoutUntil);
            var session = await verify.IdentitySessions.AsNoTracking().SingleAsync(s => s.AccountId == seed.Id, Ct);
            Assert.Null(session.RevokedAt);
            var token = await verify.RefreshTokens.AsNoTracking().SingleAsync(t => t.AccountId == seed.Id, Ct);
            Assert.False(token.IsRevoked);
            var audits = (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(verify, Ct))
                .Where(a => a.TargetId == seed.Id.ToString()).ToList();
            var audit = Assert.Single(audits);
            Assert.Equal("admin_password_reset", audit.Action);
            Assert.Equal("account", audit.TargetType);
            Assert.Equal(OperatorId.ToString(), audit.OperatorId);
            var auditText = System.Text.Json.JsonSerializer.Serialize(audit);
            Assert.DoesNotContain(NewPassword, auditText, StringComparison.Ordinal);
            Assert.DoesNotContain(OldPassword, auditText, StringComparison.Ordinal);
            Assert.DoesNotContain(credential.PasswordHash, auditText, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task AuditSaveAndCancellationFailures_RollBackTheHashAndAudit(string provider)
    {
        await using var database = await Database.CreateAsync(provider);
        foreach (var failure in new[] { "audit", "save", "cancel", "zero", "two" })
        {
            var seed = await SeedAsync(database.Options);
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            await using (var context = new IdentityDbContext(database.Options))
            {
                IManagementAuditWriter writer = new EfCoreManagementAuditWriter<IdentityDbContext>(context);
                if (failure is "audit" or "cancel") writer = new FailingAuditWriter(writer, failure, cancellation);
                IUnitOfWork unitOfWork = new EfCoreUnitOfWork(context);
                if (failure == "save")
                {
                    var mock = new Mock<IUnitOfWork>();
                    mock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()))
                        .ThrowsAsync(new InvalidOperationException("Injected save failure."));
                    unitOfWork = mock.Object;
                }
                IPasswordCredentialRepository repository = new PasswordCredentialRepository(context);
                if (failure is "zero" or "two")
                {
                    var real = repository;
                    var mock = new Mock<IPasswordCredentialRepository>();
                    mock.Setup(r => r.GetUpToTwoByAccountIdAsync(seed.Id, It.IsAny<CancellationToken>()))
                        .Returns((Guid id, CancellationToken token) => real.GetUpToTwoByAccountIdAsync(id, token));
                    mock.Setup(r => r.UpdatePasswordHashAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                        .ReturnsAsync(failure == "zero" ? 0 : 2);
                    repository = mock.Object;
                }
                var exception = await Record.ExceptionAsync(() => ResetAsync(context, seed.Id, writer, unitOfWork,
                    repository, cancellation.Token));
                Assert.NotNull(exception);
                if (failure == "cancel") Assert.IsAssignableFrom<OperationCanceledException>(exception);
                else if (failure is "zero" or "two") Assert.IsType<DbUpdateConcurrencyException>(exception);
                else Assert.Equal($"Injected {failure} failure.", Assert.IsType<InvalidOperationException>(exception).Message);
            }
            await using var verify = new IdentityDbContext(database.Options);
            var hash = await verify.PasswordCredentials.AsNoTracking().Where(c => c.AccountId == seed.Id)
                .Select(c => c.PasswordHash).SingleAsync(Ct);
            Assert.True(Hasher.VerifyPassword(OldPassword, hash));
            Assert.Empty((await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(verify, Ct)).Where(a => a.TargetId == seed.Id.ToString()));
        }
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task TwoOverlappingResets_EachAuditCommits_AndLastWriterWins(string provider)
    {
        await using var database = await Database.CreateAsync(provider);
        var seed = await SeedAsync(database.Options);
        var written = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var first = new IdentityDbContext(database.Options);
        await using var second = new IdentityDbContext(database.Options);
        var firstTask = ResetAsync(first, seed.Id, new PausingAuditWriter(
            new EfCoreManagementAuditWriter<IdentityDbContext>(first), written, release));
        await written.Task.WaitAsync(TimeSpan.FromSeconds(20), Ct);
        var secondStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondTask = Task.Run(() =>
        {
            secondStarted.TrySetResult();
            return ResetAsync(second, seed.Id, password: "Last-Reset-789");
        }, Ct);
        await secondStarted.Task.WaitAsync(TimeSpan.FromSeconds(20), Ct);
        release.TrySetResult();
        Assert.IsType<OkObjectResult>(await firstTask);
        Assert.IsType<OkObjectResult>(await secondTask);
        await using var verify = new IdentityDbContext(database.Options);
        var hash = await verify.PasswordCredentials.AsNoTracking().Where(c => c.AccountId == seed.Id)
            .Select(c => c.PasswordHash).SingleAsync(Ct);
        Assert.True(Hasher.VerifyPassword("Last-Reset-789", hash));
        Assert.False(Hasher.VerifyPassword(NewPassword, hash));
        Assert.Equal(2, (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(verify, Ct))
            .Count(a => a.TargetId == seed.Id.ToString() && a.Action == "admin_password_reset"));
    }

    private static readonly RequestDelegate CorrelationPipeline = BuildCorrelationPipeline();
    private static RequestDelegate BuildCorrelationPipeline()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSignaCoreServiceMantle();
        var app = new ApplicationBuilder(services.BuildServiceProvider());
        app.UseServiceMantleCorrelationId();
        return app.Build();
    }

    private static readonly Guid OperatorId = Guid.NewGuid();
    private static Task<IActionResult> ResetAsync(IdentityDbContext context, Guid id,
        IManagementAuditWriter? writer = null, IUnitOfWork? unitOfWork = null,
        IPasswordCredentialRepository? repository = null, CancellationToken? token = null,
        string password = NewPassword, IAccountRepository? accounts = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton<ManagementOperatorReader>();
        services.AddSingleton<IManagementClaimsParser, ManagementClaimsParser>();
        services.AddSingleton<IManagementCurrentOperatorResolver, ManagementCurrentOperatorResolver>();
        var controller = new AdminController(NullLogger<AdminController>.Instance, services.BuildServiceProvider())
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext
            {
                User = ManagementIdentity.Create(WellKnownManagementAuditOperatorSources.InteractiveAdmin,
                    OperatorId.ToString(), [ManagementPermission.Admin], "reset operator").ToClaimsPrincipal()
            } }
        };
        CorrelationPipeline(controller.HttpContext).GetAwaiter().GetResult();
        return controller.ResetUserPassword(id, new AdminResetPasswordRequest(password),
            Hasher, accounts ?? new AccountRepository(context), repository ?? new PasswordCredentialRepository(context),
            unitOfWork ?? new EfCoreUnitOfWork(context), writer ?? new EfCoreManagementAuditWriter<IdentityDbContext>(context),
            context, token ?? Ct);
    }

    private sealed class FailingAuditWriter(IManagementAuditWriter inner, string failure,
        CancellationTokenSource cancellation) : IManagementAuditWriter
    {
        public async ValueTask<ManagementAuditRecord> RecordAsync(ManagementAuditEvent auditEvent, CancellationToken cancellationToken = default)
        {
            Assert.Equal(cancellation.Token, cancellationToken);
            var record = await inner.RecordAsync(auditEvent, cancellationToken);
            if (failure == "cancel") { cancellation.Cancel(); cancellationToken.ThrowIfCancellationRequested(); }
            throw new InvalidOperationException("Injected audit failure.");
        }
    }

    private sealed class PausingAuditWriter(IManagementAuditWriter inner, TaskCompletionSource written,
        TaskCompletionSource release) : IManagementAuditWriter
    {
        public async ValueTask<ManagementAuditRecord> RecordAsync(ManagementAuditEvent auditEvent, CancellationToken cancellationToken = default)
        {
            written.TrySetResult();
            await release.Task.WaitAsync(cancellationToken);
            return await inner.RecordAsync(auditEvent, cancellationToken);
        }
    }

    private sealed record Seed(Guid Id, Guid CredentialId, string Username, DateTimeOffset CreatedAt, DateTimeOffset LockoutUntil);
    private static async Task<Seed> SeedAsync(DbContextOptions<IdentityDbContext> options, bool active = true)
    {
        await using var context = new IdentityDbContext(options);
        var id = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var username = $"reset-{id:N}";
        // Round to microseconds, the PostgreSQL timestamp resolution.
        var now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        context.Accounts.Add(new AccountEntity { Id = id, IsActive = active, CreatedAt = now,
            Nickname = "retained nickname", Remark = "retained remark" });
        context.PasswordCredentials.Add(new PasswordCredentialEntity { Id = credentialId, AccountId = id,
            Username = username, PasswordHash = Hasher.HashPassword(OldPassword), CreatedAt = now });
        context.LoginAttempts.Add(new LoginAttemptEntity { Id = Guid.NewGuid(), Username = username,
            FailedAttempts = 4, LockoutUntil = now.AddHours(1), LastAttemptAt = now });
        await context.SaveChangesAsync(Ct);
        var session = await new IdentitySessionStore(new IdentitySessionRepository(context), new EfCoreUnitOfWork(context))
            .CreateAsync(id, credentialId, now, Ct);
        var rootId = Guid.NewGuid();
        context.RefreshTokens.Add(new RefreshTokenEntity { Id = rootId, FamilyId = rootId, AccountId = id,
            IdentitySessionId = session.Id, Scope = "openid profile", AuthTime = now, TokenValue = $"synthetic-{rootId:N}", AppId = "reset-test-app",
            CreatedAt = now, ExpiresAt = now.AddHours(2) });
        await context.SaveChangesAsync(Ct);
        return new Seed(id, credentialId, username, now, now.AddHours(1));
    }

    private sealed class Database : IAsyncDisposable
    {
        private readonly string path = Path.Combine(PhysicalTempPath.Root(), $"reset-{Guid.NewGuid():N}.db");
        private PostgreSqlContainer? container;
        public DbContextOptions<IdentityDbContext> Options { get; private set; } = null!;
        public static async Task<Database> CreateAsync(string provider)
        {
            var database = new Database();
            var builder = new DbContextOptionsBuilder<IdentityDbContext>();
            if (provider == "PostgreSQL")
            {
                Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true",
                    "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true for PostgreSQL contracts.");
                database.container = new PostgreSqlBuilder(Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") ?? "postgres:15-alpine")
                    .WithDatabase("identity").WithUsername("postgres").WithPassword("postgres").Build();
                await database.container.StartAsync(Ct);
                builder.UseIdentityDatabase(new DatabaseOptions { Provider = provider, ServerVersion = "15",
                    ConnectionString = database.container.GetConnectionString() });
            }
            else builder.UseSqlite($"Data Source={database.path};Pooling=False;Default Timeout=30",
                p => p.MigrationsAssembly("SignaCore.Database.Migrations.Sqlite"));
            database.Options = builder.Options;
            await using var context = new IdentityDbContext(database.Options);
            await context.Database.MigrateAsync(Ct);
            return database;
        }
        public async ValueTask DisposeAsync()
        {
            if (container != null) await container.DisposeAsync();
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
