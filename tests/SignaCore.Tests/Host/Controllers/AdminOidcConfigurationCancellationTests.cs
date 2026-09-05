using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.FileProviders;
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

namespace SignaCore.Tests.Host.Controllers;

/// <summary>
/// Holds the cancellation contract of the interactive OIDC configuration commit path and the three
/// exchange trust endpoints: every repository and audit boundary of one request observes the exact
/// request token, and the configuration change, its redirect URI registrations and its audit entry
/// share one commit boundary.
/// </summary>
public sealed class AdminOidcConfigurationCancellationTests
{
    private const string AppId = "oidc-cancellation-app";
    private const string SourceAppId = "oidc-cancellation-source-app";
    private const string RedirectUri = "https://client.example.test/signin-oidc";

    public static TheoryData<string> OidcConfigurationEndpoints() =>
        new("oidc-policy", "add-redirect-uri", "remove-redirect-uri");

    /// <summary>
    /// All three entry points commit through <c>ApplyOidcConfigurationAsync</c>, so the redirect URI
    /// staging and the audit write have to observe the request token on every one of them.
    /// </summary>
    [Theory]
    [MemberData(nameof(OidcConfigurationEndpoints))]
    public async Task OidcConfiguration_PassesTheRequestTokenToTheUriChangesAndTheAudit(string endpoint)
    {
        using var cancellation = new CancellationTokenSource();
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        var app = await SeedAppWithRedirectUriAsync(database.Context);
        var registrationId = app.RedirectUris.Single().Id;
        var repository = new TokenAssertingAppRegistrationRepository(
            new AppRegistrationRepository(database.Context), cancellation.Token);
        var audit = CreateAuditMock(cancellation.Token);
        var unitOfWork = new EfCoreUnitOfWork(database.Context);
        var controller = CreateController();

        var result = endpoint switch
        {
            "oidc-policy" => await controller.UpdateOidcPolicy(
                AppId,
                new AdminUpdateOidcPolicyRequest("Confidential", false, ["openid"], false, null),
                repository,
                unitOfWork,
                audit.Object,
                ProductionEnvironment(),
                cancellation.Token),
            "add-redirect-uri" => await controller.AddOidcRedirectUris(
                AppId,
                new AdminAddRedirectUrisRequest("Redirect", ["https://client.example.test/second"]),
                repository,
                unitOfWork,
                audit.Object,
                ProductionEnvironment(),
                cancellation.Token),
            _ => await controller.RemoveOidcRedirectUri(
                AppId,
                registrationId,
                repository,
                unitOfWork,
                audit.Object,
                ProductionEnvironment(),
                cancellation.Token)
        };

        Assert.IsType<OkObjectResult>(result);
        audit.VerifyAll();
        Assert.Equal(1, repository.AddRedirectUriCalls);
        Assert.Equal(1, repository.RemoveRedirectUriCalls);
    }

    [Fact]
    public async Task GetExchangeTrusts_PassesTheRequestTokenToTheAppReadAndTheListing()
    {
        using var cancellation = new CancellationTokenSource();
        var app = CreateApp(AppId);
        var appRegistrations = new Mock<IAppRegistrationRepository>(MockBehavior.Strict);
        appRegistrations.Setup(repository => repository.GetByAppIdAsync(AppId, cancellation.Token))
            .ReturnsAsync(app);
        var trusts = new Mock<IAppExchangeTrustRepository>(MockBehavior.Strict);
        trusts.Setup(repository => repository.ListSourcesAsync(app.Id, cancellation.Token))
            .ReturnsAsync([]);

        var result = await CreateController().GetExchangeTrusts(
            AppId, appRegistrations.Object, trusts.Object, cancellation.Token);

        Assert.Empty(Assert.IsAssignableFrom<IReadOnlyList<AdminExchangeTrustResponse>>(
            Assert.IsType<OkObjectResult>(result).Value));
        appRegistrations.VerifyAll();
        trusts.VerifyAll();
    }

    [Fact]
    public async Task AddExchangeTrust_PassesTheRequestTokenToBothAppReadsAndTheAudit()
    {
        using var cancellation = new CancellationTokenSource();
        var app = CreateApp(AppId);
        var sourceApp = CreateApp(SourceAppId);
        var appRegistrations = new Mock<IAppRegistrationRepository>(MockBehavior.Strict);
        appRegistrations.Setup(repository => repository.GetByAppIdAsync(AppId, cancellation.Token))
            .ReturnsAsync(app);
        appRegistrations.Setup(repository => repository.GetByAppIdAsync(SourceAppId, cancellation.Token))
            .ReturnsAsync(sourceApp);
        var edge = new AppExchangeTrust(
            sourceApp.Id, sourceApp.AppId, sourceApp.AppName, SourceIsActive: true, ApprovedBy: null,
            DateTimeOffset.UtcNow);
        var trusts = new Mock<IAppExchangeTrustRepository>(MockBehavior.Strict);
        trusts.Setup(repository => repository.AddAsync(
                app, sourceApp, It.IsAny<Guid?>(), cancellation.Token))
            .ReturnsAsync(edge);
        var audit = CreateAuditMock(cancellation.Token, "app_exchange_trust_added");
        var unitOfWork = new Mock<IUnitOfWork>(MockBehavior.Strict);
        unitOfWork.Setup(unit => unit.SaveChangesAsync(cancellation.Token)).ReturnsAsync(1);

        var result = await CreateController().AddExchangeTrust(
            AppId,
            new AdminAddExchangeTrustRequest(SourceAppId),
            appRegistrations.Object,
            trusts.Object,
            audit.Object,
            unitOfWork.Object,
            cancellation.Token);

        var response = Assert.IsType<AdminExchangeTrustResponse>(Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal(SourceAppId, response.SourceAppId);
        appRegistrations.VerifyAll();
        trusts.VerifyAll();
        audit.VerifyAll();
        unitOfWork.VerifyAll();
    }

    [Fact]
    public async Task RemoveExchangeTrust_PassesTheRequestTokenToBothAppReadsAndTheAudit()
    {
        using var cancellation = new CancellationTokenSource();
        await using var database = await MigratedSqliteTestDatabase.CreateAsync();
        var app = CreateApp(AppId);
        var sourceApp = CreateApp(SourceAppId);
        var appRegistrations = new Mock<IAppRegistrationRepository>(MockBehavior.Strict);
        appRegistrations.Setup(repository => repository.GetByAppIdAsync(AppId, cancellation.Token))
            .ReturnsAsync(app);
        appRegistrations.Setup(repository => repository.GetByAppIdAsync(SourceAppId, cancellation.Token))
            .ReturnsAsync(sourceApp);
        var trusts = new Mock<IAppExchangeTrustRepository>(MockBehavior.Strict);
        trusts.Setup(repository => repository.RemoveAsync(app.Id, sourceApp.Id, cancellation.Token))
            .ReturnsAsync(true);
        var audit = CreateAuditMock(cancellation.Token, "app_exchange_trust_removed");
        var unitOfWork = new Mock<IUnitOfWork>(MockBehavior.Strict);
        unitOfWork.Setup(unit => unit.SaveChangesAsync(cancellation.Token)).ReturnsAsync(1);

        var result = await CreateController().RemoveExchangeTrust(
            AppId,
            SourceAppId,
            appRegistrations.Object,
            trusts.Object,
            audit.Object,
            unitOfWork.Object,
            database.Context,
            cancellation.Token);

        Assert.IsType<OkObjectResult>(result);
        appRegistrations.VerifyAll();
        trusts.VerifyAll();
        audit.VerifyAll();
        unitOfWork.VerifyAll();
    }

    public static TheoryData<string, string> CommitBoundaryCases()
    {
        var cases = new TheoryData<string, string>();
        foreach (var endpoint in new[] { "add-redirect-uri", "add-trust", "remove-trust" })
        {
            cases.Add(endpoint, "before-commit");
            cases.Add(endpoint, "after-commit");
        }

        return cases;
    }

    /// <summary>
    /// The configuration change or trust edge and its audit entry are one <c>SaveChanges</c> unit:
    /// cancellation observed before that commit persists neither, while cancellation observed
    /// afterwards leaves both authoritative.
    /// </summary>
    [Theory]
    [MemberData(nameof(CommitBoundaryCases))]
    public async Task ConfigurationAndTrustChanges_CancellationPreservesTheCommitBoundary(
        string endpoint, string boundary)
    {
        using var cancellation = new CancellationTokenSource();
        var interceptor = boundary == "after-commit" ? new CancelAfterSaveInterceptor(cancellation) : null;
        await using var database = await MigratedSqliteTestDatabase.CreateAsync(interceptor);
        var app = await SeedAppWithRedirectUriAsync(database.Context);
        var sourceApp = CreateApp(SourceAppId);
        database.Context.AppRegistrations.Add(sourceApp);
        await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        var trustRepository = new AppExchangeTrustRepository(database.Context);
        if (endpoint == "remove-trust")
        {
            await trustRepository.AddAsync(app, sourceApp, null, TestContext.Current.CancellationToken);
            await database.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        database.Context.ChangeTracker.Clear();
        IAuditService auditService = boundary == "before-commit"
            ? new CancelingActionAuditService(CreateAuditService(database.Context), cancellation)
            : CreateAuditService(database.Context);
        var appRegistrations = new AppRegistrationRepository(database.Context);
        var unitOfWork = new EfCoreUnitOfWork(database.Context);
        if (interceptor != null) interceptor.Armed = true;
        var controller = CreateController();
        IActionResult? response = null;

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            response = endpoint switch
            {
                "add-redirect-uri" => await controller.AddOidcRedirectUris(
                    AppId,
                    new AdminAddRedirectUrisRequest("Redirect", ["https://client.example.test/second"]),
                    appRegistrations,
                    unitOfWork,
                    auditService,
                    ProductionEnvironment(),
                    cancellation.Token),
                "add-trust" => await controller.AddExchangeTrust(
                    AppId,
                    new AdminAddExchangeTrustRequest(SourceAppId),
                    appRegistrations,
                    trustRepository,
                    auditService,
                    unitOfWork,
                    cancellation.Token),
                _ => await controller.RemoveExchangeTrust(
                    AppId,
                    SourceAppId,
                    appRegistrations,
                    trustRepository,
                    auditService,
                    unitOfWork,
                    database.Context,
                    cancellation.Token)
            });

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Null(response);
        var committed = boundary == "after-commit";
        database.Context.ChangeTracker.Clear();
        var uriCount = await database.Context.AppRedirectUris
            .AsNoTracking()
            .CountAsync(TestContext.Current.CancellationToken);
        var trustCount = await database.Context.AppExchangeTrusts
            .AsNoTracking()
            .CountAsync(TestContext.Current.CancellationToken);
        switch (endpoint)
        {
            case "add-redirect-uri":
                Assert.Equal(committed ? 2 : 1, uriCount);
                break;
            case "add-trust":
                Assert.Equal(committed ? 1 : 0, trustCount);
                break;
            default:
                Assert.Equal(committed ? 0 : 1, trustCount);
                break;
        }

        var audits = await database.Context.AuditLogs
            .AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken);
        if (committed) Assert.Single(audits);
        else Assert.Empty(audits);
    }

    private static Mock<IAuditService> CreateAuditMock(CancellationToken expectedToken)
    {
        var audit = new Mock<IAuditService>(MockBehavior.Strict);
        audit.Setup(service => service.RecordActionAsync(
                It.IsAny<string>(), "AppRegistration", AppId, It.IsAny<Guid?>(), It.IsAny<string?>(),
                It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<object?>(),
                It.IsAny<object?>(), expectedToken))
            .Returns(Task.CompletedTask);
        return audit;
    }

    private static Mock<IAuditService> CreateAuditMock(CancellationToken expectedToken, string action)
    {
        var audit = new Mock<IAuditService>(MockBehavior.Strict);
        audit.Setup(service => service.RecordActionAsync(
                action, "AppRegistration", AppId, It.IsAny<Guid?>(), It.IsAny<string?>(),
                It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<object?>(),
                It.IsAny<object?>(), expectedToken))
            .Returns(Task.CompletedTask);
        return audit;
    }

    private static AdminController CreateController()
    {
        var controller = new AdminController(NullLogger<AdminController>.Instance);
        var httpContext = new DefaultHttpContext
        {
            Connection = { RemoteIpAddress = IPAddress.Parse("192.0.2.40") },
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Name, "admin")
            ], "Test"))
        };
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };
        return controller;
    }

    private static AuditService CreateAuditService(IdentityDbContext context) =>
        new(new LoginHistoryRepository(context), new AuditLogRepository(context));

    private static IWebHostEnvironment ProductionEnvironment()
    {
        var environment = new Mock<IWebHostEnvironment>();
        environment.SetupGet(item => item.EnvironmentName).Returns("Production");
        environment.SetupGet(item => item.ApplicationName).Returns("SignaCore.Host");
        environment.SetupGet(item => item.ContentRootPath).Returns(AppContext.BaseDirectory);
        environment.SetupGet(item => item.ContentRootFileProvider).Returns(new NullFileProvider());
        environment.SetupGet(item => item.WebRootPath).Returns(AppContext.BaseDirectory);
        environment.SetupGet(item => item.WebRootFileProvider).Returns(new NullFileProvider());
        return environment.Object;
    }

    private static AppRegistrationEntity CreateApp(string appId) => new()
    {
        Id = Guid.NewGuid(),
        AppId = appId,
        AppIdNormalized = IdentityValueNormalizer.Normalize(appId),
        AppName = appId,
        AppSecretHash = "unused-test-hash",
        IsActive = true,
        CreatedAt = DateTimeOffset.UtcNow
    };

    private static async Task<AppRegistrationEntity> SeedAppWithRedirectUriAsync(IdentityDbContext context)
    {
        var app = CreateApp(AppId);
        app.RedirectUris.Add(new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = app.Id,
            Kind = RedirectUriKind.Redirect,
            CanonicalUri = RedirectUri
        });
        context.AppRegistrations.Add(app);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
        return app;
    }

    /// <summary>
    /// Fails the test when a redirect URI change observes anything other than the request token,
    /// while still staging it against the real repository.
    /// </summary>
    private sealed class TokenAssertingAppRegistrationRepository(
        IAppRegistrationRepository inner, CancellationToken expectedToken) : IAppRegistrationRepository
    {
        public int AddRedirectUriCalls { get; private set; }

        public int RemoveRedirectUriCalls { get; private set; }

        public Task<AppRegistrationEntity?> GetByAppIdAsync(
            string appId, CancellationToken cancellationToken = default)
        {
            Assert.Equal(expectedToken, cancellationToken);
            return inner.GetByAppIdAsync(appId, cancellationToken);
        }

        public Task<AppRegistrationEntity?> GetByAppIdWithOidcConfigurationAsync(
            string appId, CancellationToken cancellationToken)
        {
            Assert.Equal(expectedToken, cancellationToken);
            return inner.GetByAppIdWithOidcConfigurationAsync(appId, cancellationToken);
        }

        public Task AddAsync(AppRegistrationEntity app, CancellationToken cancellationToken = default)
        {
            Assert.Equal(expectedToken, cancellationToken);
            return inner.AddAsync(app, cancellationToken);
        }

        public Task AddRedirectUrisAsync(
            IEnumerable<AppRedirectUriEntity> registrations, CancellationToken cancellationToken = default)
        {
            Assert.Equal(expectedToken, cancellationToken);
            AddRedirectUriCalls++;
            return inner.AddRedirectUrisAsync(registrations, cancellationToken);
        }

        public Task RemoveRedirectUrisAsync(
            IEnumerable<AppRedirectUriEntity> registrations, CancellationToken cancellationToken = default)
        {
            Assert.Equal(expectedToken, cancellationToken);
            RemoveRedirectUriCalls++;
            return inner.RemoveRedirectUrisAsync(registrations, cancellationToken);
        }

        public Task DeleteAsync(AppRegistrationEntity app, CancellationToken cancellationToken = default)
        {
            Assert.Equal(expectedToken, cancellationToken);
            return inner.DeleteAsync(app, cancellationToken);
        }

        public Task<int> DeactivateExpiredCallbacksAsync(
            DateTimeOffset utcNow, CancellationToken cancellationToken = default)
        {
            Assert.Equal(expectedToken, cancellationToken);
            return inner.DeactivateExpiredCallbacksAsync(utcNow, cancellationToken);
        }
    }

    /// <summary>Observes cancellation only once the change is already committed.</summary>
    private sealed class CancelAfterSaveInterceptor(CancellationTokenSource cancellation) : SaveChangesInterceptor
    {
        public bool Armed { get; set; }

        public override ValueTask<int> SavedChangesAsync(
            SaveChangesCompletedEventData eventData,
            int result,
            CancellationToken cancellationToken = default)
        {
            if (!Armed) return ValueTask.FromResult(result);
            Assert.Equal(cancellation.Token, cancellationToken);
            cancellation.Cancel();
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(result);
        }
    }

    /// <summary>
    /// Cancels while the audit entry is being staged, which is the last boundary before the single
    /// commit that carries the change and its audit entry.
    /// </summary>
    private sealed class CancelingActionAuditService(IAuditService inner, CancellationTokenSource cancellation)
        : IAuditService
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
            inner.RecordLoginAsync(
                accountId, username, authMethod, eventType, clientIp, userAgent, failureReason, appId,
                correlationId, cancellationToken);

        public Task RecordActionAsync(
            string action,
            string targetType,
            string targetId,
            Guid? actorId,
            string? actorName,
            string? description,
            string? clientIp = null,
            string? correlationId = null,
            object? before = null,
            object? after = null,
            CancellationToken cancellationToken = default)
        {
            Assert.Equal(cancellation.Token, cancellationToken);
            cancellation.Cancel();
            return inner.RecordActionAsync(
                action, targetType, targetId, actorId, actorName, description, clientIp, correlationId,
                before, after, cancellationToken);
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
