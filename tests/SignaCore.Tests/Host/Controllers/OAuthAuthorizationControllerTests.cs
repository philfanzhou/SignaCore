using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Controllers;
using SignaCore.Host.Security;
using SignaCore.Host.Services;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

/// <summary>
/// Log-shape contract of <c>GET /oauth2/authorize</c>. The endpoint is unauthenticated, so the
/// correlation id it logs is attacker controlled at the source. The ServiceMantle correlation
/// middleware only accepts a single header value matching the fixed correlation shape; a value
/// with line endings is discarded whole and replaced by a generated id, so the forged content
/// cannot reach the log at all. The controller still encodes line endings as defense in depth.
/// </summary>
public class OAuthAuthorizationControllerTests
{
    private const string CorrelationIdHeader = "x-correlation-id";

    /// <summary>
    /// A correlation id carrying line endings can no longer pass the middleware's acceptance rule,
    /// so the log line carries the generated replacement; the forged entry must not appear.
    /// </summary>
    [Theory]
    [InlineData("abc\nWARN Forged log line")]
    [InlineData("abc\r\nWARN Forged log line")]
    [InlineData("abc\rWARN Forged log line")]
    public async Task LocalRejection_RejectsAnInjectedCorrelationIdEntirely(string correlationId)
    {
        var logger = new TestLogger<OAuthAuthorizationController>();
        var controller = await CreateController(
            new OidcAuthorizationValidationResult.LocalRejection(
                OidcAuthorizationLocalReasons.ClientUnknown),
            logger,
            correlationId);

        var result = await controller.Authorize(TestContext.Current.CancellationToken);

        // The rejection itself is unchanged: still the local answer, still no Location header.
        var content = Assert.IsType<ContentResult>(result);
        Assert.Equal(StatusCodes.Status400BadRequest, content.StatusCode);
        Assert.False(controller.Response.Headers.ContainsKey("Location"));

        var entry = Assert.Single(logger.LogEntries);
        Assert.DoesNotContain('\n', entry);
        Assert.DoesNotContain('\r', entry);
        Assert.Contains(OidcAuthorizationLocalReasons.ClientUnknown, entry, StringComparison.Ordinal);
        // The injected value is discarded whole: neither its text nor a line-ending-encoded copy
        // survives into the logged correlation id.
        Assert.DoesNotContain("Forged log line", entry, StringComparison.Ordinal);
        Assert.DoesNotContain("abc\\r", entry, StringComparison.Ordinal);
        Assert.DoesNotContain("abc\\n", entry, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LocalRejection_LogsAnOrdinaryCorrelationIdUnchanged()
    {
        var logger = new TestLogger<OAuthAuthorizationController>();
        var controller = await CreateController(
            new OidcAuthorizationValidationResult.LocalRejection(
                OidcAuthorizationLocalReasons.RedirectUriUnmatched),
            logger,
            "0123456789abcdef0123456789abcdef");

        await controller.Authorize(TestContext.Current.CancellationToken);

        var entry = Assert.Single(logger.LogEntries);
        Assert.Contains("0123456789abcdef0123456789abcdef", entry, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuditedOutcome_StagesExactFieldsAndCommitsWithRequestToken(bool accepted)
    {
        var applicationId = Guid.NewGuid();
        var validator = new Mock<IOidcAuthorizationRequestValidator>();
        validator.Setup(service => service.ValidateAsync(
                It.IsAny<OidcAuthorizationParameters>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AuditedOutcome(applicationId, accepted));
        var audit = new Mock<IAuditService>();
        var unitOfWork = new Mock<IUnitOfWork>();
        unitOfWork.Setup(value => value.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);
        var store = new Mock<IAuthorizationRequestStore>();
        store.Setup(value => value.CreateAsync(
                It.IsAny<OidcAuthorizationValidationResult.Accepted>(),
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AuthorizationRequestCreation(
                Guid.NewGuid(), "unit-test-handle-0123456789abcdefg"));
        var controller = new OAuthAuthorizationController(
            validator.Object,
            store.Object,
            CreateCookielessReader(),
            sessionReuse: null!,
            audit.Object,
            unitOfWork.Object,
            AuthTestDoubles.AuthMetrics(),
            new JwtOptions { Issuer = "https://issuer.example" },
            NullLogger<OAuthAuthorizationController>.Instance).WithHttpContext("correlation-148");
        // The accepted branch validates the continuation destination through the real local-URL
        // predicate, so the controller needs a real URL helper exactly like the hosted pipeline.
        UseRealUrlHelper(controller);

        var result = await controller.Authorize(TestContext.Current.CancellationToken);

        if (accepted)
        {
            // The accepted path redirects to the login page with the handle as its only field;
            // the continuation store owns the single save, so the controller's unit of work never
            // commits on this branch. The result is a local redirect: the executor re-asserts
            // locality on top of the controller's own check.
            var redirect = Assert.IsType<LocalRedirectResult>(result);
            Assert.StartsWith("/oauth2/login?login_handle=", redirect.Url, StringComparison.Ordinal);
            Assert.False(redirect.Permanent);
            Assert.False(redirect.PreserveMethod);
        }
        else
        {
            Assert.IsType<RedirectResult>(result);
        }

        audit.Verify(service => service.RecordActionAsync(
            "oidc.authorize.validated",
            "OidcAuthorizationRequest",
            applicationId.ToString("D"),
            null,
            null,
            accepted ? "accepted" : "invalid_request",
            "127.0.0.1",
            "correlation-148",
            null,
            null,
            TestContext.Current.CancellationToken), Times.Once);
        validator.Verify(service => service.ValidateAsync(
            It.IsAny<OidcAuthorizationParameters>(), TestContext.Current.CancellationToken), Times.Once);
        if (accepted)
        {
            store.Verify(value => value.CreateAsync(
                It.IsAny<OidcAuthorizationValidationResult.Accepted>(),
                It.IsAny<DateTimeOffset>(),
                TestContext.Current.CancellationToken), Times.Once);
            unitOfWork.Verify(
                value => value.SaveChangesAsync(It.IsAny<CancellationToken>()),
                Times.Never);
        }
        else
        {
            unitOfWork.Verify(
                value => value.SaveChangesAsync(TestContext.Current.CancellationToken),
                Times.Once);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuditedOutcome_WhenAuditWriteObservesCancellation_DoesNotCommit(bool accepted)
    {
        using var cancellation = new CancellationTokenSource();
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var database = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(connection).Options);
        await database.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        var validator = new Mock<IOidcAuthorizationRequestValidator>();
        validator.Setup(service => service.ValidateAsync(It.IsAny<OidcAuthorizationParameters>(), cancellation.Token))
            .ReturnsAsync(AuditedOutcome(Guid.NewGuid(), accepted));
        var repository = new Mock<IAuditLogRepository>();
        repository.Setup(value => value.AddAsync(It.IsAny<AuditLogEntity>(), It.IsAny<CancellationToken>()))
            .Returns<AuditLogEntity, CancellationToken>(async (entry, ct) =>
            {
                Assert.Equal(cancellation.Token, ct);
                await new AuditLogRepository(database).AddAsync(entry, ct);
                cancellation.Cancel();
                ct.ThrowIfCancellationRequested();
            });
        var audit = new AuditService(new Mock<ILoginHistoryRepository>().Object, repository.Object);
        var unitOfWork = new Mock<IUnitOfWork>(MockBehavior.Strict);
        var store = new Mock<IAuthorizationRequestStore>(MockBehavior.Strict);
        var controller = new OAuthAuthorizationController(
            validator.Object, store.Object, CreateCookielessReader(), sessionReuse: null!, audit,
            unitOfWork.Object, AuthTestDoubles.AuthMetrics(),
            new JwtOptions { Issuer = "https://issuer.example" },
            NullLogger<OAuthAuthorizationController>.Instance).WithHttpContext();
        UseRealUrlHelper(controller);

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => controller.Authorize(cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        repository.Verify(value => value.AddAsync(It.IsAny<AuditLogEntity>(), cancellation.Token), Times.Once);
        unitOfWork.Verify(value => value.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Never);
        Assert.Single(database.ChangeTracker.Entries<AuditLogEntity>(), entry => entry.State == EntityState.Added);
        database.ChangeTracker.Clear();
        Assert.Empty(await database.AuditLogs.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken));
        Assert.False(controller.Response.HasStarted);
        Assert.False(controller.Response.Headers.ContainsKey("Location"));
    }

    /// <summary>
    /// A PathBase that cannot form a local continuation URL — here a scheme-relative mount — is
    /// refused with the fixed local error before anything is written: no Location header, no
    /// continuation, no audit row, and no echo of the original prefix.
    /// </summary>
    [Fact]
    public async Task AcceptedOutcome_UnderANonLocalPathBase_RejectsLocallyBeforeWriting()
    {
        var applicationId = Guid.NewGuid();
        var validator = new Mock<IOidcAuthorizationRequestValidator>();
        validator.Setup(service => service.ValidateAsync(
                It.IsAny<OidcAuthorizationParameters>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(AuditedOutcome(applicationId, accepted: true));
        var audit = new Mock<IAuditService>(MockBehavior.Strict);
        var unitOfWork = new Mock<IUnitOfWork>(MockBehavior.Strict);
        var store = new Mock<IAuthorizationRequestStore>(MockBehavior.Strict);
        var controller = new OAuthAuthorizationController(
            validator.Object,
            store.Object,
            CreateCookielessReader(),
            sessionReuse: null!,
            audit.Object,
            unitOfWork.Object,
            AuthTestDoubles.AuthMetrics(),
            new JwtOptions { Issuer = "https://issuer.example" },
            NullLogger<OAuthAuthorizationController>.Instance).WithHttpContext("correlation-149");
        UseRealUrlHelper(controller);
        controller.Request.PathBase = new PathString("//outside.example.test");

        var content = Assert.IsType<ContentResult>(await controller.Authorize(TestContext.Current.CancellationToken));

        Assert.Equal(StatusCodes.Status400BadRequest, content.StatusCode);
        Assert.False(controller.Response.Headers.ContainsKey("Location"));
        Assert.DoesNotContain("outside.example.test", content.Content, StringComparison.Ordinal);
        store.VerifyNoOtherCalls();
        audit.VerifyNoOtherCalls();
        unitOfWork.VerifyNoOtherCalls();
    }

    /// <summary>
    /// The final continuation redirect is a <c>LocalRedirectResult</c>: even a result whose
    /// destination is later non-local is refused by the executor itself with no response started,
    /// so the controller's own pre-check never remains the only guard.
    /// </summary>
    [Fact]
    public async Task TheFinalContinuationRedirect_RefusesANonLocalDestination()
    {
        var httpContext = new DefaultHttpContext
        {
            // The executor resolves itself from request services, exactly like the hosted
            // pipeline; the MVC core registrations carry it.
            RequestServices = new ServiceCollection().AddMvcCore().Services.BuildServiceProvider()
        };
        var actionContext = new ActionContext(httpContext, new RouteData(), new ActionDescriptor());

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new LocalRedirectResult("//outside.example.test/oauth2/login")
                .ExecuteResultAsync(actionContext));

        Assert.False(httpContext.Response.HasStarted);
        Assert.False(httpContext.Response.Headers.ContainsKey("Location"));
    }

    /// <summary>
    /// The accepted branch decides locality through the real URL helper predicate, so unit tests
    /// wire one exactly like the hosted pipeline would (the manually built
    /// <see cref="ControllerContext"/> starts without route data).
    /// </summary>
    private static void UseRealUrlHelper(OAuthAuthorizationController controller)
    {
        controller.ControllerContext.RouteData ??= new RouteData();
        controller.Url = new UrlHelper(controller.ControllerContext);
    }

    private static OidcAuthorizationValidationResult AuditedOutcome(Guid applicationId, bool accepted) => accepted
        ? new OidcAuthorizationValidationResult.Accepted(
            "client-1", applicationId, "https://client.example/callback", "openid",
            "test-state", "test-nonce", "test-challenge")
        : new OidcAuthorizationValidationResult.RedirectRejection(
            "client-1", applicationId, "https://client.example/callback", "invalid_request",
            "The request is invalid.", null);

    private static async Task<OAuthAuthorizationController> CreateController(
        OidcAuthorizationValidationResult result,
        ILogger<OAuthAuthorizationController> logger,
        string correlationId)
    {
        var validator = new Mock<IOidcAuthorizationRequestValidator>();
        validator
            .Setup(v => v.ValidateAsync(
                It.IsAny<OidcAuthorizationParameters>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(result);

        var controller = new OAuthAuthorizationController(
            validator.Object,
            new Mock<IAuthorizationRequestStore>().Object,
            CreateCookielessReader(),
            sessionReuse: null!,
            new Mock<IAuditService>().Object,
            new Mock<IUnitOfWork>().Object,
            AuthTestDoubles.AuthMetrics(),
            new JwtOptions(),
            logger);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers[CorrelationIdHeader] = correlationId;
        // The correlation slot is established by the real middleware, so the controller's accessor
        // observes exactly what production would: an accepted value verbatim, or the generated
        // replacement for a rejected one.
        await CorrelationTestPipeline.EstablishAsync(httpContext);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };
        return controller;
    }

    private sealed class TestLogger<T> : ILogger<T>
    {
        public List<string> LogEntries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) => LogEntries.Add(formatter(state, exception));
    }

    /// <summary>
    /// The cookie reader double of the controller unit tests: no candidate session id, so the
    /// reuse service is never reached and the continuation path runs exactly as before.
    /// </summary>
    private static IIdentitySessionCookieReader CreateCookielessReader()
    {
        var reader = new Mock<IIdentitySessionCookieReader>();
        reader.Setup(value => value.TryReadSessionIdAsync(It.IsAny<HttpContext>()))
            .ReturnsAsync((Guid?)null);
        return reader.Object;
    }
}
