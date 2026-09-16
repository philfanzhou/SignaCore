using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
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
            audit.Object,
            unitOfWork.Object,
            AuthTestDoubles.AuthMetrics(),
            new JwtOptions { Issuer = "https://issuer.example" },
            NullLogger<OAuthAuthorizationController>.Instance).WithHttpContext("correlation-148");

        var result = await controller.Authorize(TestContext.Current.CancellationToken);

        if (accepted)
        {
            // The accepted path redirects to the login page with the handle as its only field;
            // the continuation store owns the single save, so the controller's unit of work never
            // commits on this branch.
            var redirect = Assert.IsType<RedirectResult>(result);
            Assert.StartsWith("/oauth2/login?login_handle=", redirect.Url, StringComparison.Ordinal);
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
            validator.Object, store.Object, audit, unitOfWork.Object, AuthTestDoubles.AuthMetrics(),
            new JwtOptions { Issuer = "https://issuer.example" },
            NullLogger<OAuthAuthorizationController>.Instance).WithHttpContext();

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
}
