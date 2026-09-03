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
/// Log-shape contract of <c>GET /oauth2/authorize</c>. The endpoint is unauthenticated and the
/// correlation id it logs is a request header that <see cref="CorrelationIdMiddleware"/> passes
/// through verbatim whenever the caller supplies one, so it is fully attacker controlled.
/// </summary>
public class OAuthAuthorizationControllerTests
{
    private const string CorrelationIdHeader = CorrelationIdMiddleware.CorrelationIdHeader;

    /// <summary>
    /// A correlation id carrying line endings must not be able to add physical lines to the
    /// application log, which is how a forged entry would be smuggled in. The value keeps its own
    /// data; only its line endings are encoded, exactly as everywhere else this header is logged.
    /// </summary>
    [Theory]
    [InlineData("abc\nWARN Forged log line")]
    [InlineData("abc\r\nWARN Forged log line")]
    [InlineData("abc\rWARN Forged log line")]
    public async Task LocalRejection_KeepsAnInjectedCorrelationIdOnOnePhysicalLogLine(string correlationId)
    {
        var logger = new TestLogger<OAuthAuthorizationController>();
        var controller = CreateController(
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
        Assert.Contains("abc\\nWARN Forged log line", entry, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LocalRejection_LogsAnOrdinaryCorrelationIdUnchanged()
    {
        var logger = new TestLogger<OAuthAuthorizationController>();
        var controller = CreateController(
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
        var controller = new OAuthAuthorizationController(
            validator.Object,
            audit.Object,
            unitOfWork.Object,
            AuthTestDoubles.AuthMetrics(),
            new JwtOptions { Issuer = "https://issuer.example" },
            NullLogger<OAuthAuthorizationController>.Instance).WithHttpContext();
        controller.HttpContext.Items[CorrelationIdMiddleware.HttpContextItemsKey] = "correlation-148";

        var result = await controller.Authorize(TestContext.Current.CancellationToken);

        if (accepted)
            Assert.Equal(StatusCodes.Status501NotImplemented, Assert.IsType<ContentResult>(result).StatusCode);
        else
            Assert.IsType<RedirectResult>(result);
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
        unitOfWork.Verify(
            value => value.SaveChangesAsync(TestContext.Current.CancellationToken),
            Times.Once);
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
        var controller = new OAuthAuthorizationController(
            validator.Object, audit, unitOfWork.Object, AuthTestDoubles.AuthMetrics(),
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

    private static OAuthAuthorizationController CreateController(
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
            new Mock<IAuditService>().Object,
            new Mock<IUnitOfWork>().Object,
            AuthTestDoubles.AuthMetrics(),
            new JwtOptions(),
            logger);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers[CorrelationIdHeader] = correlationId;
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
