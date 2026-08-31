using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using SignaCore.Database;
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
