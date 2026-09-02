using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Host.Http;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Host.Security;

public class AuthenticationHandlerCancellationTests
{
    [Fact]
    public async Task GatewayAuthentication_PassesRequestAbortedToValidation()
    {
        using var cancellation = new CancellationTokenSource();
        var context = new DefaultHttpContext
        {
            RequestAborted = cancellation.Token
        };
        context.Request.Headers[IdentityHeaders.AppId] = "testapp";
        context.Request.Headers[IdentityHeaders.AppSecret] = "testsecret";
        var (service, repository) = CreateValidationService();
        var handler = new GatewayAppAuthenticationHandler(
            CreateOptionsMonitor(),
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            service);
        await InitializeAsync(handler, context, GatewayAppAuthenticationDefaults.Scheme);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        repository.Verify(
            item => item.GetByAppIdAsync("testapp", cancellation.Token),
            Times.Once);
    }

    [Fact]
    public async Task OAuthBasicAuthentication_PassesRequestAbortedToValidation()
    {
        using var cancellation = new CancellationTokenSource();
        var context = new DefaultHttpContext
        {
            RequestAborted = cancellation.Token
        };
        var encodedCredentials = Convert.ToBase64String(
            Encoding.UTF8.GetBytes("testapp:testsecret"));
        context.Request.Headers.Authorization = $"Basic {encodedCredentials}";
        var (service, repository) = CreateValidationService();
        var handler = new OAuthClientAuthenticationHandler(
            CreateOptionsMonitor(),
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            service);
        await InitializeAsync(handler, context, OAuthClientAuthenticationDefaults.Scheme);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        repository.Verify(
            item => item.GetByAppIdAsync("testapp", cancellation.Token),
            Times.Once);
    }

    [Fact]
    public async Task OAuthFormAuthentication_ObservesRequestAbortedWhileReadingForm()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var body = Encoding.UTF8.GetBytes("client_id=testapp&client_secret=testsecret");
        var context = new DefaultHttpContext
        {
            RequestAborted = cancellation.Token
        };
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.ContentLength = body.Length;
        context.Request.Body = new MemoryStream(body);
        var (service, repository) = CreateValidationService();
        var handler = new OAuthClientAuthenticationHandler(
            CreateOptionsMonitor(),
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            service);
        await InitializeAsync(handler, context, OAuthClientAuthenticationDefaults.Scheme);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => handler.AuthenticateAsync());
        repository.Verify(
            item => item.GetByAppIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    private static async Task InitializeAsync(
        IAuthenticationHandler handler,
        HttpContext context,
        string schemeName)
    {
        await handler.InitializeAsync(
            new AuthenticationScheme(schemeName, schemeName, handler.GetType()),
            context);
    }

    private static IOptionsMonitor<AuthenticationSchemeOptions> CreateOptionsMonitor()
    {
        var options = new Mock<IOptionsMonitor<AuthenticationSchemeOptions>>();
        options
            .Setup(item => item.Get(It.IsAny<string?>()))
            .Returns(new AuthenticationSchemeOptions());
        return options.Object;
    }

    private static (GatewayValidationService Service, Mock<IAppRegistrationRepository> Repository)
        CreateValidationService()
    {
        var app = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "testapp",
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword("testsecret"),
            AppName = "Test App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        var repository = new Mock<IAppRegistrationRepository>();
        repository
            .Setup(item => item.GetByAppIdAsync(
                "testapp",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(app);
        return (
            new GatewayValidationService(
                repository.Object,
                NullLogger<GatewayValidationService>.Instance),
            repository);
    }
}
