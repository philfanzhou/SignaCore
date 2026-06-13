using System.Net;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Domain;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain;

public class CallbackServiceTests
{
    private static ILogger<CallbackService> CreateLogger() => NullLogger<CallbackService>.Instance;
    private static readonly CallbackUrlValidator _validator = new();

    [Fact]
    public async Task FetchExternalClaimsAsync_WithValidResponse_ReturnsClaims()
    {
        var handler = new MockHttpMessageHandler(
            "{\"roles\":[\"admin\",\"user\"],\"permissions\":[\"read\",\"write\"]}",
            HttpStatusCode.OK);

        var httpClient = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(IdentityConstants.CallbackTimeoutSeconds)
        };

        var factory = new TestHttpClientFactory(httpClient);
        var service = new CallbackService(factory, CreateLogger(), _validator);

        var claims = await service.FetchExternalClaimsAsync("https://example.com/callback", "user123");

        Assert.Equal(4, claims.Count);
        Assert.Contains(claims, c => c.Type == ClaimTypes.Role && c.Value == "admin");
        Assert.Contains(claims, c => c.Type == ClaimTypes.Role && c.Value == "user");
        Assert.Contains(claims, c => c.Type == IdentityConstants.ClaimPermission && c.Value == "read");
        Assert.Contains(claims, c => c.Type == IdentityConstants.ClaimPermission && c.Value == "write");
    }

    [Fact]
    public async Task FetchExternalClaimsAsync_WithErrorResponse_ReturnsEmptyList()
    {
        var handler = new MockHttpMessageHandler("{}", HttpStatusCode.InternalServerError);
        var httpClient = new HttpClient(handler);
        var factory = new TestHttpClientFactory(httpClient);
        var service = new CallbackService(factory, CreateLogger(), _validator);

        var claims = await service.FetchExternalClaimsAsync("https://example.com/callback", "user123");

        Assert.Empty(claims);
    }

    [Fact]
    public async Task FetchExternalClaimsAsync_WithInvalidUrl_ReturnsEmptyList()
    {
        var handler = new MockHttpMessageHandler("{}", HttpStatusCode.OK);
        var httpClient = new HttpClient(handler);
        var factory = new TestHttpClientFactory(httpClient);
        var service = new CallbackService(factory, CreateLogger(), _validator);

        var claims = await service.FetchExternalClaimsAsync("invalid-url", "user123");

        Assert.Empty(claims);
    }

    [Fact]
    public async Task FetchExternalClaimsAsync_WithCustomClaims_ReturnsClaims()
    {
        var handler = new MockHttpMessageHandler(
            "{\"customClaims\":{\"tenant_id\":\"123\",\"environment\":\"prod\"}}",
            HttpStatusCode.OK);

        var httpClient = new HttpClient(handler);
        var factory = new TestHttpClientFactory(httpClient);
        var service = new CallbackService(factory, CreateLogger(), _validator);

        var claims = await service.FetchExternalClaimsAsync("https://example.com/callback", "user123");

        Assert.Equal(2, claims.Count);
        Assert.Contains(claims, c => c.Type == "tenant_id" && c.Value == "123");
        Assert.Contains(claims, c => c.Type == "environment" && c.Value == "prod");
    }
}

public class MockHttpMessageHandler : HttpMessageHandler
{
    private readonly string _response;
    private readonly HttpStatusCode _statusCode;

    public MockHttpMessageHandler(string response, HttpStatusCode statusCode)
    {
        _response = response;
        _statusCode = statusCode;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return Task.FromResult(new HttpResponseMessage(_statusCode)
        {
            Content = new StringContent(_response)
        });
    }
}

public class TestHttpClientFactory : IHttpClientFactory
{
    private readonly HttpClient _httpClient;

    public TestHttpClientFactory(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public HttpClient CreateClient(string name) => _httpClient;
}
