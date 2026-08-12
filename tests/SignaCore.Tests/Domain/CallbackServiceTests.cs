using System.Linq;
using System.Net;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Database;
using SignaCore.Domain;
using Xunit;

namespace SignaCore.Tests.Domain;

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
        Assert.Contains(claims, c => c.Type == IdentityConstants.ClaimRole && c.Value == "admin");
        Assert.Contains(claims, c => c.Type == IdentityConstants.ClaimRole && c.Value == "user");
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
            "{\"customClaims\":{\"department\":\"Engineering\",\"school\":\"TestSchool\"}}",
            HttpStatusCode.OK);

        var httpClient = new HttpClient(handler);
        var factory = new TestHttpClientFactory(httpClient);
        var service = new CallbackService(factory, CreateLogger(), _validator);

        var claims = await service.FetchExternalClaimsAsync("https://example.com/callback", "user123");

        Assert.Equal(2, claims.Count);
        Assert.Contains(claims, c => c.Type == "department" && c.Value == "Engineering");
        Assert.Contains(claims, c => c.Type == "school" && c.Value == "TestSchool");
    }

    [Fact]
    public async Task FetchExternalClaimsAsync_WithDisallowedCustomClaimType_FiltersOut()
    {
        var handler = new MockHttpMessageHandler(
            "{\"customClaims\":{\"department\":\"Engineering\",\"forbidden_field\":\"value\"}}",
            HttpStatusCode.OK);

        var httpClient = new HttpClient(handler);
        var factory = new TestHttpClientFactory(httpClient);
        var service = new CallbackService(factory, CreateLogger(), _validator);

        var claims = await service.FetchExternalClaimsAsync("https://example.com/callback", "user123");

        Assert.Single(claims);
        Assert.Contains(claims, c => c.Type == "department" && c.Value == "Engineering");
    }

    [Fact]
    public async Task FetchExternalClaimsAsync_WithTooManyRoles_TruncatesToMax()
    {
        // 生成超过 50 个角色
        var roles = Enumerable.Range(0, 55).Select(i => $"role_{i}").ToList();
        var json = $"{{\"roles\":[{string.Join(",", roles.Select(r => $"\"{r}\""))}]}}";
        var handler = new MockHttpMessageHandler(json, HttpStatusCode.OK);

        var httpClient = new HttpClient(handler);
        var factory = new TestHttpClientFactory(httpClient);
        var service = new CallbackService(factory, CreateLogger(), _validator);

        var claims = await service.FetchExternalClaimsAsync("https://example.com/callback", "user123");

        Assert.Equal(50, claims.Count);
        Assert.All(claims, c => Assert.Equal(IdentityConstants.ClaimRole, c.Type));
    }

    [Fact]
    public async Task FetchExternalClaimsAsync_WithTooManyPermissions_TruncatesToMax()
    {
        var permissions = Enumerable.Range(0, 55).Select(i => $"perm_{i}").ToList();
        var json = $"{{\"permissions\":[{string.Join(",", permissions.Select(p => $"\"{p}\""))}]}}";
        var handler = new MockHttpMessageHandler(json, HttpStatusCode.OK);

        var httpClient = new HttpClient(handler);
        var factory = new TestHttpClientFactory(httpClient);
        var service = new CallbackService(factory, CreateLogger(), _validator);

        var claims = await service.FetchExternalClaimsAsync("https://example.com/callback", "user123");

        Assert.Equal(50, claims.Count);
        Assert.All(claims, c => Assert.Equal(IdentityConstants.ClaimPermission, c.Type));
    }

    [Fact]
    public async Task FetchExternalClaimsAsync_WithOverlongClaimValue_FiltersOut()
    {
        var longValue = new string('a', 257);
        var handler = new MockHttpMessageHandler(
            $"{{\"customClaims\":{{\"department\":\"{longValue}\"}}}}",
            HttpStatusCode.OK);

        var httpClient = new HttpClient(handler);
        var factory = new TestHttpClientFactory(httpClient);
        var service = new CallbackService(factory, CreateLogger(), _validator);

        var claims = await service.FetchExternalClaimsAsync("https://example.com/callback", "user123");

        Assert.Empty(claims);
    }

    [Fact]
    public async Task FetchExternalClaimsAsync_WithBlankRole_FiltersOut()
    {
        var handler = new MockHttpMessageHandler(
            "{\"roles\":[\"admin\",\"\",\"  \",\"user\"]}",
            HttpStatusCode.OK);

        var httpClient = new HttpClient(handler);
        var factory = new TestHttpClientFactory(httpClient);
        var service = new CallbackService(factory, CreateLogger(), _validator);

        var claims = await service.FetchExternalClaimsAsync("https://example.com/callback", "user123");

        Assert.Equal(2, claims.Count);
        Assert.Contains(claims, c => c.Value == "admin");
        Assert.Contains(claims, c => c.Value == "user");
    }

    [Fact]
    public async Task FetchExternalClaimsAsync_WhenCallerCancels_PropagatesCancellation()
    {
        var handler = new MockHttpMessageHandler("{}", HttpStatusCode.OK);
        using var httpClient = new HttpClient(handler);
        var service = new CallbackService(
            new TestHttpClientFactory(httpClient),
            CreateLogger(),
            _validator);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            service.FetchExternalClaimsAsync(
                "https://example.com/callback",
                "user123",
                cancellation.Token));
    }

    [Theory]
    [InlineData(
        "https://callback.example.com/secret/token?access_token=sensitive#fragment",
        "https://callback.example.com")]
    [InlineData("not-a-url", "<invalid>")]
    public void DescribeForLog_DoesNotExposePathQueryOrFragment(
        string callbackUrl,
        string expected)
    {
        Assert.Equal(expected, CallbackService.DescribeForLog(callbackUrl));
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
