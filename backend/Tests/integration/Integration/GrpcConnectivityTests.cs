using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Grpc.Core;
using Grpc.Net.Client;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using QuantumZhou.Identity.Contract.Protos;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using Xunit;

namespace QuantumZhou.Identity.Tests.Integration;

public class GrpcConnectivityTests : IClassFixture<GrpcServerFixture>
{
    private readonly GrpcServerFixture _fixture;

    public GrpcConnectivityTests(GrpcServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task GrpcChannel_CanConnectAndReceiveResponse()
    {
        var channel = _fixture.CreateChannel();
        var client = new AuthGrpcService.AuthGrpcServiceClient(channel);

        var request = new GetTokenRequest
        {
            GrantType = "password",
            AppId = "nonexistent",
            AppSecret = "nonexistent",
            Password = new PasswordCredential { Username = "test", Password = "test" }
        };

        var response = await client.GetTokenAsync(request);

        Assert.NotNull(response);
        Assert.False(response.Success);
    }

    [Fact]
    public async Task HealthCheckEndpoint_ReturnsHealthy()
    {
        using var http = _fixture.CreateHttpClient();
        var response = await http.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        Assert.Equal("Healthy", content);
    }

    [Fact]
    public async Task JwksEndpoint_ReturnsValidJwks()
    {
        using var http = _fixture.CreateHttpClient();
        var response = await http.GetAsync("/.well-known/jwks");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("RSA", content);
        Assert.Contains("keys", content);
    }

    [Fact]
    public async Task GatewayUserQueries_SearchAndBatchReturnSameUsers()
    {
        var appId = $"gateway_app_{Guid.NewGuid():N}";
        var appSecret = "gateway_secret_123";
        var username = $"linked_user_{Guid.NewGuid():N}";
        var phone = $"138{Guid.NewGuid():N}".Substring(0, 11);
        var accountId = Guid.NewGuid();

        await _fixture.SeedGatewayAppAsync(appId, appSecret);
        await _fixture.SeedGatewayUserAsync(accountId, username, phone, "managed");

        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Add("X-Admin-AppId", appId);
        http.DefaultRequestHeaders.Add("X-Admin-AppSecret", appSecret);

        var searchResponse = await http.GetAsync($"/api/gateway/users/search?username={username}&page=1&pageSize=20");
        Assert.Equal(HttpStatusCode.OK, searchResponse.StatusCode);

        var searchPayload = await searchResponse.Content.ReadFromJsonAsync<TestPagedResponse<TestUserItem>>();
        Assert.NotNull(searchPayload);
        var searchedUser = Assert.Single(searchPayload!.Items);
        Assert.Equal(accountId.ToString(), searchedUser.UserId);
        Assert.Equal(username, searchedUser.Username);
        Assert.Equal(phone, searchedUser.Phone);
        Assert.Equal(username, searchedUser.DisplayName);

        var batchResponse = await http.PostAsJsonAsync("/api/gateway/users/batch", new[] { accountId.ToString() });
        Assert.Equal(HttpStatusCode.OK, batchResponse.StatusCode);

        var batchPayload = await batchResponse.Content.ReadFromJsonAsync<List<TestUserItem>>();
        Assert.NotNull(batchPayload);
        var batchUser = Assert.Single(batchPayload!);
        Assert.Equal(searchedUser.UserId, batchUser.UserId);
        Assert.Equal(searchedUser.Username, batchUser.Username);
        Assert.Equal(searchedUser.Phone, batchUser.Phone);
        Assert.Equal(searchedUser.DisplayName, batchUser.DisplayName);
    }

}

public class GrpcServerFixture : IAsyncLifetime
{
    private WebApplicationFactory<Program>? _factory;
    private string? _previousMasterKey;

    public async Task InitializeAsync()
    {
        AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);

        _previousMasterKey = Environment.GetEnvironmentVariable("RSA_MASTER_KEY");
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", "test-master-key-for-e2e-testing-only");

        var dbPath = Path.Combine(Path.GetTempPath(), $"identity_test_{Guid.NewGuid():N}.db");

        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("Database:Provider", "SQLite");
                builder.UseSetting("Database:AutoMigrate", "true");
                builder.UseSetting("ConnectionStrings:Default", $"Data Source={dbPath}");
                builder.UseSetting("RateLimiting:PermitLimitPerClient", "1000");
                builder.UseSetting("RateLimiting:WindowSeconds", "60");
                builder.UseSetting("AdminBootstrap:Username", "");
                builder.UseSetting("AdminBootstrap:Password", "");
            });

        _factory.CreateClient();
    }

    public HttpClient CreateHttpClient()
    {
        return _factory!.CreateClient();
    }

    public async Task SeedGatewayAppAsync(string appId, string appSecret)
    {
        using var scope = _factory!.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();

        dbContext.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = appId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(appSecret),
            AppName = "Gateway Test App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });

        await dbContext.SaveChangesAsync();
    }

    public async Task SeedGatewayUserAsync(Guid accountId, string username, string phone, string? remark)
    {
        using var scope = _factory!.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();

        dbContext.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            Remark = remark
        });

        dbContext.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("SecurePassword123!"),
            CreatedAt = DateTimeOffset.UtcNow
        });

        dbContext.UserLogins.Add(new UserLoginEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            ProviderName = "Sms",
            ProviderUserId = phone
        });

        await dbContext.SaveChangesAsync();
    }

    public GrpcChannel CreateChannel()
    {
        var httpHandler = _factory!.Server.CreateHandler();
        var options = new GrpcChannelOptions
        {
            MaxReceiveMessageSize = 16 * 1024 * 1024,
            MaxSendMessageSize = 16 * 1024 * 1024,
            HttpHandler = httpHandler
        };

        return GrpcChannel.ForAddress("http://localhost", options);
    }

    public async Task DisposeAsync()
    {
        _factory?.Dispose();
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", _previousMasterKey);
    }
}

internal sealed record TestPagedResponse<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);

internal sealed record TestUserItem(
    string UserId,
    string Username,
    string Phone,
    bool IsActive,
    string Remark,
    long CreatedAt,
    string DisplayName);
