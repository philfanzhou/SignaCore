using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using Xunit;

namespace QuantumZhou.Identity.Tests.Integration;

public class IdentityHttpEndpointsTests : IClassFixture<IdentityServerFixture>
{
    private readonly IdentityServerFixture _fixture;

    public IdentityHttpEndpointsTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
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

public class IdentityServerFixture : IAsyncLifetime
{
    private WebApplicationFactory<Program>? _factory;
    private string? _previousMasterKey;
    private string? _databasePath;

    public Task InitializeAsync()
    {
        _previousMasterKey = Environment.GetEnvironmentVariable("RSA_MASTER_KEY");
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", "test-master-key-for-e2e-testing-only");
        _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"quantum-identity-http-{Guid.NewGuid():N}.db");
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath
        }.ConnectionString;

        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("AdminBootstrap:Username", "");
                builder.UseSetting("AdminBootstrap:Password", "");
                builder.UseSetting("Database:Provider", "SQLite");
                builder.UseSetting("Database:ServerVersion", "");
                builder.UseSetting("Database:ConnectionString", connectionString);
            });

        _factory.CreateClient();
        return Task.CompletedTask;
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

    public Task DisposeAsync()
    {
        _factory?.Dispose();
        SqliteConnection.ClearAllPools();
        if (_databasePath != null && File.Exists(_databasePath))
        {
            File.Delete(_databasePath);
        }
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", _previousMasterKey);
        return Task.CompletedTask;
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
