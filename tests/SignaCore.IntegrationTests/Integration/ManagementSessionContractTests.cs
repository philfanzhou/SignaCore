using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using ServiceMantle.Management;
using SignaCore.Database;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The shared ServiceMantle management session as served by the normal SignaCore host: fixed
/// result set, credential envelope, current-session projection, logout semantics, provider
/// failure convergence, and the sensitive-material boundary.
/// </summary>
public sealed class ManagementSessionContractTests : IClassFixture<IdentityServerFixture>
{
    private const string Root = "/management/v1";
    private const string CookieName = "__Host-ServiceMantle.Management";
    private const string UnsafeRequestHeader = "X-ServiceMantle-Request";

    private readonly IdentityServerFixture _fixture;

    public ManagementSessionContractTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    private static async Task<HttpResponseMessage> LoginAsync(
        HttpClient http,
        object? payload,
        bool includeUnsafeHeader = true)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{Root}/session/login");
        if (includeUnsafeHeader)
        {
            request.Headers.TryAddWithoutValidation(UnsafeRequestHeader, "1");
        }

        if (payload is not null)
        {
            request.Content = new StringContent(
                JsonSerializer.Serialize(payload),
                Encoding.UTF8,
                "application/json");
        }

        return await http.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static string? ExtractManagementCookie(HttpResponseMessage response)
    {
        if (!response.Headers.NonValidated.TryGetValues("Set-Cookie", out var values))
        {
            return null;
        }

        foreach (var value in values)
        {
            var segment = value.Split(';')[0];
            if (segment.StartsWith($"{CookieName}=", StringComparison.Ordinal))
            {
                return segment;
            }
        }

        return null;
    }

    private static async Task<string> LoginForCookieAsync(HttpClient http)
    {
        using var response = await LoginAsync(http, new
        {
            username = IdentityServerFixture.AdminUsername,
            password = IdentityServerFixture.AdminPassword
        });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var cookie = ExtractManagementCookie(response);
        Assert.NotNull(cookie);
        return cookie!;
    }

    /// <summary>
    /// Builds a fresh derived host for one login-bearing test. The login entry references the Setup
    /// rate-limit policy (5 per window per client partition) and TestServer reports no remote IP, so
    /// every login on the shared fixture lands in one partition and the sixth becomes a 429. A
    /// derived host carries its own in-process limiter state and shares the fixture's database file,
    /// so seeded accounts and audit rows stay visible without relaxing the production limit.
    /// </summary>
    private WebApplicationFactory<Program> CreateSessionHost() =>
        _fixture.WithTestServices(_ => { });

    [Fact]
    public async Task Login_WithBootstrapAdmin_Returns204AndSetsTheFixedManagementCookie()
    {
        using var factory = CreateSessionHost();
        using var client = factory.CreateClient();

        using var response = await LoginAsync(client, new
        {
            username = IdentityServerFixture.AdminUsername,
            password = IdentityServerFixture.AdminPassword
        });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var cookie = ExtractManagementCookie(response);
        Assert.NotNull(cookie);
        Assert.True(response.Headers.NonValidated.TryGetValues("Set-Cookie", out var setCookieValues));
        var setCookie = setCookieValues
            .Single(value => value.StartsWith($"{CookieName}=", StringComparison.Ordinal));
        Assert.Contains("secure", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", setCookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Login_WithWrongPassword_Returns401WithTheFixedErrorCodeAndRecordsFailure()
    {
        using var factory = CreateSessionHost();
        using var client = factory.CreateClient();

        using var response = await LoginAsync(client, new
        {
            username = IdentityServerFixture.AdminUsername,
            password = "definitely-not-the-password"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("management.session.unauthenticated", body, StringComparison.Ordinal);
        Assert.Null(ExtractManagementCookie(response));

        using var scope = _fixture.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var history = await db.LoginHistories.AsNoTracking()
            .Where(entry => entry.EventType == "login_failure" && entry.AuthMethod == "admin_login")
            .OrderByDescending(entry => entry.CreatedAt)
            .FirstAsync(TestContext.Current.CancellationToken);
        Assert.Equal(IdentityServerFixture.AdminUsername, history.Username);
        Assert.NotNull(history.FailureReason);
    }

    [Fact]
    public async Task Login_WithNonBootstrapAccount_Returns401AndRecordsTheBootstrapReason()
    {
        // A valid password account that is not the bootstrap administrator.
        var username = $"session_other_{Guid.NewGuid():N}";
        var password = "OtherOperator123!";
        using (var scope = _fixture.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var account = new Database.Entity.AccountEntity
            {
                Id = Guid.NewGuid(),
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            };
            db.Accounts.Add(account);
            db.PasswordCredentials.Add(new Database.Entity.PasswordCredentialEntity
            {
                Id = Guid.NewGuid(),
                AccountId = account.Id,
                Username = username,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(password),
                CreatedAt = DateTimeOffset.UtcNow
            });
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        using var factory = CreateSessionHost();
        using var client = factory.CreateClient();
        using var response = await LoginAsync(client, new { username, password });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("management.session.unauthenticated", body, StringComparison.Ordinal);
        Assert.Null(ExtractManagementCookie(response));

        using var scope2 = _fixture.Services.CreateScope();
        var db2 = scope2.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var history = await db2.LoginHistories.AsNoTracking()
            .SingleAsync(
                entry => entry.Username == username && entry.AuthMethod == "admin_login",
                TestContext.Current.CancellationToken);
        Assert.Equal("bootstrap_admin_required", history.FailureReason);
        Assert.Equal("login_failure", history.EventType);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Login_WithoutTheUnsafeRequestHeader_IsRejectedAsInvalidRequest(bool includeHeader)
    {
        using var factory = CreateSessionHost();
        using var client = factory.CreateClient();

        using var response = await LoginAsync(
            client,
            new { username = "x", password = "y" },
            includeUnsafeHeader: includeHeader);

        Assert.Equal(
            includeHeader ? HttpStatusCode.Unauthorized : HttpStatusCode.BadRequest,
            response.StatusCode);
    }

    [Fact]
    public async Task Login_WithDuplicateUnsafeRequestHeader_IsRejected()
    {
        using var factory = CreateSessionHost();
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{Root}/session/login")
        {
            Content = new StringContent(
                """{"username":"x","password":"y"}""", Encoding.UTF8, "application/json")
        };
        request.Headers.TryAddWithoutValidation(UnsafeRequestHeader, "1");
        request.Headers.TryAddWithoutValidation(UnsafeRequestHeader, "1");

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("management.request.invalid", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Login_WithQueryString_IsRejectedAsInvalidRequest()
    {
        using var factory = CreateSessionHost();
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(
            HttpMethod.Post, $"{Root}/session/login?who=admin")
        {
            Content = new StringContent(
                """{"username":"x","password":"y"}""", Encoding.UTF8, "application/json")
        };
        request.Headers.TryAddWithoutValidation(UnsafeRequestHeader, "1");

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("management.request.invalid", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Login_ExceedingTheEnvelope_IsRejectedAsInvalidRequest()
    {
        using var factory = CreateSessionHost();
        using var client = factory.CreateClient();
        var oversized = new string('a', 65 * 1024);
        using var response = await LoginAsync(client, new
        {
            username = oversized,
            password = oversized
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("management.request.invalid", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CurrentSession_WithTheManagementCookie_ReturnsTheFixedProjection()
    {
        using var factory = CreateSessionHost();
        using var client = factory.CreateClient();
        var cookie = await LoginForCookieAsync(client);
        client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", cookie);

        using var response = await client.GetAsync(Root + "/session", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken));
        var root = document.RootElement;
        Assert.True(root.GetProperty("authenticated").GetBoolean());
        Assert.NotEqual(default, root.GetProperty("expiresAtUtc").GetDateTime());
        var permissions = root.GetProperty("permissions");
        Assert.Equal(1, permissions.GetArrayLength());
        Assert.Equal("management.admin", permissions[0].GetString());
        // The projection never carries operator material.
        Assert.Throws<KeyNotFoundException>(() => root.GetProperty("operatorId"));
        Assert.Throws<KeyNotFoundException>(() => root.GetProperty("displayName"));
    }

    [Fact]
    public async Task CurrentSession_WithoutCookie_Returns401Unauthenticated()
    {
        using var client = _fixture.CreateHttpClient();

        using var response = await client.GetAsync(Root + "/session", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("management.session.unauthenticated", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CurrentSession_WithGarbageCookie_ReturnsTheClosedExpiredResult()
    {
        using var client = _fixture.CreateHttpClient();
        client.DefaultRequestHeaders.TryAddWithoutValidation(
            "Cookie", $"{CookieName}=not-a-valid-ticket");

        using var response = await client.GetAsync(Root + "/session", TestContext.Current.CancellationToken);

        // A presented-but-unacceptable cookie keeps the closed expired-session contract, not a 403:
        // management-entry-authorization.md reserves 403 forbidden for a valid identity that lacks
        // the permission or carries an invalid ServiceMantle claim, and never exposes ticket detail.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("management.session.expired", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Logout_WithTheManagementCookie_Returns204AndDeletesTheCookie()
    {
        using var factory = CreateSessionHost();
        using var client = factory.CreateClient();
        var cookie = await LoginForCookieAsync(client);
        client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", cookie);

        using var request = new HttpRequestMessage(HttpMethod.Post, Root + "/session/logout");
        request.Headers.TryAddWithoutValidation(UnsafeRequestHeader, "1");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(response.Headers.NonValidated.TryGetValues("Set-Cookie", out var deletionValues));
        Assert.Contains(
            deletionValues,
            value => value.StartsWith($"{CookieName}=;", StringComparison.Ordinal)
                     || value.Contains($"{CookieName}=; expires=", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Login_WhenTheProviderThrows_ConvergesTo503Unavailable()
    {
        using var factory = _fixture.WithTestServices(services =>
        {
            services.RemoveAll<IManagementIdentityProvider>();
            services.AddScoped<IManagementIdentityProvider, ThrowingProvider>();
        });
        using var client = factory.CreateClient();

        using var response = await LoginAsync(client, new
        {
            username = IdentityServerFixture.AdminUsername,
            password = IdentityServerFixture.AdminPassword
        });

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("management.session.unavailable", body, StringComparison.Ordinal);
        Assert.DoesNotContain("upstream", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Login_SensitiveMaterialNeverReachesLogs()
    {
        var capture = new LogCapture();
        using var factory = _fixture.WithTestServices(services =>
        {
            services.RemoveAll<ILoggerFactory>();
            services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
                logging.AddProvider(capture)));
        });
        using var client = factory.CreateClient();

        using var response = await LoginAsync(client, new
        {
            username = IdentityServerFixture.AdminUsername,
            password = IdentityServerFixture.AdminPassword
        });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var cookie = ExtractManagementCookie(response);
        Assert.NotNull(cookie);

        var logged = string.Join('\n', capture.Messages);
        Assert.DoesNotContain(IdentityServerFixture.AdminPassword, logged, StringComparison.Ordinal);
        Assert.DoesNotContain(cookie!, logged, StringComparison.Ordinal);
    }

    private sealed class ThrowingProvider : IManagementIdentityProvider
    {
        public ValueTask<ManagementIdentityResult> GetIdentityAsync(
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("upstream identity failure");
    }

    private sealed class LogCapture : ILoggerProvider
    {
        public List<string> Messages { get; } = [];

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(LogCapture owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                owner.Messages.Add(
                    $"{formatter(state, exception)} {exception?.ToString() ?? string.Empty}");
        }
    }
}
