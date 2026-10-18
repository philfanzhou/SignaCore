using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ServiceMantle.Audit;
using ServiceMantle.Management;
using ServiceMantle.Web.Management;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Host.Management;
using Xunit;

namespace SignaCore.Tests.Integration;

[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class AdminPasswordResetEndpointTests(IdentityServerFixture fixture) : IClassFixture<IdentityServerFixture>
{
    private const string OldPassword = "Http-Reset-Old-123";
    private const string NewPassword = " Http-Reset-New-456 ";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task CookieAndBearerAdministrators_ResetWithoutOldPassword_AndOnlyTheTargetLoginChanges()
    {
        var target = await SeedAsync();
        var other = await SeedAsync();
        using var admin = await fixture.CreateAdminHttpClientAsync();
        using var response = await admin.PostAsJsonAsync(Path(target.Id), new { newPassword = NewPassword }, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(Ct);
        var operation = JsonSerializer.Deserialize<JsonElement>(body);
        Assert.True(operation.GetProperty("success").GetBoolean());
        Assert.Equal("Password reset.", operation.GetProperty("message").GetString());
        Assert.DoesNotContain(NewPassword, body, StringComparison.Ordinal);
        Assert.True(await LoginSucceedsAsync(target.Username, NewPassword));
        Assert.False(await LoginSucceedsAsync(target.Username, OldPassword));
        Assert.True(await LoginSucceedsAsync(other.Username, OldPassword));

        using var host = fixture.WithTestServices(_ => { });
        using var scope = host.Services.CreateScope();
        var issued = await scope.ServiceProvider.GetRequiredService<ManagementBearerSessionService>().IssueAsync(
            await fixture.GetAdminAccountIdAsync(), Ct);
        using var bearer = host.CreateClient();
        bearer.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", issued.Token!);
        using var second = await bearer.PostAsJsonAsync(Path(target.Id), new { newPassword = OldPassword }, Ct);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.True(await LoginSucceedsAsync(target.Username, OldPassword));
        await QueryAsync(async db =>
        {
            var audits = (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(db, Ct))
                .Where(a => a.Action == "admin_password_reset" && a.TargetId == target.Id.ToString()).ToList();
            Assert.Equal(2, audits.Count);
            var adminId = (await fixture.GetAdminAccountIdAsync()).ToString();
            Assert.All(audits, audit => Assert.Equal(adminId, audit.OperatorId));
        });
    }

    [Theory]
    [InlineData("x")]
    [InlineData("lowercase1")]
    [InlineData("UPPERCASE1")]
    [InlineData("LettersOnly")]
    [InlineData(" weak ")]
    public async Task CookieAndBearerAdministrators_BypassPasswordLengthAndComplexity(string password)
    {
        using var host = fixture.WithTestServices(_ => { });
        using var scope = host.Services.CreateScope();
        var issued = await scope.ServiceProvider.GetRequiredService<ManagementBearerSessionService>().IssueAsync(
            await fixture.GetAdminAccountIdAsync(), Ct);
        using var bearer = host.CreateClient();
        bearer.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", issued.Token!);
        using var cookie = await fixture.CreateAdminHttpClientAsync();
        foreach (var admin in new[] { cookie, bearer })
        {
            var target = await SeedAsync();
            using var response = await admin.PostAsJsonAsync(Path(target.Id), new { newPassword = password }, Ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(await LoginSucceedsAsync(target.Username, password));
            Assert.False(await LoginSucceedsAsync(target.Username, OldPassword));
            if (password != password.Trim())
                Assert.False(await LoginSucceedsAsync(target.Username, password.Trim()));
        }
    }

    [Fact]
    public async Task AnonymousOrdinaryJwtApplicationAndForgedClaims_AreDeniedWithoutWrites()
    {
        var target = await SeedAsync();
        using var gateway = fixture.CreateGatewayHttpClient();
        using var login = await gateway.PostAsJsonAsync("/api/auth/token", new
        { grantType = IdentityConstants.GrantTypePassword, username = target.Username, password = OldPassword }, Ct);
        var json = await login.Content.ReadFromJsonAsync<JsonElement>(Ct);
        var jwt = json.GetProperty("accessToken").GetString()!;
        using var host = fixture.WithTestServices(_ => { });
        var noPermission = ManagementIdentity.Create(WellKnownManagementAuditOperatorSources.InteractiveAdmin,
            Guid.NewGuid().ToString(), [ManagementPermission.Read], "read operator").ToClaimsPrincipal();
        var forged = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Role, "admin")], ManagementSessionDefaults.AuthenticationScheme));
        var cookieOptions = host.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(ManagementSessionDefaults.AuthenticationScheme);
        foreach (var mode in new[] { "anonymous", "jwt", "application", "forged", "no-permission" })
        {
            using var http = host.CreateClient(new() { BaseAddress = new Uri("https://localhost"), HandleCookies = false });
            if (mode == "jwt") http.DefaultRequestHeaders.Authorization = new("Bearer", jwt);
            if (mode == "application")
            {
                http.DefaultRequestHeaders.Add("X-Admin-AppId", IdentityServerFixture.GatewayAppId);
                http.DefaultRequestHeaders.Add("X-Admin-AppSecret", IdentityServerFixture.GatewayAppSecret);
            }
            if (mode is "forged" or "no-permission")
            {
                var ticket = new AuthenticationTicket(mode == "forged" ? forged : noPermission,
                    new AuthenticationProperties { ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1) },
                    ManagementSessionDefaults.AuthenticationScheme);
                http.DefaultRequestHeaders.Add("Cookie", $"{ManagementSessionDefaults.CookieName}={cookieOptions.TicketDataFormat.Protect(ticket)}");
                http.DefaultRequestHeaders.Add("X-ServiceMantle-Request", "1");
            }
            using var response = await http.PostAsJsonAsync(Path(target.Id), new { newPassword = NewPassword }, Ct);
            Assert.Equal(mode is "forged" or "no-permission" ? HttpStatusCode.Forbidden : HttpStatusCode.Unauthorized,
                response.StatusCode);
        }
        await AssertUnchangedAsync(target);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"newPassword\":null}")]
    [InlineData("{\"newPassword\":\"\"}")]
    [InlineData("{\"newPassword\":\"   \"}")]
    [InlineData("{\"newPassword\":\"\\t\\r\\n\"}")]
    public async Task InvalidPasswords_ReturnTheStandardErrorWithoutWrites(string json)
    {
        var target = await SeedAsync();
        using var admin = await fixture.CreateAdminHttpClientAsync();
        using var response = await admin.PostAsync(Path(target.Id), new StringContent(json, Encoding.UTF8, "application/json"), Ct);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertErrorAsync(response);
        await AssertUnchangedAsync(target);
    }

    [Fact]
    public async Task UnknownNoPasswordAndMultipleCredentials_AreRejectedWithoutCreatingOrChangingCredentials()
    {
        var empty = await SeedAsync(0);
        var multiple = await SeedAsync(2);
        using var admin = await fixture.CreateAdminHttpClientAsync();
        foreach (var (id, expected) in new[] { (Guid.NewGuid(), HttpStatusCode.NotFound),
            (empty.Id, HttpStatusCode.BadRequest), (multiple.Id, HttpStatusCode.Conflict) })
        {
            using var response = await admin.PostAsJsonAsync(Path(id), new { newPassword = NewPassword }, Ct);
            Assert.Equal(expected, response.StatusCode);
            await AssertErrorAsync(response);
        }
        await AssertUnchangedAsync(empty);
        await AssertUnchangedAsync(multiple);
    }

    [Fact]
    public async Task Reset_ResponseAuditAndLogsContainNeitherPlaintextNorHashes()
    {
        var target = await SeedAsync();
        var capture = new CapturingLoggerProvider();
        using var host = fixture.WithTestServices(services =>
        {
            services.RemoveAll<ILoggerFactory>();
            services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
            {
                logging.AddProvider(capture);
                logging.SetMinimumLevel(LogLevel.Information);
                logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
                logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);
            }));
        });
        using var scope = host.Services.CreateScope();
        var issued = await scope.ServiceProvider.GetRequiredService<ManagementBearerSessionService>()
            .IssueAsync(await fixture.GetAdminAccountIdAsync(), Ct);
        using var http = host.CreateClient();
        http.DefaultRequestHeaders.Authorization = new("Bearer", issued.Token!);
        using var response = await http.PostAsJsonAsync(Path(target.Id), new { newPassword = NewPassword }, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(Ct);
        Assert.NotEmpty(capture.Messages);
        await QueryAsync(async db =>
        {
            var newHash = await db.PasswordCredentials.AsNoTracking().Where(c => c.AccountId == target.Id)
                .Select(c => c.PasswordHash).SingleAsync(Ct);
            var audits = (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(db, Ct))
                .Where(a => a.Action == "admin_password_reset" && a.TargetId == target.Id.ToString()).ToList();
            Assert.Single(audits);
            var auditText = JsonSerializer.Serialize(audits);
            foreach (var canary in new[] { OldPassword, NewPassword, target.Hash, newHash })
            {
                Assert.DoesNotContain(capture.Messages, message => message.Contains(canary, StringComparison.Ordinal));
                Assert.DoesNotContain(canary, body, StringComparison.Ordinal);
                Assert.DoesNotContain(canary, auditText, StringComparison.Ordinal);
            }
        });
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();
        public ILogger CreateLogger(string categoryName) => new CapturingLogger(Messages);
        public void Dispose() { }
        private sealed class CapturingLogger(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) => messages.Enqueue(formatter(state, exception));
        }
    }

    private static string Path(Guid id) => $"/api/admin/users/{id}/reset-password";
    private static async Task AssertErrorAsync(HttpResponseMessage response)
    {
        var json = await response.Content.ReadFromJsonAsync<JsonElement>(Ct);
        Assert.True(json.TryGetProperty("message", out _));
        Assert.False(json.TryGetProperty("errors", out _));
        Assert.DoesNotContain(NewPassword, json.ToString(), StringComparison.Ordinal);
    }
    private async Task<bool> LoginSucceedsAsync(string username, string password)
    {
        using var gateway = fixture.CreateGatewayHttpClient();
        using var response = await gateway.PostAsJsonAsync("/api/auth/token", new
        { grantType = IdentityConstants.GrantTypePassword, username, password }, Ct);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(Ct);
        return body.TryGetProperty("success", out var success) && success.GetBoolean();
    }
    private sealed record Seed(Guid Id, string Username, int Count, string Hash);
    private async Task<Seed> SeedAsync(int count = 1)
    {
        var id = Guid.NewGuid();
        var username = $"http-reset-{id:N}";
        var hash = BCrypt.Net.BCrypt.HashPassword(OldPassword, 4);
        await QueryAsync(async db =>
        {
            db.Accounts.Add(new AccountEntity { Id = id, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
            for (var index = 0; index < count; index++)
                db.PasswordCredentials.Add(new PasswordCredentialEntity { Id = Guid.NewGuid(), AccountId = id,
                    Username = index == 0 ? username : $"{username}-{index}", PasswordHash = hash,
                    CreatedAt = DateTimeOffset.UtcNow });
            await db.SaveChangesAsync(Ct);
        });
        return new Seed(id, username, count, hash);
    }
    private async Task AssertUnchangedAsync(Seed seed) => await QueryAsync(async db =>
    {
        var credentials = await db.PasswordCredentials.AsNoTracking().Where(c => c.AccountId == seed.Id).ToListAsync(Ct);
        Assert.Equal(seed.Count, credentials.Count);
        Assert.All(credentials, c => Assert.True(c.PasswordHash == seed.Hash, "Original hash is preserved."));
        Assert.Empty((await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(db, Ct))
            .Where(a => a.Action == "admin_password_reset" && a.TargetId == seed.Id.ToString()));
    });
    private async Task QueryAsync(Func<IdentityDbContext, Task> query)
    {
        using var scope = fixture.Services.CreateScope();
        await query(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }
}
