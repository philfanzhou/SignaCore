using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The end-to-end self-service password change over the real HTTP surface (<c>POST
/// /api/profile/password</c>, <c>UserProfile</c> JWT Bearer): the credential rotates, every
/// identity session (reason <c>password_changed</c>), interactive family, and legacy refresh token
/// of the account is revoked in the same committed transaction, the new password logs in and the
/// old one does not, an already-issued access token still validates to <c>exp</c>, and neither a
/// plaintext password nor a hash reaches the logs, the audit snapshot, or any response.
/// </summary>
public sealed class ProfilePasswordChangeTests : IClassFixture<IdentityServerFixture>
{
    private const string OldPassword = "Old-Secret-123";
    private const string NewPassword = "New-Secret-456";
    private const string WrongPassword = "Totally-Wrong-789";

    private readonly IdentityServerFixture _fixture;

    public ProfilePasswordChangeTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task ChangePassword_RotatesTheCredential_AndRevokesEverySessionFamilyAndLegacyToken()
    {
        var seed = await SeedAccountAsync();
        var token = await GetUserTokenAsync(seed.Username, OldPassword);

        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await http.PostAsJsonAsync(
            "/api/profile/password",
            new { currentPassword = OldPassword, newPassword = NewPassword },
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // The new password logs in; the old one no longer does.
        Assert.True(await LoginSucceedsAsync(seed.Username, NewPassword));
        Assert.False(await LoginSucceedsAsync(seed.Username, OldPassword));

        await AssertDbAsync(async context =>
        {
            // Every session of the account is revoked with the canonical reason, including the
            // caller's own (account-wide revocation excludes nothing).
            var sessions = await context.IdentitySessions.AsNoTracking()
                .Where(row => row.AccountId == seed.AccountId)
                .ToListAsync(TestContext.Current.CancellationToken);
            Assert.Equal(2, sessions.Count);
            Assert.All(sessions, session =>
            {
                Assert.NotNull(session.RevokedAt);
                Assert.Equal("password_changed", session.RevocationReason);
            });

            var family = await context.RefreshTokens.AsNoTracking()
                .SingleAsync(row => row.Id == seed.FamilyRootId, TestContext.Current.CancellationToken);
            Assert.True(family.IsRevoked);
            var legacy = await context.RefreshTokens.AsNoTracking()
                .SingleAsync(row => row.Id == seed.LegacyTokenId, TestContext.Current.CancellationToken);
            Assert.True(legacy.IsRevoked);

            var audit = await context.AuditLogs.AsNoTracking()
                .SingleAsync(row => row.Action == "password_changed"
                    && row.TargetId == seed.AccountId.ToString(),
                    TestContext.Current.CancellationToken);
            using var snapshot = JsonDocument.Parse(audit.AfterSnapshot!);
            Assert.Equal(2, snapshot.RootElement.GetProperty("revokedSessions").GetInt32());
            Assert.Equal(1, snapshot.RootElement.GetProperty("revokedFamilyMembers").GetInt32());
            Assert.True(snapshot.RootElement.GetProperty("revokedLegacyTokens").GetInt32() >= 1);
        });
    }

    [Fact]
    public async Task ChangePassword_WrongCurrentPassword_GenericFailureCountsTheAttemptAndWritesNothingElse()
    {
        var seed = await SeedAccountAsync();
        var token = await GetUserTokenAsync(seed.Username, OldPassword);

        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await http.PostAsJsonAsync(
            "/api/profile/password",
            new { currentPassword = WrongPassword, newPassword = NewPassword },
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("Wrong current password.", error.GetProperty("message").GetString());

        // The shared failed-attempt counter recorded exactly one failure, the stored hash is
        // untouched (the old password still verifies, the new one does not), nothing was
        // revoked, and no audit row exists. No second login here: a successful login would
        // clear the very counter this test asserts on.
        await AssertDbAsync(async context =>
        {
            var attempt = await context.LoginAttempts.AsNoTracking()
                .SingleAsync(row => row.UsernameNormalized
                    == IdentityValueNormalizer.Normalize(seed.Username),
                    TestContext.Current.CancellationToken);
            Assert.Equal(1, attempt.FailedAttempts);

            var credential = await context.PasswordCredentials.AsNoTracking()
                .SingleAsync(row => row.Id == seed.CredentialId, TestContext.Current.CancellationToken);
            Assert.True(BCrypt.Net.BCrypt.Verify(OldPassword, credential.PasswordHash));
            Assert.False(BCrypt.Net.BCrypt.Verify(NewPassword, credential.PasswordHash));

            var sessions = await context.IdentitySessions.AsNoTracking()
                .Where(row => row.AccountId == seed.AccountId)
                .ToListAsync(TestContext.Current.CancellationToken);
            Assert.Equal(2, sessions.Count);
            Assert.All(sessions, session => Assert.Null(session.RevokedAt));

            Assert.Empty(await context.AuditLogs.AsNoTracking()
                .Where(row => row.Action == "password_changed"
                    && row.TargetId == seed.AccountId.ToString())
                .ToListAsync(TestContext.Current.CancellationToken));
        });
    }

    [Fact]
    public async Task ChangePassword_WeakNewPassword_FailsThePolicyWithoutAnyWrite()
    {
        var seed = await SeedAccountAsync();
        var token = await GetUserTokenAsync(seed.Username, OldPassword);

        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await http.PostAsJsonAsync(
            "/api/profile/password",
            new { currentPassword = OldPassword, newPassword = "weak" },
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        // The stored hash is untouched and nothing was revoked for this account.
        await AssertDbAsync(async context =>
        {
            var credential = await context.PasswordCredentials.AsNoTracking()
                .SingleAsync(row => row.Id == seed.CredentialId, TestContext.Current.CancellationToken);
            Assert.True(BCrypt.Net.BCrypt.Verify(OldPassword, credential.PasswordHash));

            var sessions = await context.IdentitySessions.AsNoTracking()
                .Where(row => row.AccountId == seed.AccountId)
                .ToListAsync(TestContext.Current.CancellationToken);
            Assert.All(sessions, session => Assert.Null(session.RevokedAt));
            Assert.Empty(await context.AuditLogs.AsNoTracking()
                .Where(row => row.Action == "password_changed"
                    && row.TargetId == seed.AccountId.ToString())
                .ToListAsync(TestContext.Current.CancellationToken));
        });
    }

    [Fact]
    public async Task ChangePassword_AlreadyIssuedAccessToken_StillValidatesToExp()
    {
        var seed = await SeedAccountAsync();
        var token = await GetUserTokenAsync(seed.Username, OldPassword);

        using var http = _fixture.CreateHttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // The token works before the change.
        using var before = await http.GetAsync("/api/profile/me", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        using var change = await http.PostAsJsonAsync(
            "/api/profile/password",
            new { currentPassword = OldPassword, newPassword = NewPassword },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, change.StatusCode);

        // The explicit non-guarantee: the already-issued self-contained access token is not
        // remotely revoked and still validates downstream to exp.
        using var after = await http.GetAsync("/api/profile/me", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, after.StatusCode);
    }

    [Fact]
    public async Task ChangePassword_NeverLeaksPlaintextOrHashToLogsAuditOrResponse()
    {
        var seed = await SeedAccountAsync();
        var capture = new CapturingLoggerProvider();
        using var factory = _fixture.WithTestServices(services =>
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

        var tokenClient = factory.CreateClient();
        tokenClient.DefaultRequestHeaders.Add("X-Admin-AppId", IdentityServerFixture.GatewayAppId);
        tokenClient.DefaultRequestHeaders.Add("X-Admin-AppSecret", IdentityServerFixture.GatewayAppSecret);
        var token = await GetTokenFromClientAsync(tokenClient, seed.Username, OldPassword);

        using var http = factory.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await http.PostAsJsonAsync(
            "/api/profile/password",
            new { currentPassword = OldPassword, newPassword = NewPassword },
            TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // The capture is proven non-empty (the login and change flowed through the pipeline).
        Assert.NotEmpty(capture.Messages);

        var oldHash = await QueryDbAsync(context => context.PasswordCredentials.AsNoTracking()
            .Where(row => row.Id == seed.CredentialId)
            .Select(row => row.PasswordHash)
            .SingleAsync(TestContext.Current.CancellationToken));

        // Neither plaintext nor the (old) hash appears in any captured log line, the response
        // body, or the audit snapshot.
        var canaries = new[] { OldPassword, NewPassword, oldHash };
        foreach (var canary in canaries)
        {
            Assert.DoesNotContain(capture.Messages, message => message.Contains(canary, StringComparison.Ordinal));
            Assert.DoesNotContain(canary, body, StringComparison.Ordinal);
        }

        await AssertDbAsync(async context =>
        {
            var audit = await context.AuditLogs.AsNoTracking()
                .SingleAsync(row => row.Action == "password_changed"
                    && row.TargetId == seed.AccountId.ToString(),
                    TestContext.Current.CancellationToken);
            foreach (var canary in canaries)
            {
                Assert.DoesNotContain(canary, audit.AfterSnapshot ?? string.Empty, StringComparison.Ordinal);
                Assert.DoesNotContain(canary, audit.BeforeSnapshot ?? string.Empty, StringComparison.Ordinal);
                Assert.DoesNotContain(canary, audit.Description ?? string.Empty, StringComparison.Ordinal);
            }
        });
    }

    // ---- Harness ----

    private sealed record Seed(
        Guid AccountId,
        Guid CredentialId,
        string Username,
        Guid SessionId,
        Guid FamilyRootId,
        Guid LegacyTokenId);

    private async Task<Seed> SeedAccountAsync()
    {
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var username = $"pwd_change_{Guid.NewGuid():N}";
        var sessionId = Guid.NewGuid();
        var secondSessionId = Guid.NewGuid();
        var familyRootId = Guid.NewGuid();
        var legacyTokenId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;

        await ExecuteDbAsync(async context =>
        {
            context.Accounts.Add(new AccountEntity
            {
                Id = accountId,
                IsActive = true,
                CreatedAt = now,
                Nickname = "pwd-change-nickname"
            });
            context.PasswordCredentials.Add(new PasswordCredentialEntity
            {
                Id = credentialId,
                AccountId = accountId,
                Username = username,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(OldPassword),
                CreatedAt = now
            });
            context.IdentitySessions.Add(new IdentitySessionEntity
            {
                Id = sessionId,
                AccountId = accountId,
                PasswordCredentialId = credentialId,
                AuthMethod = IdentityConstants.AuthMethodPassword,
                AuthTime = now,
                LastSeenAt = now,
                IdleExpiresAt = now.AddMinutes(30),
                AbsoluteExpiresAt = now.AddHours(12)
            });
            context.IdentitySessions.Add(new IdentitySessionEntity
            {
                Id = secondSessionId,
                AccountId = accountId,
                PasswordCredentialId = credentialId,
                AuthMethod = IdentityConstants.AuthMethodPassword,
                AuthTime = now,
                LastSeenAt = now,
                IdleExpiresAt = now.AddMinutes(30),
                AbsoluteExpiresAt = now.AddHours(12)
            });
            context.RefreshTokens.Add(new RefreshTokenEntity
            {
                Id = familyRootId,
                FamilyId = familyRootId,
                AccountId = accountId,
                AppId = IdentityServerFixture.GatewayAppId,
                TokenValue = RefreshTokenDigest.Compute("pwd-change-family-" + familyRootId.ToString("N")),
                CreatedAt = now,
                ExpiresAt = now.AddDays(7),
                IsRevoked = false,
                IdentitySessionId = sessionId,
                Scope = "openid profile offline_access",
                AuthTime = now.AddMinutes(-5)
            });
            context.RefreshTokens.Add(new RefreshTokenEntity
            {
                Id = legacyTokenId,
                FamilyId = legacyTokenId,
                AccountId = accountId,
                AppId = IdentityServerFixture.GatewayAppId,
                TokenValue = RefreshTokenDigest.Compute("pwd-change-legacy-" + legacyTokenId.ToString("N")),
                CreatedAt = now,
                ExpiresAt = now.AddDays(7),
                IsRevoked = false
            });
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
            context.ChangeTracker.Clear();
        });

        return new Seed(accountId, credentialId, username, sessionId, familyRootId, legacyTokenId);
    }

    private async Task<string> GetUserTokenAsync(string username, string password)
    {
        using var gateway = _fixture.CreateGatewayHttpClient();
        return await GetTokenFromClientAsync(gateway, username, password);
    }

    /// <summary>Asserts the login outcome without a reusable token: success issues a token,
    /// failure returns the historical <c>success:false</c> body.</summary>
    private async Task<bool> LoginSucceedsAsync(string username, string password)
    {
        using var gateway = _fixture.CreateGatewayHttpClient();
        using var response = await gateway.PostAsJsonAsync(
            "/api/auth/token",
            new { grantType = IdentityConstants.GrantTypePassword, username, password },
            TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        using var document = JsonDocument.Parse(body);
        return document.RootElement.TryGetProperty("success", out var success) && success.GetBoolean();
    }

    private static async Task<string> GetTokenFromClientAsync(
        HttpClient gateway, string username, string password)
    {
        using var response = await gateway.PostAsJsonAsync(
            "/api/auth/token",
            new { grantType = IdentityConstants.GrantTypePassword, username, password },
            TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        using var document = JsonDocument.Parse(body);
        if (!document.RootElement.TryGetProperty("success", out var success) || !success.GetBoolean())
        {
            throw new InvalidOperationException(
                $"The password grant did not issue a token: HTTP {(int)response.StatusCode} {body}");
        }

        return document.RootElement.GetProperty("accessToken").GetString()!;
    }

    private async Task AssertDbAsync(Func<IdentityDbContext, Task> assert)
    {
        using var scope = _fixture.Services.CreateScope();
        await assert(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }

    private async Task<TResult> QueryDbAsync<TResult>(Func<IdentityDbContext, Task<TResult>> query)
    {
        using var scope = _fixture.Services.CreateScope();
        return await query(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }

    private async Task ExecuteDbAsync(Func<IdentityDbContext, Task> action)
    {
        using var scope = _fixture.Services.CreateScope();
        await action(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<string> _messages = new();

        public IReadOnlyCollection<string> Messages => _messages;

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, _messages);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(
            string categoryName,
            ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var message = formatter(state, exception);
                messages.Enqueue(exception is null
                    ? $"[{logLevel}] {categoryName}: {message}"
                    : $"[{logLevel}] {categoryName}: {message}{Environment.NewLine}{exception}");
            }
        }
    }
}
