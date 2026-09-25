using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Startup;
using Testcontainers.PostgreSql;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

public sealed partial class OidcMultiInstanceAcceptanceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RefreshMatrix_ReuseRevokesDescendantsAcrossInstances_WithoutLeakingTokens(bool swap)
    {
        using var logs = new CapturingLoggerProvider();
        using var output = new StringWriter();
        var originalOutput = Console.Out;
        var canaries = new List<string>();
        try
        {
            Console.SetOut(output);
            using var first = CreateInstance(configureTestServices: services => ReplaceLoggerFactory(services, logs));
            using var second = CreateInstance(configureTestServices: services => ReplaceLoggerFactory(services, logs));
            var a = swap ? second : first;
            var b = swap ? first : second;
            var seed = await RefreshSeedAsync(a);
            canaries.AddRange(seed.Tokens.Values);
            using var rotated = await RefreshPostAsync(b, seed.Tokens.Refresh);
            var child = await RefreshSuccessAsync(rotated);
            canaries.AddRange(child.Values);
            using var rotatedAgain = await RefreshPostAsync(a, child.Refresh);
            var grandchild = await RefreshSuccessAsync(rotatedAgain);
            canaries.AddRange(grandchild.Values);
            Assert.True(seed.Tokens.Refresh != child.Refresh && child.Refresh != grandchild.Refresh, "Rotation reused plaintext.");
            var id = new JwtSecurityTokenHandler().ReadJwtToken(grandchild.Id);
            Assert.False(id.Payload.ContainsKey("nonce"));
            Assert.True(id.Subject == seed.AccountId.ToString("D"), "Rotation changed the subject.");
            Assert.True(id.Payload["sid"].ToString() == seed.SessionId.ToString("D"), "Rotation changed the session.");
            using var replay = await RefreshPostAsync(b, seed.Tokens.Refresh);
            await RefreshFailureAsync(replay);
            foreach (var host in new[] { a, b })
            foreach (var presented in new[] { child.Refresh, grandchild.Refresh })
            {
                using var rejected = await RefreshPostAsync(host, presented);
                await RefreshFailureAsync(rejected);
            }
            using (var scope = a.Services.CreateScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
                var family = await db.RefreshTokens.Where(x => x.FamilyId == seed.RootId).ToListAsync(TestContext.Current.CancellationToken);
                Assert.Equal(3, family.Count);
                var root = family.Single(x => x.Id == seed.RootId);
                Assert.All(family, row => Assert.True(row.ExpiresAt == root.ExpiresAt && row.AuthTime == root.AuthTime
                    && row.IdentitySessionId == root.IdentitySessionId && row.AccountId == root.AccountId
                    && row.AppId == root.AppId && row.Scope == root.Scope, "Rotation changed a family binding or deadline."));
                Assert.All(family.Where(x => x.ConsumedAt is null), x => Assert.True(x.IsRevoked));
                Assert.Null((await db.IdentitySessions.SingleAsync(x => x.Id == seed.SessionId, TestContext.Current.CancellationToken)).RevokedAt);
                var audits = await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(db, TestContext.Current.CancellationToken);
                Assert.Contains(audits, x => x.Action == "oidc.refresh.replayed");
            }
            var location = await AuthorizeWithIdentityCookieAsync(a, BuildSuccessAuthorizeUrl(), seed.Cookie);
            Assert.True(location.Contains("code=", StringComparison.Ordinal), "Family reuse revoked the identity session.");
            await AssertRefreshDatabaseHasNoPlaintextAsync(canaries);
            AssertRefreshCanariesAbsent(string.Join('\n', logs.Messages), canaries, "logs");

        }
        finally { Console.SetOut(originalOutput); }
        AssertRefreshCanariesAbsent(output.ToString(), canaries, "console output");
    }

    [Fact]
    public async Task RefreshMatrix_SigningFailureRollsBack_ThenPeerCreatesOnlyOneChild()
    {
        using var logs = new CapturingLoggerProvider();
        using var a = CreateInstance(configureTestServices: services => ReplaceLoggerFactory(services, logs));
        var seed = await RefreshSeedAsync(a);
        using var b = CreateInstance(configureTestServices: services =>
        {
            ReplaceLoggerFactory(services, logs);
            services.RemoveAll<IInteractiveAccessTokenFactory>();
            services.AddSingleton<IInteractiveAccessTokenFactory, RefreshFailingSigner>();
        });
        using var failed = await RefreshPostAsync(b, seed.Tokens.Refresh);
        await RefreshFailureAsync(failed, "server_error");
        using (var scope = a.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var root = Assert.Single(await db.RefreshTokens.Where(x => x.FamilyId == seed.RootId).ToListAsync(TestContext.Current.CancellationToken));
            Assert.Null(root.ConsumedAt);
            Assert.False(root.IsRevoked);
        }
        using var retried = await RefreshPostAsync(a, seed.Tokens.Refresh);
        var child = await RefreshSuccessAsync(retried);
        using var replay = await RefreshPostAsync(b, seed.Tokens.Refresh);
        await RefreshFailureAsync(replay);
        using var childRejected = await RefreshPostAsync(a, child.Refresh);
        await RefreshFailureAsync(childRejected);
        using var verification = a.Services.CreateScope();
        var context = verification.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var family = await context.RefreshTokens.Where(x => x.FamilyId == seed.RootId).ToListAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, family.Count);
        Assert.Single(family, x => x.ParentId == seed.RootId);
        var canaries = seed.Tokens.Values.Concat(child.Values).ToArray();
        await AssertRefreshDatabaseHasNoPlaintextAsync(canaries);
        AssertRefreshCanariesAbsent(string.Join('\n', logs.Messages), canaries, "failure/retry logs");
    }

    [Theory]
    [InlineData("wrong-client")]
    [InlineData("session")]
    [InlineData("account")]
    [InlineData("application")]
    [InlineData("max-age")]
    [InlineData("scope")]
    public async Task RefreshMatrix_CurrentBindingAndPolicyCannotBeBypassedAtThePeer(string change)
    {
        using var a = CreateInstance();
        using var b = CreateInstance();
        var seed = await RefreshSeedAsync(a);
        using (var scope = a.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var app = await db.AppRegistrations.SingleAsync(x => x.AppId == SuccessAppId, TestContext.Current.CancellationToken);
            var session = await db.IdentitySessions.SingleAsync(x => x.Id == seed.SessionId, TestContext.Current.CancellationToken);
            if (change == "wrong-client") db.AppRegistrations.Add(new AppRegistrationEntity
            { Id = Guid.NewGuid(), AppId = "refresh-other-client", AppName = "Other client", IsActive = true,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword(ClientSecret), CreatedAt = DateTimeOffset.UtcNow, AllowRefreshToken = true });
            if (change == "session") session.IdleExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1);
            if (change == "account") (await db.Accounts.SingleAsync(x => x.Id == seed.AccountId, TestContext.Current.CancellationToken)).IsActive = false;
            if (change == "application") app.IsActive = false;
            if (change == "max-age") { app.IdentitySessionMaxAgeSeconds = 60; session.AuthTime = DateTimeOffset.UtcNow.AddMinutes(-5); }
            if (change == "scope") app.AllowedScopes = "openid offline_access";
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }
        foreach (var host in new[] { b, a })
        {
            using var rejected = await RefreshPostAsync(host, seed.Tokens.Refresh, change == "wrong-client" ? "refresh-other-client" : SuccessAppId);
            await RefreshFailureAsync(rejected, change == "application" ? "invalid_client" : "invalid_grant");
        }
        using var verification = a.Services.CreateScope();
        var context = verification.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var root = Assert.Single(await context.RefreshTokens.Where(x => x.FamilyId == seed.RootId).ToListAsync(TestContext.Current.CancellationToken));
        Assert.Null(root.ConsumedAt);
        Assert.Equal(change is "session" or "max-age" or "scope", root.IsRevoked);
        if (change == "wrong-client")
        {
            using var accepted = await RefreshPostAsync(a, seed.Tokens.Refresh);
            await RefreshSuccessAsync(accepted);
        }
    }

    [Fact]
    public async Task RefreshDatabaseContractTests_PostgreSql_ConcurrentHttpRotationHasOneWinner()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true",
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true for the PostgreSQL HTTP matrix.");
        await using var container = new PostgreSqlBuilder(Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE")
            ?? "public.ecr.aws/docker/library/postgres:15-alpine").Build();
        await container.StartAsync(TestContext.Current.CancellationToken);
        var database = new DatabaseOptions { Provider = "PostgreSQL", ServerVersion = "15", ConnectionString = container.GetConnectionString() };
        var options = new DbContextOptionsBuilder<IdentityDbContext>(); options.UseIdentityDatabase(database);
        await using var setup = new IdentityDbContext(options.Options);
        var bootstrap = await setup.Database.CreateExecutionStrategy().ExecuteAsync(() => InstallationTestSupport.PrepareCompletedInstallationAsync(
            Path.Combine(_workingDirectory, "refresh-postgres"), database, RootSecretOf("refresh-postgres"), AdminUsername, AdminPassword,
            cancellationToken: TestContext.Current.CancellationToken));
        using var a = CreateInstance(bootstrap);
        using var b = CreateInstance(bootstrap);
        var seed = await RefreshSeedAsync(a);
        var results = await Task.WhenAll(RefreshPostAsync(a, seed.Tokens.Refresh), RefreshPostAsync(b, seed.Tokens.Refresh));
        try
        {
            AssertRefreshOneWinner(results);
            var child = await RefreshSuccessAsync(results.Single(x => x.StatusCode == HttpStatusCode.OK));
            await RefreshFailureAsync(results.Single(x => x.StatusCode != HttpStatusCode.OK));
            foreach (var host in new[] { a, b })
            {
                using var revoked = await RefreshPostAsync(host, child.Refresh);
                await RefreshFailureAsync(revoked);
            }
            using var scope = b.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var family = await db.RefreshTokens.Where(x => x.FamilyId == seed.RootId).ToListAsync(TestContext.Current.CancellationToken);
            Assert.Equal(2, family.Count);
            Assert.True(Assert.Single(family, x => x.ParentId is not null).IsRevoked);
        }
        finally { foreach (var result in results) result.Dispose(); }
    }

    [Fact]
    public async Task RefreshMatrix_DisconnectedAtomicStateNegativeControlDetectsTwoWinners()
    {
        using var a = CreateInstance();
        var seed = await RefreshSeedAsync(a);
        var copiedConnection = ConnectionStringOf("refresh-disconnected.db");
        await using (var source = new SqliteConnection(_connectionString))
        await using (var copy = new SqliteConnection(copiedConnection))
        {
            await source.OpenAsync(TestContext.Current.CancellationToken);
            await copy.OpenAsync(TestContext.Current.CancellationToken);
            source.BackupDatabase(copy);
        }
        var bootstrap = await InstallationTestSupport.PrepareUninstalledBootstrapAsync(Path.Combine(_workingDirectory, "refresh-disconnected"),
            new DatabaseOptions { Provider = "SQLite", ConnectionString = copiedConnection }, RootSecretOf("shared"), TestContext.Current.CancellationToken);
        using var disconnected = CreateInstance(bootstrap);
        var results = await Task.WhenAll(RefreshPostAsync(a, seed.Tokens.Refresh), RefreshPostAsync(disconnected, seed.Tokens.Refresh));
        try
        {
            // Each local transaction still works, but the distributed one-winner invariant is broken.
            Assert.All(results, response => Assert.Equal(HttpStatusCode.OK, response.StatusCode));
            var failure = Assert.Throws<Xunit.Sdk.EqualException>(() => AssertRefreshOneWinner(results));
            AssertRefreshCanariesAbsent(failure.Message, seed.Tokens.Values, "negative-control failure artifact");
            var children = await Task.WhenAll(results.Select(RefreshSuccessAsync));
            using var firstChild = await RefreshPostAsync(a, children[0].Refresh);
            using var secondChild = await RefreshPostAsync(disconnected, children[1].Refresh);
            await RefreshSuccessAsync(firstChild); await RefreshSuccessAsync(secondChild);
        }
        finally { foreach (var result in results) result.Dispose(); }
    }

    [Fact]
    public async Task RefreshMatrix_LegacyRotationStillWorksAcrossHostsWithoutInteractiveMarkers()
    {
        using var a = CreateInstance();
        using var b = CreateInstance();
        await EnsureSeededAsync(a);
        using (var scope = a.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            (await db.AppRegistrations.SingleAsync(x => x.AppId == SuccessAppId, TestContext.Current.CancellationToken)).AllowRefreshToken = true;
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }
        using var http = RefreshClient(a, SuccessAppId);
        using var issued = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        { ["grant_type"] = "password", ["username"] = LoginUser, ["password"] = LoginPassword }), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
        var initial = await issued.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        var raw = initial.GetProperty("refresh_token").GetString()!;
        using var rotated = await RefreshPostAsync(b, raw);
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        var body = await rotated.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        Assert.False(body.TryGetProperty("id_token", out _)); Assert.False(body.TryGetProperty("scope", out _));
        Assert.True(raw != body.GetProperty("refresh_token").GetString(), "Legacy rotation reused plaintext.");
        using var scope_ = a.Services.CreateScope();
        var db_ = scope_.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var rows = await db_.RefreshTokens.ToListAsync(TestContext.Current.CancellationToken);
        Assert.All(rows, row => { Assert.Null(row.IdentitySessionId); Assert.Null(row.ParentId); Assert.Null(row.ConsumedAt); Assert.Equal(row.Id, row.FamilyId); });
        await AssertRefreshDatabaseHasNoPlaintextAsync(new[] { raw, body.GetProperty("refresh_token").GetString()! });
    }

    private sealed record RefreshBody(string Access, string Id, string Refresh)
    { public string[] Values => [Access, Id, Refresh]; }
    private sealed record RefreshSeed(RefreshBody Tokens, string Cookie, Guid RootId, Guid SessionId, Guid AccountId);

    private async Task<RefreshSeed> RefreshSeedAsync(WebApplicationFactory<Program> host)
    {
        var cookie = await LoginOnInstanceAsync(host);
        using (var scope = host.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var app = await db.AppRegistrations.SingleAsync(x => x.AppId == SuccessAppId, TestContext.Current.CancellationToken);
            app.AllowRefreshToken = true; app.AllowedScopes = "openid profile offline_access";
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }
        var url = BuildSuccessAuthorizeUrl().Replace("scope=openid%20profile", "scope=openid%20profile%20offline_access", StringComparison.Ordinal);
        var code = ExtractQueryValue(await AuthorizeWithIdentityCookieAsync(host, url, cookie), "code");
        using var client = RefreshClient(host, SuccessAppId);
        using var response = await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        { ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = SuccessRegisteredUri, ["code_verifier"] = CodeVerifier }), TestContext.Current.CancellationToken);
        var tokens = await RefreshSuccessAsync(response);
        using var scope_ = host.Services.CreateScope();
        var root = await scope_.ServiceProvider.GetRequiredService<IdentityDbContext>().RefreshTokens.AsNoTracking()
            .SingleAsync(x => x.TokenValue == RefreshTokenDigest.Compute(tokens.Refresh), TestContext.Current.CancellationToken);
        return new RefreshSeed(tokens, cookie, root.Id, root.IdentitySessionId!.Value, root.AccountId);
    }

    private static HttpClient RefreshClient(WebApplicationFactory<Program> host, string clientId)
    {
        var client = NonRedirectingClient(host);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(clientId + ":" + ClientSecret)));
        return client;
    }
    private static async Task<HttpResponseMessage> RefreshPostAsync(WebApplicationFactory<Program> host, string token, string clientId = SuccessAppId)
    {
        using var client = RefreshClient(host, clientId);
        return await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        { ["grant_type"] = "refresh_token", ["refresh_token"] = token }), TestContext.Current.CancellationToken);
    }
    private static async Task<RefreshBody> RefreshSuccessAsync(HttpResponseMessage response)
    {
        Assert.True(response.StatusCode == HttpStatusCode.OK, "Refresh/token issuance did not succeed.");
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        Assert.Equal("openid profile offline_access", body.GetProperty("scope").GetString());
        return new RefreshBody(body.GetProperty("access_token").GetString()!, body.GetProperty("id_token").GetString()!, body.GetProperty("refresh_token").GetString()!);
    }
    private static async Task RefreshFailureAsync(HttpResponseMessage response, string error = "invalid_grant")
    {
        Assert.True(response.StatusCode == (error == "invalid_client" ? HttpStatusCode.Unauthorized : error == "server_error"
            ? HttpStatusCode.InternalServerError : HttpStatusCode.BadRequest), "Refresh failure status mismatch.");
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        Assert.True(body.GetProperty("error").GetString() == error, "Refresh error classification mismatch.");
        foreach (var name in new[] { "access_token", "refresh_token", "id_token" }) Assert.False(body.TryGetProperty(name, out _), "Failure exposed a token field.");
    }
    private static void AssertRefreshOneWinner(IEnumerable<HttpResponseMessage> results) => Assert.Equal(1, results.Count(x => x.StatusCode == HttpStatusCode.OK));
    private static void AssertRefreshCanariesAbsent(string text, IEnumerable<string> canaries, string carrier) =>
        Assert.True(canaries.All(value => !text.Contains(value, StringComparison.Ordinal)), "Plaintext token found in " + carrier + ".");

    private async Task AssertRefreshDatabaseHasNoPlaintextAsync(IEnumerable<string> canaries)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var tables = new List<string>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'";
            await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
            while (await reader.ReadAsync(TestContext.Current.CancellationToken)) tables.Add(reader.GetString(0));
        }
        Assert.Contains("service_audit_logs", tables);
        foreach (var table in tables)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT * FROM \"" + table.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
            await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
            while (await reader.ReadAsync(TestContext.Current.CancellationToken))
            for (var field = 0; field < reader.FieldCount; field++)
                AssertRefreshCanariesAbsent(reader.GetValue(field) is byte[] bytes ? Encoding.UTF8.GetString(bytes) : reader.GetValue(field).ToString() ?? string.Empty, canaries, "database");
        }
    }
    private sealed class RefreshFailingSigner : IInteractiveAccessTokenFactory
    {
        public InteractiveAccessTokenResult Create(InteractiveAccessTokenDescriptor descriptor, RsaSecurityKey signingKey, DateTimeOffset now) =>
            throw new InvalidOperationException("Synthetic refresh signing failure.");
    }
}
