using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
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
    public async Task CodeMatrix_BindingsAndReplay_CannotBeBypassedByChangingInstances(bool swap)
    {
        using var first = CreateInstance();
        using var second = CreateInstance();
        var a = swap ? second : first;
        var b = swap ? first : second;
        var cookie = await LoginOnInstanceAsync(a);
        var ct = TestContext.Current.CancellationToken;
        foreach (var variant in new[] { "forged", "expired", "redirect", "verifier", "plain", "missing-verifier", "scope", "cross-client", "wrong-secret", "mixed-auth", "missing-auth" })
        {
            var code = ExtractQueryValue(await AuthorizeWithIdentityCookieAsync(a, BuildSuccessAuthorizeUrl(), cookie), "code");
            var fields = CodeFields(code);
            var clientId = SuccessAppId;
            var secret = ClientSecret;
            if (variant == "forged") fields["code"] = new string('x', 43);
            if (variant == "redirect") fields["redirect_uri"] += "/";
            if (variant == "verifier") fields["code_verifier"] = new string('w', 43);
            if (variant == "plain") fields["code_verifier"] = SuccessChallenge;
            if (variant == "missing-verifier") fields.Remove("code_verifier");
            if (variant == "scope") fields["scope"] = "openid";
            if (variant == "wrong-secret") secret = "incorrect-secret";
            if (variant == "mixed-auth") { fields["client_id"] = clientId; fields["client_secret"] = secret; }
            if (variant is "expired" or "cross-client")
            {
                using var scope = a.Services.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
                if (variant == "expired")
                {
                    var row = await db.AuthorizationCodes.SingleAsync(x => x.CodeDigest == AuthorizationCodeDigest.Compute(code), ct);
                    row.ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1);
                }
                else
                {
                    clientId = "matrix-other-client";
                    db.AppRegistrations.Add(new AppRegistrationEntity
                    {
                        Id = Guid.NewGuid(), AppId = clientId, AppName = "Other client", IsActive = true,
                        AppSecretHash = BCrypt.Net.BCrypt.HashPassword(secret), CreatedAt = DateTimeOffset.UtcNow,
                        AudienceMode = AudienceMode.PerApplication, ClientType = OidcClientType.Confidential,
                        AllowAuthorizationCode = true, AllowedScopes = "openid profile"
                    });
                }
                await db.SaveChangesAsync(ct);
            }
            using var response = await SendCodeAsync(b, fields, variant == "missing-auth" ? null : clientId, secret);
            var expected = variant is "wrong-secret" or "mixed-auth" or "missing-auth" ? "invalid_client"
                : variant is "missing-verifier" or "scope" ? "invalid_request" : "invalid_grant";
            await AssertCodeFailureAsync(response, expected);
            using (var scope = a.Services.CreateScope())
            {
                var lookup = await scope.ServiceProvider.GetRequiredService<IAuthorizationCodeStore>().FindAsync(code, DateTimeOffset.UtcNow, ct);
                Assert.Null(lookup.Entity!.ConsumedAt);
            }
            if (variant != "expired")
            {
                // The rejected attempt did not poison the code; redeem from the original host
                // with form client auth, then prove the peer sees the same consumed fact.
                var valid = CodeFields(code);
                valid["client_id"] = SuccessAppId; valid["client_secret"] = ClientSecret;
                using var success = await SendCodeAsync(a, valid, null);
                Assert.Equal(HttpStatusCode.OK, success.StatusCode);
            }
        }
        var replayCode = ExtractQueryValue(await AuthorizeWithIdentityCookieAsync(a, BuildSuccessAuthorizeUrl(), cookie), "code");
        using var winner = await SendCodeAsync(b, CodeFields(replayCode));
        Assert.Equal(HttpStatusCode.OK, winner.StatusCode);
        using var loser = await SendCodeAsync(a, CodeFields(replayCode));
        await AssertCodeFailureAsync(loser, "invalid_grant");
    }

    [Fact]
    public async Task CodeMatrix_SigningFailureRollsBack_AndTheOtherInstanceCanRetry()
    {
        using var a = CreateInstance();
        using var b = CreateInstance(configureTestServices: services =>
        {
            services.RemoveAll<IInteractiveAccessTokenFactory>();
            services.AddSingleton<IInteractiveAccessTokenFactory, FailedCodeSigner>();
        });
        var cookie = await LoginOnInstanceAsync(a);
        var code = ExtractQueryValue(await AuthorizeWithIdentityCookieAsync(a, BuildSuccessAuthorizeUrl(), cookie), "code");
        using var failure = await SendCodeAsync(b, CodeFields(code));
        await AssertCodeFailureAsync(failure, "server_error");
        using var success = await SendCodeAsync(a, CodeFields(code));
        Assert.Equal(HttpStatusCode.OK, success.StatusCode);
        using var replay = await SendCodeAsync(b, CodeFields(code));
        await AssertCodeFailureAsync(replay, "invalid_grant");
    }

    // The method name deliberately includes DatabaseContractTests: the existing CI provider
    // job selects that substring, while the normal build reports this gate as skipped.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CodeDatabaseContractTests_PostgreSql_TwoHttpHostsAndAtomicWriteNegativeControl(bool bypassConsume)
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true",
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true for the PostgreSQL HTTP matrix.");
        await using var container = new PostgreSqlBuilder(Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE")
            ?? "public.ecr.aws/docker/library/postgres:15-alpine").Build();
        await container.StartAsync(TestContext.Current.CancellationToken);
        var database = new DatabaseOptions
        { Provider = "PostgreSQL", ServerVersion = "15", ConnectionString = container.GetConnectionString() };
        var options = new DbContextOptionsBuilder<IdentityDbContext>();
        options.UseIdentityDatabase(database);
        await using var setupContext = new IdentityDbContext(options.Options);
        // The existing preparation helper owns an explicit settings transaction. PostgreSQL's
        // configured retry strategy must own that whole preparation, including its context.
        var bootstrap = await setupContext.Database.CreateExecutionStrategy().ExecuteAsync(() =>
            InstallationTestSupport.PrepareCompletedInstallationAsync(
                Path.Combine(_workingDirectory, "postgres"), database,
                RootSecretOf("postgres"), AdminUsername, AdminPassword));
        void Configure(IServiceCollection services)
        {
            if (!bypassConsume) return;
            services.RemoveAll<IAuthorizationCodeRepository>();
            services.AddScoped<IAuthorizationCodeRepository, NonConsumingCodeRepository>();
        }
        using var a = CreateInstance(bootstrap, Configure);
        using var b = CreateInstance(bootstrap, Configure);
        var cookie = await LoginOnInstanceAsync(a);
        var code = ExtractQueryValue(await AuthorizeWithIdentityCookieAsync(b, BuildSuccessAuthorizeUrl(), cookie), "code");
        var results = await Task.WhenAll(SendCodeAsync(a, CodeFields(code)), SendCodeAsync(b, CodeFields(code)));
        try
        {
            void OneWinner() => Assert.Equal(1, results.Count(r => r.StatusCode == HttpStatusCode.OK));
            if (bypassConsume)
            {
                Assert.Throws<Xunit.Sdk.EqualException>(OneWinner);
                Assert.All(results, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
            }
            else
            {
                OneWinner();
                await AssertCodeFailureAsync(results.Single(r => r.StatusCode != HttpStatusCode.OK), "invalid_grant");
                using var again = await SendCodeAsync(b, CodeFields(code));
                await AssertCodeFailureAsync(again, "invalid_grant");
            }
        }
        finally { foreach (var result in results) result.Dispose(); }
    }

    private static Dictionary<string, string> CodeFields(string code) => new()
    {
        ["grant_type"] = "authorization_code", ["code"] = code,
        ["redirect_uri"] = SuccessRegisteredUri, ["code_verifier"] = CodeVerifier
    };

    private static async Task<HttpResponseMessage> SendCodeAsync(WebApplicationFactory<Program> host,
        Dictionary<string, string> fields, string? clientId = SuccessAppId, string secret = ClientSecret)
    {
        using var client = NonRedirectingClient(host);
        if (clientId is not null) client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes(clientId + ":" + secret)));
        return await client.PostAsync("/oauth2/token", new FormUrlEncodedContent(fields), TestContext.Current.CancellationToken);
    }

    private static async Task AssertCodeFailureAsync(HttpResponseMessage response, string error)
    {
        Assert.Equal(error == "invalid_client" ? HttpStatusCode.Unauthorized : error == "server_error"
            ? HttpStatusCode.InternalServerError : HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        Assert.Equal(error, body.GetProperty("error").GetString());
        foreach (var key in new[] { "access_token", "id_token", "refresh_token" }) Assert.False(body.TryGetProperty(key, out _));
        // Authentication can fail before the interactive dispatcher; its legacy error
        // headers are outside the code-consumption contract. No token may exist in either shape.
    }

    private sealed class FailedCodeSigner : IInteractiveAccessTokenFactory
    {
        public InteractiveAccessTokenResult Create(InteractiveAccessTokenDescriptor descriptor, RsaSecurityKey signingKey, DateTimeOffset now) =>
            throw new InvalidOperationException("Synthetic signing failure.");
    }

    private sealed class NonConsumingCodeRepository(IdentityDbContext db) : IAuthorizationCodeRepository
    {
        private readonly AuthorizationCodeRepository inner = new(db);
        public Task AddAsync(AuthorizationCodeEntity code, CancellationToken ct = default) => inner.AddAsync(code, ct);
        public Task<AuthorizationCodeEntity?> GetByCodeDigestAsync(string digest, CancellationToken ct = default) => inner.GetByCodeDigestAsync(digest, ct);
        public Task<AuthorizationCodeEntity?> LockByIdAsync(Guid id, CancellationToken ct = default) => inner.LockByIdAsync(id, ct);
        public Task<bool> TryConsumeAsync(Guid id, DateTimeOffset now, CancellationToken ct = default) => Task.FromResult(true);
        public Task<int> LinkRefreshFamilyAsync(Guid id, Guid root, CancellationToken ct = default) => inner.LinkRefreshFamilyAsync(id, root, ct);
        public Task<int> RemoveExpiredBeforeAsync(DateTimeOffset cutoff, CancellationToken ct = default) => inner.RemoveExpiredBeforeAsync(cutoff, ct);
    }
}
