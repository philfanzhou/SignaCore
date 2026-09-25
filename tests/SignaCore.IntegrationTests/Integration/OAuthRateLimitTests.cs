using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Domain.Validators;
using SignaCore.Domain.Services;
using SignaCore.Database.Repositories;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The interactive OIDC product rate limits (issue #304) over the real host: the fixed budgets
/// of the six endpoint classes, the partition contract (registered clients vs the source
/// network, never an attacker-controlled protocol value), the fixed overload shape, and the
/// side-effect guarantee — a rejected request consumes nothing, counts no failure, and never
/// reaches the password validator.
/// <para>
/// Each scenario drives a fresh derived host so its limiter state starts empty; the budgets
/// asserted are the <c>IdentityConstants</c> values themselves.</para>
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed partial class OAuthRateLimitTests : IClassFixture<IdentityServerFixture>
{
    private const string ClientId = "rate-limit-app";
    private const string ClientSecret = "rate-limit-app-secret";
    private const string RedirectUri = "https://bff.rate-limit.test/callback";
    private const string Username = "rate_limit_user";
    private const string Password = "Rate-Limit-123!";

    private readonly IdentityServerFixture _fixture;

    public OAuthRateLimitTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Token_WithinTheBudget_BehavesIdentically_AndThenRejectsOverload()
    {
        using var host = CreateHost();
        using var http = host.CreateClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader("unknown-client", "wrong-secret");
        var content = InvalidGrantForm();

        HttpStatusCode lastWithin = 0;
        string lastWithinBody = string.Empty;
        for (var i = 0; i < SignaCore.Database.IdentityConstants.OidcTokenRateLimitPerMinute; i++)
        {
            using var response = await http.PostAsync("/oauth2/token", content, TestContext.Current.CancellationToken);
            lastWithin = response.StatusCode;
            lastWithinBody = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        }

        // Every within-budget request answered the same protocol bytes: the generic 401
        // invalid_client an unregistered client always gets.
        Assert.Equal(HttpStatusCode.Unauthorized, lastWithin);
        Assert.Contains("invalid_client", lastWithinBody, StringComparison.Ordinal);

        using var rejected = await http.PostAsync("/oauth2/token", content, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        Assert.Equal("no-store", rejected.Headers.CacheControl?.ToString());
        Assert.False(rejected.Headers.Contains("Location"));
        var body = await rejected.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("temporarily_unavailable", body.GetProperty("error").GetString());
        Assert.Equal(
            "The service is temporarily busy. Please try again later.",
            body.GetProperty("error_description").GetString());
        // The fixed body names no partition key, no request value, and no endpoint detail.
        var raw = await rejected.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("unknown-client", raw, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Token_RejectedOverload_DoesNotConsumeAValidCode()
    {
        var seeded = await SeedAccountAndCodeAsync();
        using var host = CreateHost();
        using var http = host.CreateClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader("unknown-client", "wrong-secret");
        var content = InvalidGrantForm();

        for (var i = 0; i < SignaCore.Database.IdentityConstants.OidcTokenRateLimitPerMinute; i++)
        {
            using var within = await http.PostAsync("/oauth2/token", content, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Unauthorized, within.StatusCode);
        }

        // The valid code is presented only once the endpoint is over budget: the rejection must
        // leave it unconsumed and write no audit about it.
        using var rejected = await http.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = seeded.Code,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
            }),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);

        var codeRow = await QueryAsync(async context => await context.AuthorizationCodes.AsNoTracking()
            .SingleAsync(row => row.Id == seeded.CodeId, TestContext.Current.CancellationToken));
        Assert.Null(codeRow.ConsumedAt);
        Assert.Empty(await QueryAsync(async context => (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(context))
            .Where(row => row.TargetId == seeded.CodeId.ToString("D"))
            .ToList()));
    }

    [Fact]
    public async Task Authorize_ThePartitionIgnoresAttackerControlledValues()
    {
        await SeedClientAsync();
        using var host = CreateHost();
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        // Every request carries a different state and nonce: the partition key stays bound to
        // the registered client, so the budget binds exactly as it would without them.
        for (var i = 0; i < SignaCore.Database.IdentityConstants.OidcAuthorizeRateLimitPerMinute; i++)
        {
            using var within = await http.GetAsync(BuildAuthorizeUrl(i), TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Found, within.StatusCode);
        }

        using var rejected = await http.GetAsync(
            BuildAuthorizeUrl(SignaCore.Database.IdentityConstants.OidcAuthorizeRateLimitPerMinute),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        Assert.False(rejected.Headers.Contains("Location"));
        var raw = await rejected.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("rate-limit-app", raw, StringComparison.Ordinal);
        Assert.DoesNotContain("state-", raw, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Login_RejectedOverload_NeverReachesThePasswordValidator()
    {
        await SeedClientAsync();
        await SeedAccountAsync();
        var gate = new ValidationGate();
        using var host = CreateHost(services =>
        {
            services.RemoveAll<IIdentityValidator>();
            services.AddScoped<PasswordValidator>();
            services.AddScoped<IIdentityValidator>(serviceProvider =>
                new CountingValidator(
                    serviceProvider.GetRequiredService<PasswordValidator>(),
                    gate));
            // The login scenario pays two requests per attempt (form GET + credential POST) on
            // one host; neutralizing only the host-wide global limiter here isolates the login
            // policy under test. The global limiter keeps its own contract tests.
            services.PostConfigure<Microsoft.AspNetCore.RateLimiting.RateLimiterOptions>(options =>
                options.GlobalLimiter = System.Threading.RateLimiting.PartitionedRateLimiter
                    .Create<Microsoft.AspNetCore.Http.HttpContext, string>(_ =>
                        System.Threading.RateLimiting.RateLimitPartition.GetNoLimiter("test")));
        });
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        });

        // Each login POST rides its own seeded continuation, so only the login budget — not the
        // authorize budget — is consumed; the wrong password reaches the validator each time.
        for (var i = 0; i < SignaCore.Database.IdentityConstants.OidcLoginRateLimitPerMinute; i++)
        {
            var handle = await OAuthLoginTestSupport.SeedContinuationAsync(_fixture.Services);
            var (token, cookie) = await ReadLoginFormAsync(http, handle);
            using var post = await http.SendAsync(
                OAuthLoginTestSupport.CreateLoginPost(
                    fields: OAuthLoginTestSupport.LoginFields(
                        new OAuthLoginTestSupport.LoginSession(handle, cookie, token),
                        Username,
                        "wrong-password-" + i),
                    cookieHeader: $"{OAuthLoginTestSupport.CookieName}={cookie}"),
                TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, post.StatusCode);
        }

        var validated = gate.Validations;

        var lastHandle = await OAuthLoginTestSupport.SeedContinuationAsync(_fixture.Services);
        var (lastToken, lastCookie) = await ReadLoginFormAsync(http, lastHandle);
        using var rejected = await http.SendAsync(
            OAuthLoginTestSupport.CreateLoginPost(
                fields: OAuthLoginTestSupport.LoginFields(
                    new OAuthLoginTestSupport.LoginSession(lastHandle, lastCookie, lastToken),
                    Username,
                    "one-password-too-many"),
                cookieHeader: $"{OAuthLoginTestSupport.CookieName}={lastCookie}"),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        // The rejected request never reached the password validation: the counter is unchanged.
        Assert.Equal(validated, gate.Validations);
        Assert.True(gate.Validations > 0);
    }

    [Fact]
    public async Task UserInfo_AndLogout_AndRevoke_EachCarryTheirOwnBudget()
    {
        using var host = CreateHost();
        using var http = host.CreateClient();

        HttpStatusCode last = 0;
        for (var i = 0; i < SignaCore.Database.IdentityConstants.OidcUserInfoRateLimitPerMinute; i++)
        {
            using var within = await http.SendAsync(
                Bearer("/oauth2/userinfo", "not-a-real-token"),
                TestContext.Current.CancellationToken);
            last = within.StatusCode;
        }

        Assert.Equal(HttpStatusCode.Unauthorized, last);
        using var userinfoRejected = await http.SendAsync(
            Bearer("/oauth2/userinfo", "not-a-real-token"),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.TooManyRequests, userinfoRejected.StatusCode);

        using var logoutHost = CreateHost();
        using var logoutClient = logoutHost.CreateClient();
        for (var i = 0; i < SignaCore.Database.IdentityConstants.OidcLogoutRateLimitPerMinute; i++)
        {
            using var within = await logoutClient.PostAsync(
                "/oauth2/logout/requests",
                new FormUrlEncodedContent(new Dictionary<string, string> { ["id_token_hint"] = "x" }),
                TestContext.Current.CancellationToken);
            last = within.StatusCode;
        }

        Assert.Equal(HttpStatusCode.Unauthorized, last);
        using var logoutRejected = await logoutClient.PostAsync(
            "/oauth2/logout/requests",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["id_token_hint"] = "x" }),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.TooManyRequests, logoutRejected.StatusCode);

        using var revokeHost = CreateHost();
        using var revokeClient = revokeHost.CreateClient();
        revokeClient.DefaultRequestHeaders.Authorization = BasicHeader("unknown-client", "wrong-secret");
        for (var i = 0; i < SignaCore.Database.IdentityConstants.OidcRevokeRateLimitPerMinute; i++)
        {
            using var within = await revokeClient.PostAsync(
                "/oauth2/revoke",
                new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = "opaque" }),
                TestContext.Current.CancellationToken);
            last = within.StatusCode;
        }

        Assert.Equal(HttpStatusCode.Unauthorized, last);
        using var revokeRejected = await revokeClient.PostAsync(
            "/oauth2/revoke",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = "opaque" }),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.TooManyRequests, revokeRejected.StatusCode);
        Assert.Equal(
            "temporarily_unavailable",
            (await revokeRejected.Content.ReadFromJsonAsync<JsonElement>(
                cancellationToken: TestContext.Current.CancellationToken))
            .GetProperty("error").GetString());
    }

    [Fact]
    public async Task OnSqlite_ThePoliciesStayInProcess_AndTheGlobalLimiterChargesSynchronously()
    {
        using var host = CreateHost();
        using var http = host.CreateClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader("unknown-client", "wrong-secret");

        // No shared store, no partitioner, and no deferral of the global permit (#381).
        Assert.Null(host.Services.GetService<SignaCore.Database.RateLimiting.IOidcRateLimitStore>());
        Assert.Null(host.Services.GetService<OidcRateLimitPartitioner>());
        var options = host.Services
            .GetRequiredService<Microsoft.Extensions.Options.IOptions<Microsoft.AspNetCore.RateLimiting.RateLimiterOptions>>()
            .Value;
        Assert.IsNotType<SignaCore.Host.Security.SharedOidcBudgetAwareGlobalLimiter>(options.GlobalLimiter);
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("192.0.2.81");
        Microsoft.AspNetCore.Http.EndpointHttpContextExtensions.SetEndpoint(context, new Microsoft.AspNetCore.Http.Endpoint(
            _ => Task.CompletedTask,
            new Microsoft.AspNetCore.Http.EndpointMetadataCollection(
                new Microsoft.AspNetCore.RateLimiting.EnableRateLimitingAttribute(
                    SignaCore.Host.Security.OidcRateLimitPolicies.Token)),
            "token"));
        var before = options.GlobalLimiter!.GetStatistics(context)?.CurrentAvailablePermits ?? 100;
        using (var lease = options.GlobalLimiter.AttemptAcquire(context))
        {
            Assert.True(lease.IsAcquired);
        }

        Assert.Equal(before - 1, options.GlobalLimiter.GetStatistics(context)!.CurrentAvailablePermits);

        for (var i = 0; i < SignaCore.Database.IdentityConstants.OidcTokenRateLimitPerMinute; i++)
        {
            using var within = await http.PostAsync("/oauth2/token", InvalidGrantForm(), TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Unauthorized, within.StatusCode);
        }

        using var rejected = await http.PostAsync("/oauth2/token", InvalidGrantForm(), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        // The in-process windows decided: the SQLite budget table was never written.
        Assert.Equal(0, await QueryAsync(context => context.OidcRateLimitBuckets.CountAsync(TestContext.Current.CancellationToken)));
    }

    // ---- Helpers ----

    [System.Text.RegularExpressions.GeneratedRegex("name=\"__RequestVerificationToken\" value=\"([^\"]*)\"")]
    private static partial System.Text.RegularExpressions.Regex TokenPattern();

    private WebApplicationFactory<Program> CreateHost(
        Action<IServiceCollection>? configure = null) =>
        _fixture.WithTestServices(services =>
        {
            configure?.Invoke(services);
        });

    /// <summary>Reads the login form once and returns its antiforgery token and cookie value.</summary>
    private static async Task<(string Token, string Cookie)> ReadLoginFormAsync(
        HttpClient http,
        string handle)
    {
        using var form = await http.GetAsync(
            $"/oauth2/login?login_handle={handle}", TestContext.Current.CancellationToken);
        var html = await form.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var token = TokenPattern().Match(html).Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(token));
        var setCookie = OAuthLoginTestSupport.GetSetCookieHeader(form, OAuthLoginTestSupport.CookieName);
        Assert.NotNull(setCookie);
        return (token, OAuthLoginTestSupport.CookieValueFromHeader(setCookie!, OAuthLoginTestSupport.CookieName));
    }

    private static FormUrlEncodedContent InvalidGrantForm() =>
        new(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = "nobody",
            ["password"] = "nothing"
        });

    private static string BuildAuthorizeUrl(int sequence) =>
        "/oauth2/authorize?" + string.Join('&',
            $"client_id={ClientId}",
            $"redirect_uri={Uri.EscapeDataString(RedirectUri)}",
            "response_type=code",
            "scope=openid",
            $"state=state-{sequence}-{Guid.NewGuid():N}",
            $"nonce=nonce-{sequence}-{Guid.NewGuid():N}",
            "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method=S256");

    private static HttpRequestMessage Bearer(string path, string token) =>
        new(HttpMethod.Get, path)
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", token) }
        };

    private static AuthenticationHeaderValue BasicHeader(string id, string secret) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}")));

    private async Task SeedClientAsync()
    {
        await ExecuteAsync(async context =>
        {
            var application = await context.AppRegistrations
                .FirstOrDefaultAsync(row => row.AppId == ClientId, TestContext.Current.CancellationToken);
            if (application is null)
            {
                application = new Database.Entity.AppRegistrationEntity
                {
                    Id = Guid.NewGuid(),
                    AppId = ClientId,
                    AppSecretHash = BCrypt.Net.BCrypt.HashPassword(ClientSecret),
                    AppName = "Rate Limit App",
                    IsActive = true,
                    CreatedAt = DateTimeOffset.UtcNow,
                    AudienceMode = Database.Entity.AudienceMode.PerApplication,
                    ClientType = Database.Entity.OidcClientType.Confidential,
                    AllowAuthorizationCode = true,
                    AllowedScopes = "openid profile",
                    AllowRefreshToken = false
                };
                context.AppRegistrations.Add(application);
                context.AppRedirectUris.Add(new Database.Entity.AppRedirectUriEntity
                {
                    Id = Guid.NewGuid(),
                    AppRegistrationId = application.Id,
                    Kind = Database.Entity.RedirectUriKind.Redirect,
                    CanonicalUri = RedirectUri
                });
            }

            application.IsActive = true;
            application.AllowAuthorizationCode = true;
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
            context.ChangeTracker.Clear();
        });
    }

    private async Task<(Guid AccountId, Guid CredentialId)> SeedAccountAsync()
    {
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var username = $"{Username}_{Guid.NewGuid():N}";
        await ExecuteAsync(async context =>
        {
            context.Accounts.Add(new Database.Entity.AccountEntity
            {
                Id = accountId,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            });
            context.PasswordCredentials.Add(new Database.Entity.PasswordCredentialEntity
            {
                Id = credentialId,
                AccountId = accountId,
                Username = username,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(Password),
                CreatedAt = DateTimeOffset.UtcNow
            });
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
            context.ChangeTracker.Clear();
        });
        return (accountId, credentialId);
    }

    private sealed record SeededCode(string Code, Guid CodeId);

    private async Task<SeededCode> SeedAccountAndCodeAsync()
    {
        await SeedClientAsync();
        var (accountId, credentialId) = await SeedAccountAsync();
        var applicationRowId = await QueryAsync(async context => await context.AppRegistrations
            .AsNoTracking()
            .Where(row => row.AppId == ClientId)
            .Select(row => row.Id)
            .SingleAsync(TestContext.Current.CancellationToken));
        return await ExecuteAsync(async context =>
        {
            var session = await new Domain.Services.IdentitySessionStore(
                new Database.Repositories.IdentitySessionRepository(context),
                new EfCoreUnitOfWork(context))
                .CreateAsync(accountId, credentialId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
            var creation = await new Domain.Services.AuthorizationCodeStore(
                new Database.Repositories.AuthorizationCodeRepository(context),
                new EfCoreUnitOfWork(context))
                .CreateAsync(
                    session,
                    new AuthorizationCodeBinding(
                        applicationRowId, RedirectUri, "openid", "rate-limit-nonce",
                        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
                    DateTimeOffset.UtcNow,
                    TestContext.Current.CancellationToken);
            context.ChangeTracker.Clear();
            return new SeededCode(creation.Code, creation.Id);
        });
    }

    private async Task<TResult> QueryAsync<TResult>(Func<IdentityDbContext, Task<TResult>> query)
    {
        using var scope = _fixture.Services.CreateScope();
        return await query(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }

    private async Task ExecuteAsync(Func<IdentityDbContext, Task> action)
    {
        using var scope = _fixture.Services.CreateScope();
        await action(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }

    private async Task<TResult> ExecuteAsync<TResult>(Func<IdentityDbContext, Task<TResult>> action)
    {
        using var scope = _fixture.Services.CreateScope();
        return await action(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }

    /// <summary>The shared per-test count of password validations.</summary>
    private sealed class ValidationGate
    {
        private int _validations;

        public int Validations => Volatile.Read(ref _validations);

        public void Count() => Interlocked.Increment(ref _validations);
    }

    /// <summary>
    /// Counts every password validation and delegates to the host's real validator: the
    /// rejected login must not add a count.
    /// </summary>
    private sealed class CountingValidator(PasswordValidator inner, ValidationGate gate)
        : IIdentityValidator
    {
        public string GrantType => "password";

        public Task<ValidationResult> ValidateAsync(ValidationRequest request)
        {
            gate.Count();
            return inner.ValidateAsync(request);
        }
    }
}
