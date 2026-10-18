using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain;
using SignaCore.Host;
using SignaCore.Host.Http;
using SignaCore.Host.Management;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// <c>GET /api/gateway/auth-capabilities</c> over the real host (#608): the calling application's
/// permitted login methods, read from its stored SMS mode on every request, behind the existing
/// generic gateway authentication, with <c>Cache-Control: no-store</c> on the 200 and the 401, and
/// without changing any state.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class GatewayAuthCapabilitiesTests : IClassFixture<IdentityServerFixture>
{
    private const string Route = "/api/gateway/auth-capabilities";
    private const string GenericUnauthorizedBody = "{\"message\":\"Invalid or missing gateway credentials.\"}";
    private const string SmsDisabledMessage = "SMS login is disabled for this application";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly IdentityServerFixture _fixture;

    public GatewayAuthCapabilitiesTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    /// <summary>
    /// Every SMS mode maps to the documented booleans, the body has exactly the two boolean fields,
    /// and an enabled mode without a provider profile still reports SMS as permitted.
    /// </summary>
    [Theory]
    [InlineData(SmsLoginMode.Disabled, null, false)]
    [InlineData(SmsLoginMode.Disabled, OAuthLoginSmsCodeTestSupport.ProfileKey, false)]
    [InlineData(SmsLoginMode.ManualApproval, null, true)]
    [InlineData(SmsLoginMode.ManualApproval, OAuthLoginSmsCodeTestSupport.ProfileKey, true)]
    [InlineData(SmsLoginMode.AutoProvision, null, true)]
    [InlineData(SmsLoginMode.AutoProvision, OAuthLoginSmsCodeTestSupport.ProfileKey, true)]
    public async Task EachSmsMode_AnswersExactlyTwoBooleanFields(
        SmsLoginMode mode, string? profileKey, bool smsLoginEnabled)
    {
        using var host = _fixture.WithTestServices(_ => { });
        var app = await SeedAppAsync(host.Services, mode, profileKey);

        using var response = await GetCapabilitiesAsync(host, app);

        await AssertCapabilitiesAsync(response, smsLoginEnabled);
    }

    /// <summary>
    /// A committed policy change — through the admin API or a direct database update — shows up on
    /// the very next request without a restart, on another host instance as well, and only for the
    /// application whose policy changed.
    /// </summary>
    [Fact]
    public async Task PolicyChangeBetweenRequests_ChangesOnlyThatApplicationsAnswer()
    {
        using var gatewayHost = _fixture.WithTestServices(_ => { });
        using var admin = await _fixture.CreateAdminHttpClientAsync();
        var changed = await SeedAppAsync(gatewayHost.Services, SmsLoginMode.Disabled, profileKey: null);
        var other = await SeedAppAsync(gatewayHost.Services, SmsLoginMode.ManualApproval, profileKey: null);

        await AssertCapabilitiesAsync(await GetCapabilitiesAsync(gatewayHost, changed), smsLoginEnabled: false);
        await AssertCapabilitiesAsync(await GetCapabilitiesAsync(gatewayHost, other), smsLoginEnabled: true);

        // Through the admin API, which runs on a different host instance than the gateway reads.
        await SetPolicyThroughAdminAsync(admin, changed, "AutoProvision", profileKey: null);
        await AssertCapabilitiesAsync(await GetCapabilitiesAsync(gatewayHost, changed), smsLoginEnabled: true);
        await AssertCapabilitiesAsync(await GetCapabilitiesAsync(gatewayHost, other), smsLoginEnabled: true);

        await SetPolicyThroughAdminAsync(admin, changed, "Disabled", profileKey: null);
        await AssertCapabilitiesAsync(await GetCapabilitiesAsync(gatewayHost, changed), smsLoginEnabled: false);
        await AssertCapabilitiesAsync(await GetCapabilitiesAsync(gatewayHost, other), smsLoginEnabled: true);

        // Through a committed database update.
        await OAuthLoginSmsCodeTestSupport.SetApplicationAsync(
            gatewayHost.Services, changed.Id, SmsLoginMode.ManualApproval, profileKey: null);
        await AssertCapabilitiesAsync(await GetCapabilitiesAsync(gatewayHost, changed), smsLoginEnabled: true);
        await OAuthLoginSmsCodeTestSupport.SetApplicationAsync(
            gatewayHost.Services, other.Id, SmsLoginMode.Disabled, profileKey: null);
        await AssertCapabilitiesAsync(await GetCapabilitiesAsync(gatewayHost, other), smsLoginEnabled: false);
        await AssertCapabilitiesAsync(await GetCapabilitiesAsync(gatewayHost, changed), smsLoginEnabled: true);
    }

    /// <summary>
    /// Missing, wrong, unknown, inactive, and expired-registration credentials all get the one
    /// existing generic 401 — same status, same body, plus <c>no-store</c> — so the answer never
    /// says whether an application exists or why it failed.
    /// </summary>
    [Fact]
    public async Task InvalidCredentials_AnswerTheGenericUnauthorizedResponse()
    {
        using var host = _fixture.WithTestServices(_ => { });
        var valid = await SeedAppAsync(host.Services, SmsLoginMode.AutoProvision, profileKey: null);
        var inactive = await SeedAppAsync(host.Services, SmsLoginMode.AutoProvision, profileKey: null, isActive: false);
        var expired = await SeedAppAsync(
            host.Services, SmsLoginMode.AutoProvision, profileKey: null,
            callbackExpiresAt: DateTimeOffset.UtcNow.AddMinutes(-5));

        var attempts = new (string? AppId, string? Secret)[]
        {
            (null, null),
            (valid.AppId, null),
            (null, valid.Secret),
            (valid.AppId, ""),
            (valid.AppId, "wrong-" + valid.Secret),
            ("unknown-" + Guid.NewGuid().ToString("N")[..12], valid.Secret),
            (inactive.AppId, inactive.Secret),
            (expired.AppId, expired.Secret)
        };

        foreach (var (appId, secret) in attempts)
        {
            using var response = await SendAsync(host, appId, secret);
            await AssertGenericUnauthorizedAsync(response);
        }
    }

    /// <summary>
    /// The route accepts only gateway application credentials. A user access token, a management
    /// bearer session, a management cookie, or an identity cookie on its own is still the generic
    /// 401 — none of them falls back into an application identity.
    /// </summary>
    [Fact]
    public async Task UserAndAdminSessionsAlone_CannotAuthenticateTheRoute()
    {
        using var host = _fixture.WithTestServices(_ => { });

        // A user access token issued through the password grant.
        string userAccessToken;
        using (var gateway = CreateClient(host, IdentityServerFixture.GatewayAppId, IdentityServerFixture.GatewayAppSecret))
        {
            using var token = await gateway.PostAsJsonAsync("/api/auth/token", new
            {
                grantType = IdentityConstants.GrantTypePassword,
                username = IdentityServerFixture.AdminUsername,
                password = IdentityServerFixture.AdminPassword
            }, Ct);
            var tokenBody = await token.Content.ReadFromJsonAsync<JsonElement>(Ct);
            Assert.True(tokenBody.GetProperty("success").GetBoolean());
            userAccessToken = tokenBody.GetProperty("accessToken").GetString()!;
        }

        // A management bearer session for the administrator.
        string managementBearer;
        using (var scope = host.Services.CreateScope())
        {
            var issued = await scope.ServiceProvider.GetRequiredService<ManagementBearerSessionService>()
                .IssueAsync(await _fixture.GetAdminAccountIdAsync(), Ct);
            managementBearer = issued.Token!;
        }

        using (var bearer = CreateClient(host, null, null))
        {
            bearer.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", userAccessToken);
            using var response = await bearer.GetAsync(Route, Ct);
            await AssertGenericUnauthorizedAsync(response);
        }

        using (var bearer = CreateClient(host, null, null))
        {
            bearer.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", managementBearer);
            using var response = await bearer.GetAsync(Route, Ct);
            await AssertGenericUnauthorizedAsync(response);
        }

        // The cookie-carrying admin client holds a live management session cookie.
        using (var admin = await _fixture.CreateAdminHttpClientAsync())
        {
            using var session = await admin.GetAsync("/api/admin/session/me", Ct);
            Assert.Equal(HttpStatusCode.OK, session.StatusCode);
            using var response = await admin.GetAsync(Route, Ct);
            await AssertGenericUnauthorizedAsync(response);
        }

        using (var identity = CreateClient(host, null, null))
        {
            identity.DefaultRequestHeaders.Add("Cookie", await IssueIdentityCookieAsync(host));
            using var response = await identity.GetAsync(Route, Ct);
            await AssertGenericUnauthorizedAsync(response);
        }
    }

    /// <summary>
    /// App A cannot inspect App B: selectors in the query string or a body never change which
    /// application is read — the answer is always the authenticated caller's own.
    /// </summary>
    [Fact]
    public async Task InjectedSelectors_NeverChangeTheInspectedApplication()
    {
        using var host = _fixture.WithTestServices(_ => { });
        var caller = await SeedAppAsync(host.Services, SmsLoginMode.Disabled, profileKey: null);
        var target = await SeedAppAsync(host.Services, SmsLoginMode.AutoProvision, profileKey: null);
        using var http = CreateClient(host, caller.AppId, caller.Secret);

        foreach (var query in new[]
                 {
                     $"?appId={target.AppId}",
                     $"?app_id={target.AppId}",
                     $"?AppId={target.AppId}&clientId={target.AppId}&client_id={target.AppId}",
                     $"?X-Admin-AppId={target.AppId}"
                 })
        {
            using var response = await http.GetAsync(Route + query, Ct);
            await AssertCapabilitiesAsync(response, smsLoginEnabled: false);
        }

        using var withBody = new HttpRequestMessage(HttpMethod.Get, Route)
        {
            Content = JsonContent.Create(new { appId = target.AppId, app_id = target.AppId })
        };
        using var bodyResponse = await http.SendAsync(withBody, Ct);
        await AssertCapabilitiesAsync(bodyResponse, smsLoginEnabled: false);

        // The target's own credentials still read the target.
        await AssertCapabilitiesAsync(await GetCapabilitiesAsync(host, target), smsLoginEnabled: true);
    }

    /// <summary>
    /// The read is read-only: neither a successful read nor a rejected one creates or changes an
    /// account, login, admission, OTP, session, refresh-token, login-history, or registration row.
    /// Responses and captured logs never carry the secret, the provider profile, or an internal
    /// failure reason.
    /// </summary>
    [Fact]
    public async Task Reads_ChangeNoStateAndLeakNothing()
    {
        var capture = new CapturingLoggerProvider();
        using var host = _fixture.WithTestServices(services =>
        {
            // The background cleanup legitimately deactivates expired registrations and deletes
            // expired rows of other tests; it must not race the before/after comparison.
            foreach (var worker in services
                         .Where(descriptor => descriptor.ServiceType == typeof(IHostedService)
                                              && descriptor.ImplementationType == typeof(CleanupWorker))
                         .ToList())
            {
                services.Remove(worker);
            }
            services.RemoveAll<ILoggerFactory>();
            services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
            {
                logging.AddProvider(capture);
                logging.SetMinimumLevel(LogLevel.Debug);
            }));
        });
        var app = await SeedAppAsync(host.Services, SmsLoginMode.AutoProvision, OAuthLoginSmsCodeTestSupport.ProfileKey);
        var inactive = await SeedAppAsync(host.Services, SmsLoginMode.AutoProvision, profileKey: null, isActive: false);
        var before = await SnapshotAsync(host.Services, app.Id, inactive.Id);

        var bodies = new List<string>();
        foreach (var (appId, secret, expected) in new (string, string, HttpStatusCode)[]
                 {
                     (app.AppId, app.Secret, HttpStatusCode.OK),
                     (app.AppId, app.Secret, HttpStatusCode.OK),
                     (app.AppId, "wrong-" + app.Secret, HttpStatusCode.Unauthorized),
                     (inactive.AppId, inactive.Secret, HttpStatusCode.Unauthorized),
                     ("unknown-" + Guid.NewGuid().ToString("N")[..12], app.Secret, HttpStatusCode.Unauthorized)
                 })
        {
            using var response = await SendAsync(host, appId, secret);
            Assert.Equal(expected, response.StatusCode);
            bodies.Add(await response.Content.ReadAsStringAsync(Ct));
        }

        Assert.Equal(before, await SnapshotAsync(host.Services, app.Id, inactive.Id));
        Assert.NotEmpty(capture.Messages);
        var forbidden = new[]
        {
            app.Secret, inactive.Secret, OAuthLoginSmsCodeTestSupport.ProfileKey,
            "not registered", "disabled", "expired", "mismatch", "Exception"
        };
        foreach (var body in bodies)
        {
            foreach (var value in forbidden)
            {
                Assert.DoesNotContain(value, body, StringComparison.OrdinalIgnoreCase);
            }
        }

        foreach (var secret in new[] { app.Secret, inactive.Secret })
        {
            Assert.DoesNotContain(capture.Messages, message => message.Contains(secret, StringComparison.Ordinal));
        }
    }

    /// <summary>
    /// A capability answer is UI information, not an authorization: after SMS is turned off, a
    /// fresh SMS code request and an SMS token request — even one carrying a code issued while SMS
    /// was on — both get the existing disabled failure. Turning SMS back on restores the existing
    /// approved/provisioned-account behavior, and another application is never affected.
    /// </summary>
    [Theory]
    [InlineData(SmsLoginMode.AutoProvision)]
    [InlineData(SmsLoginMode.ManualApproval)]
    public async Task DisabledAfterARead_FreshSmsRequestsAreRefused_AndReEnablingRestoresThem(SmsLoginMode enabledMode)
    {
        var sender = new FakeSmsSender();
        using var host = _fixture.CreateSmsHost(sender);
        using var admin = await LoginOnHostAsync(host);
        var app = await SeedAppAsync(host.Services, enabledMode, OAuthLoginSmsCodeTestSupport.ProfileKey);
        var other = await SeedAppAsync(host.Services, enabledMode, OAuthLoginSmsCodeTestSupport.ProfileKey);
        var firstPhone = OAuthLoginSmsCodeTestSupport.NewPhone();
        var secondPhone = OAuthLoginSmsCodeTestSupport.NewPhone();
        var otherPhone = OAuthLoginSmsCodeTestSupport.NewPhone();
        if (enabledMode == SmsLoginMode.ManualApproval)
        {
            await ApproveAsync(admin, app, firstPhone);
            await ApproveAsync(admin, app, secondPhone);
            await ApproveAsync(admin, other, otherPhone);
        }

        using var gateway = CreateClient(host, app.AppId, app.Secret);
        using var otherGateway = CreateClient(host, other.AppId, other.Secret);

        // SMS is on: the read says so, and a code is issued.
        await AssertCapabilitiesAsync(await gateway.GetAsync(Route, Ct), smsLoginEnabled: true);
        await AssertSmsCodeAsync(gateway, firstPhone, success: true, message: "Verification code sent");
        var earlierCode = sender.Calls.Last().Code;

        // The committed change to Disabled is visible to the read and refuses both fresh requests.
        await SetPolicyThroughAdminAsync(admin, app, "Disabled", OAuthLoginSmsCodeTestSupport.ProfileKey);
        await AssertCapabilitiesAsync(await gateway.GetAsync(Route, Ct), smsLoginEnabled: false);
        var sendsBefore = sender.CallCount;
        await AssertSmsCodeAsync(gateway, secondPhone, success: false, message: SmsDisabledMessage);
        Assert.Equal(sendsBefore, sender.CallCount);
        await AssertSmsTokenAsync(gateway, firstPhone, earlierCode, success: false, message: SmsDisabledMessage);

        // The other application keeps its own policy and behavior throughout.
        await AssertCapabilitiesAsync(await otherGateway.GetAsync(Route, Ct), smsLoginEnabled: true);
        await AssertSmsCodeAsync(otherGateway, otherPhone, success: true, message: "Verification code sent");
        await AssertSmsTokenAsync(otherGateway, otherPhone, sender.Calls.Last().Code, success: true, message: "Login successful");

        // Re-enabling restores the existing behavior: the unexpired earlier code and a fresh one
        // both sign in.
        await SetPolicyThroughAdminAsync(admin, app, enabledMode.ToString(), OAuthLoginSmsCodeTestSupport.ProfileKey);
        await AssertCapabilitiesAsync(await gateway.GetAsync(Route, Ct), smsLoginEnabled: true);
        await AssertSmsTokenAsync(gateway, firstPhone, earlierCode, success: true, message: "Login successful");
        await AssertSmsCodeAsync(gateway, secondPhone, success: true, message: "Verification code sent");
        await AssertSmsTokenAsync(gateway, secondPhone, sender.Calls.Last().Code, success: true, message: "Login successful");
        await AssertCapabilitiesAsync(await otherGateway.GetAsync(Route, Ct), smsLoginEnabled: true);
    }

    // ---- helpers ----

    private sealed record SeededApp(Guid Id, string AppId, string Secret);

    private static async Task<SeededApp> SeedAppAsync(
        IServiceProvider services,
        SmsLoginMode mode,
        string? profileKey,
        bool isActive = true,
        DateTimeOffset? callbackExpiresAt = null)
    {
        var appId = "caps-" + Guid.NewGuid().ToString("N")[..16];
        var secret = "caps-secret-" + Guid.NewGuid().ToString("N");
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var entity = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = appId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(secret, 4),
            AppName = "Capability Test App",
            IsActive = isActive,
            CreatedAt = DateTimeOffset.UtcNow,
            CallbackExpiresAt = callbackExpiresAt,
            AudienceMode = AudienceMode.PerApplication,
            SmsLoginMode = mode,
            SmsProfileKey = profileKey
        };
        db.AppRegistrations.Add(entity);
        await db.SaveChangesAsync(Ct);
        return new SeededApp(entity.Id, appId, secret);
    }

    private static HttpClient CreateClient(WebApplicationFactory<Program> host, string? appId, string? secret)
    {
        var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = false
        });
        if (appId is not null)
        {
            http.DefaultRequestHeaders.Add(IdentityHeaders.AppId, appId);
        }
        if (secret is not null)
        {
            http.DefaultRequestHeaders.Add(IdentityHeaders.AppSecret, secret);
        }
        return http;
    }

    private static async Task<HttpResponseMessage> SendAsync(WebApplicationFactory<Program> host, string? appId, string? secret)
    {
        using var http = CreateClient(host, appId, secret);
        return await http.GetAsync(Route, Ct);
    }

    private static Task<HttpResponseMessage> GetCapabilitiesAsync(WebApplicationFactory<Program> host, SeededApp app) =>
        SendAsync(host, app.AppId, app.Secret);

    private static async Task AssertCapabilitiesAsync(HttpResponseMessage response, bool smsLoginEnabled)
    {
        using (response)
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("no-store", string.Join(",", response.Headers.GetValues("Cache-Control")));
            var json = await response.Content.ReadFromJsonAsync<JsonElement>(Ct);
            Assert.Equal(JsonValueKind.Object, json.ValueKind);
            Assert.Equal(
                ["passwordEnabled", "smsLoginEnabled"],
                json.EnumerateObject().Select(property => property.Name));
            Assert.Equal(JsonValueKind.True, json.GetProperty("passwordEnabled").ValueKind);
            Assert.Equal(
                smsLoginEnabled ? JsonValueKind.True : JsonValueKind.False,
                json.GetProperty("smsLoginEnabled").ValueKind);
        }
    }

    private static async Task AssertGenericUnauthorizedAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("no-store", string.Join(",", response.Headers.GetValues("Cache-Control")));
        Assert.Equal(GenericUnauthorizedBody, await response.Content.ReadAsStringAsync(Ct));
    }

    private static async Task SetPolicyThroughAdminAsync(HttpClient admin, SeededApp app, string mode, string? profileKey)
    {
        using var response = await admin.PutAsJsonAsync(
            $"/api/admin/apps/{app.AppId}/sms-policy", new { mode, profileKey }, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static async Task ApproveAsync(HttpClient admin, SeededApp app, string phone)
    {
        using var response = await admin.PostAsJsonAsync($"/api/admin/apps/{app.AppId}/sms-users", new { phone }, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static async Task AssertSmsCodeAsync(HttpClient gateway, string phone, bool success, string message)
    {
        using var response = await gateway.PostAsJsonAsync("/api/auth/sms-code", new { phone }, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(Ct);
        Assert.Equal(success, body.GetProperty("success").GetBoolean());
        Assert.Equal(message, body.GetProperty("message").GetString());
    }

    private static async Task AssertSmsTokenAsync(HttpClient gateway, string phone, string code, bool success, string message)
    {
        using var response = await gateway.PostAsJsonAsync("/api/auth/token", new
        {
            grantType = IdentityConstants.GrantTypeSms,
            phone,
            code
        }, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(Ct);
        Assert.Equal(success, body.GetProperty("success").GetBoolean());
        Assert.Equal(message, body.GetProperty("message").GetString());
        Assert.Equal(success, !string.IsNullOrEmpty(body.GetProperty("accessToken").GetString()));
    }

    /// <summary>Logs the bootstrap administrator in on a specific derived host.</summary>
    private static async Task<HttpClient> LoginOnHostAsync(WebApplicationFactory<Program> host)
    {
        var http = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
        using var login = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
        {
            Content = JsonContent.Create(new
            {
                username = IdentityServerFixture.AdminUsername,
                password = IdentityServerFixture.AdminPassword
            })
        };
        login.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        (await http.SendAsync(login, Ct)).EnsureSuccessStatusCode();
        return http;
    }

    private static async Task<string> IssueIdentityCookieAsync(WebApplicationFactory<Program> host)
    {
        using var scope = host.Services.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        await context.SignInAsync(
            IdentitySessionDefaults.AuthenticationScheme,
            IdentitySessionPrincipal.Create(Guid.NewGuid()));

        var setCookie = Assert.Single(context.Response.Headers["Set-Cookie"].ToArray());
        return setCookie.Split(';')[0];
    }

    /// <summary>
    /// The full contents of every table a capability read must never write, plus the registrations
    /// the read authenticates against, serialized in a stable order so any insert, update, or
    /// delete changes the result.
    /// </summary>
    private static async Task<string> SnapshotAsync(IServiceProvider services, params Guid[] appRegistrationIds)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var options = new JsonSerializerOptions { ReferenceHandler = ReferenceHandler.IgnoreCycles };
        var tables = new Dictionary<string, object>
        {
            ["accounts"] = await db.Accounts.AsNoTracking().OrderBy(row => row.Id).ToListAsync(Ct),
            ["user_logins"] = await db.UserLogins.AsNoTracking().OrderBy(row => row.Id).ToListAsync(Ct),
            ["password_credentials"] = await db.PasswordCredentials.AsNoTracking().OrderBy(row => row.Id).ToListAsync(Ct),
            ["app_sms_accesses"] = await db.AppSmsAccesses.AsNoTracking().OrderBy(row => row.Id).ToListAsync(Ct),
            ["otps"] = await db.Otps.AsNoTracking().OrderBy(row => row.Id).ToListAsync(Ct),
            ["identity_sessions"] = await db.IdentitySessions.AsNoTracking().OrderBy(row => row.Id).ToListAsync(Ct),
            ["refresh_tokens"] = await db.RefreshTokens.AsNoTracking().OrderBy(row => row.Id).ToListAsync(Ct),
            ["login_histories"] = await db.LoginHistories.AsNoTracking().OrderBy(row => row.Id).ToListAsync(Ct),
            ["login_attempts"] = await db.LoginAttempts.AsNoTracking().OrderBy(row => row.Id).ToListAsync(Ct),
            ["app_registrations"] = await db.AppRegistrations.AsNoTracking()
                .Where(row => appRegistrationIds.Contains(row.Id)).OrderBy(row => row.Id).ToListAsync(Ct)
        };
        return JsonSerializer.Serialize(tables, options);
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(Messages);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                messages.Enqueue(formatter(state, exception) + (exception is null ? string.Empty : " " + exception));
        }
    }
}
