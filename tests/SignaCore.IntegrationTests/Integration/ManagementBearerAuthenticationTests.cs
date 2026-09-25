using System.Collections.Concurrent;
using System.Data.Common;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using ServiceMantle.AspNetCore.Management;
using ServiceMantle.Audit;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Host;
using SignaCore.Host.Management;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The management bearer authentication scheme (#384) over the real host: a request to a management
/// route that carries an <c>Authorization</c> header is authenticated by the management bearer only
/// and never falls back to the cookie; the cookie-only routes, the business JWT, OIDC and gateway
/// routes are unchanged; failures answer the fixed 401/503 without the credential; and no carrier
/// ever holds the credential.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class ManagementBearerAuthenticationTests : IClassFixture<IdentityServerFixture>
{
    private const string UnauthenticatedBody = """{"errorCode":"management.bearer.unauthenticated"}""";
    private const string UnavailableBody = """{"errorCode":"management.bearer.unavailable"}""";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly IdentityServerFixture _fixture;

    public ManagementBearerAuthenticationTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task ABearerCredential_AuthenticatesTheSupportedManagementRoutes_AsTheCookieOperator()
    {
        var reads = new SessionReadCounter();
        using var host = CreateHost(services => ReplaceService(services, reads));
        var cookie = await LoginCookieAsync(host);
        var token = await IssueAsync(host, await _fixture.GetAdminAccountIdAsync());

        // The same operator DTO through either credential.
        var bearerMe = await ReadAsync(host, Get("/api/admin/session/me", bearer: token));
        var cookieMe = await ReadAsync(host, Get("/api/admin/session/me", cookie: cookie));
        Assert.Equal(HttpStatusCode.OK, bearerMe.Status);
        Assert.Equal(HttpStatusCode.OK, cookieMe.Status);
        Assert.Equal(cookieMe.Body, bearerMe.Body);

        reads.Reset();
        foreach (var path in new[]
                 {
                     "/api/admin/users",
                     "/management/v1/settings",
                     "/management/v1/settings/definitions",
                     "/management/v1/audit"
                 })
        {
            var response = await ReadAsync(host, Get(path, bearer: token));
            Assert.True(response.Status == HttpStatusCode.OK, $"{path} answered {(int)response.Status}");
        }

        // Every request validated its credential exactly once, even where the default
        // authentication and the policy authentication both resolve the bearer.
        Assert.Equal(4, reads.Count);

        // A write through each credential records the same operator.
        var bearerUser = await CreateUserAsync(host, bearer: token);
        var cookieUser = await CreateUserAsync(host, cookie: cookie);
        var rows = await LoadAuditRowsAsync();
        var bearerRow = Assert.Single(rows, row => row.Action == "account_created" && row.TargetId == bearerUser);
        var cookieRow = Assert.Single(rows, row => row.Action == "account_created" && row.TargetId == cookieUser);
        Assert.Equal(cookieRow.OperatorId, bearerRow.OperatorId);
        Assert.Equal(cookieRow.OperatorDisplayName, bearerRow.OperatorDisplayName);
        Assert.Equal(cookieRow.OperatorSource, bearerRow.OperatorSource);
        Assert.Equal((await _fixture.GetAdminAccountIdAsync()).ToString(), bearerRow.OperatorId);
    }

    [Fact]
    public async Task TheCookieOnlyRoutes_IgnoreTheAuthorizationHeader()
    {
        using var host = CreateHost();
        var cookie = await LoginCookieAsync(host);
        var token = await IssueAsync(host, await _fixture.GetAdminAccountIdAsync());

        foreach (var request in CookieOnlyRequests())
        {
            var bearerOnly = await ReadAsync(host, request(token, null));
            Assert.Equal(HttpStatusCode.Unauthorized, bearerOnly.Status);
            Assert.DoesNotContain(token, bearerOnly.Body, StringComparison.Ordinal);
        }

        // The cookie keeps working on the cookie-only reads, with or without a header next to it.
        foreach (var path in new[] { "/management/v1/session", "/api/admin/bootstrap" })
        {
            Assert.Equal(HttpStatusCode.OK, (await ReadAsync(host, Get(path, cookie: cookie))).Status);
            Assert.Equal(HttpStatusCode.OK, (await ReadAsync(host, Get(path, cookie: cookie, bearer: "not-a-credential"))).Status);
        }
    }

    [Fact]
    public async Task EveryRejectedCredential_Answers401_AndNeverFallsBackToTheCookie()
    {
        using var host = CreateHost();
        var cookie = await LoginCookieAsync(host);
        var adminId = await _fixture.GetAdminAccountIdAsync();
        var revoked = await IssueAsync(host, adminId);
        Assert.Equal(ManagementBearerRevocationResult.Revoked, await Service(host).RevokeAsync(revoked, Ct));
        var expired = await IssueAsync(host, adminId);
        await ExpireAsync(expired);
        var notAdmin = await IssueAsync(host, await SeedAccountAsync());

        var headers = new Dictionary<string, StringValues>
        {
            ["garbage"] = "Bearer not-a-credential",
            ["unknown"] = "Bearer " + ManagementBearerToken.Generate(),
            ["revoked"] = "Bearer " + revoked,
            ["expired"] = "Bearer " + expired,
            ["not-admin"] = "Bearer " + notAdmin,
            ["lowercase-prefix-garbage"] = "bearer x",
            ["basic"] = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:password")),
            ["empty"] = string.Empty,
            ["whitespace"] = " ",
            ["two-values"] = new StringValues(["Bearer " + revoked, "Bearer " + revoked])
        };

        foreach (var (name, header) in headers)
        {
            foreach (var path in new[] { "/api/admin/users", "/management/v1/settings", "/api/admin/session/me" })
            {
                // Injected on the server side: an HttpClient drops empty header values in transit.
                var context = await SendRawAsync(host, "GET", path, header, cookie);
                Assert.True(
                    context.Response.StatusCode == StatusCodes.Status401Unauthorized,
                    $"{name} on {path} answered {context.Response.StatusCode}");
                Assert.Equal("no-store", context.Response.Headers.CacheControl.ToString());
                var body = await ReadBodyAsync(context);
                Assert.Equal(UnauthenticatedBody, body);
            }
        }

        // The same valid cookie without any header still authenticates.
        Assert.Equal(HttpStatusCode.OK, (await ReadAsync(host, Get("/api/admin/users", cookie: cookie))).Status);
    }

    [Fact]
    public async Task ABearerCredential_IsRefusedOutsideTheManagementRoutes()
    {
        using var host = CreateHost();
        var token = await IssueAsync(host, await _fixture.GetAdminAccountIdAsync());

        foreach (var path in new[] { "/api/profile/me", "/oauth2/userinfo", "/api/gateway/users/search?keyword=x" })
        {
            var response = await ReadAsync(host, Get(path, bearer: token));
            Assert.True(response.Status == HttpStatusCode.Unauthorized, $"{path} answered {(int)response.Status}");
            Assert.DoesNotContain(token, response.Body, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task AnUnavailableStore_Answers503_AndNeverFallsBackToTheCookie()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}", "bearer.db");
        using var host = CreateHost(services => services.Replace(ServiceDescriptor.Singleton(serviceProvider =>
            new ManagementBearerSessionService(
                new DatabaseOptions { Provider = "SQLite", ConnectionString = $"Data Source={missing};Pooling=false" },
                serviceProvider.GetRequiredService<AdminIdentityOptions>(),
                serviceProvider.GetRequiredService<IManagementBearerSessionRepository>(),
                serviceProvider.GetRequiredService<TimeProvider>(),
                serviceProvider.GetRequiredService<ILogger<ManagementBearerSessionService>>()))));
        var cookie = await LoginCookieAsync(host);
        var token = ManagementBearerToken.Generate();

        foreach (var path in new[] { "/api/admin/users", "/management/v1/settings" })
        {
            var response = await ReadAsync(host, Get(path, bearer: token, cookie: cookie));
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.Status);
            Assert.Equal("no-store", response.CacheControl);
            Assert.Equal(UnavailableBody, response.Body);
        }
    }

    [Fact]
    public async Task CallerCancellation_PropagatesInsteadOfAnswering401Or503()
    {
        var gate = new BlockingSessionRead();
        var outcome = new PipelineOutcome();
        using var host = CreateHost(services =>
        {
            ReplaceService(services, gate);
            services.AddSingleton<IStartupFilter>(new OutcomeStartupFilter(outcome));
        });
        var token = await IssueAsync(host, await _fixture.GetAdminAccountIdAsync());
        using var client = Client(host);
        using var caller = CancellationTokenSource.CreateLinkedTokenSource(Ct);

        var pending = client.SendAsync(Get("/api/admin/users", bearer: token), caller.Token);
        await gate.Entered.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        await caller.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        // The handler rethrows the caller's cancellation; the host's existing canceled-request
        // path ends the request without writing anything. A handler that turned the cancellation
        // into a rejection would have written its 401 or 503 challenge.
        var (exception, started, status) = await outcome.Completed.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        Assert.True(exception is null or OperationCanceledException, exception?.GetType().Name);
        Assert.False(started);
        Assert.NotEqual(StatusCodes.Status401Unauthorized, status);
        Assert.NotEqual(StatusCodes.Status503ServiceUnavailable, status);
    }

    [Fact]
    public async Task TheHostDefaults_AreTheSelector_AndSignInStaysOnTheCookie()
    {
        using var host = CreateHost();
        using var _ = Client(host);
        var schemes = host.Services.GetRequiredService<IAuthenticationSchemeProvider>();

        Assert.Equal(ManagementBearerAuthenticationDefaults.SelectorScheme, (await schemes.GetDefaultAuthenticateSchemeAsync())!.Name);
        Assert.Equal(ManagementBearerAuthenticationDefaults.SelectorScheme, (await schemes.GetDefaultChallengeSchemeAsync())!.Name);
        Assert.Equal(ManagementBearerAuthenticationDefaults.SelectorScheme, (await schemes.GetDefaultForbidSchemeAsync())!.Name);
        Assert.Equal(ManagementSessionDefaults.AuthenticationScheme, (await schemes.GetDefaultSignInSchemeAsync())!.Name);
        Assert.Equal(ManagementSessionDefaults.AuthenticationScheme, (await schemes.GetDefaultSignOutSchemeAsync())!.Name);

        // The shared admin policy names no scheme of its own; it follows the host default.
        var admin = await host.Services.GetRequiredService<IAuthorizationPolicyProvider>()
            .GetPolicyAsync(ManagementAuthorizationDefaults.AdminPolicyName);
        Assert.Empty(admin!.AuthenticationSchemes);
    }

    [Fact]
    public async Task AddingASchemeToTheSharedAdminPolicy_FailsTheHostStartup()
    {
        using var host = CreateHost(services =>
            services.PostConfigure<AuthorizationOptions>(options =>
            {
                var shared = options.GetPolicy(ManagementAuthorizationDefaults.AdminPolicyName)!;
                options.AddPolicy(
                    ManagementAuthorizationDefaults.AdminPolicyName,
                    new AuthorizationPolicyBuilder(shared)
                        .AddAuthenticationSchemes(ManagementBearerAuthenticationDefaults.SelectorScheme)
                        .Build());
            }));

        // ServiceMantle pins the bootstrap update entry to the management cookie alone.
        var failure = Assert.ThrowsAny<Exception>(() => host.CreateClient());
        Assert.Contains(
            "management entry mapping is invalid",
            failure.ToString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task NoCarrier_HoldsTheCredential()
    {
        var logs = new ConcurrentQueue<string>();
        using var host = CreateHost(services =>
        {
            services.RemoveAll<ILoggerFactory>();
            services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
                logging.SetMinimumLevel(LogLevel.Trace).AddProvider(new CaptureLoggerProvider(logs))));
        });
        var token = await IssueAsync(host, await _fixture.GetAdminAccountIdAsync());
        var carriers = new List<string>();
        var tagValues = new ConcurrentQueue<string>();
        using var _ = Client(host);
        var meterScope = host.Services.GetRequiredService<System.Diagnostics.Metrics.IMeterFactory>();
        using var meters = new System.Diagnostics.Metrics.MeterListener();
        meters.InstrumentPublished = (instrument, listener) =>
        {
            if (ReferenceEquals(instrument.Meter.Scope, meterScope))
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };
        meters.SetMeasurementEventCallback<long>((_, _, tags, _) => RecordTags(tags, tagValues));
        meters.SetMeasurementEventCallback<double>((_, _, tags, _) => RecordTags(tags, tagValues));
        meters.SetMeasurementEventCallback<int>((_, _, tags, _) => RecordTags(tags, tagValues));
        meters.Start();

        // Success, a write with its audit row, a rejected credential, and a revoked one.
        carriers.Add((await ReadAsync(host, Get("/api/admin/users", bearer: token))).Describe());
        var created = await CreateUserAsync(host, bearer: token);
        carriers.Add((await ReadAsync(host, Get("/api/admin/users", bearer: token + "x"))).Describe());
        Assert.Equal(ManagementBearerRevocationResult.Revoked, await Service(host).RevokeAsync(token, Ct));
        carriers.Add((await ReadAsync(host, Get("/management/v1/settings", bearer: token))).Describe());
        carriers.Add((await ReadAsync(host, Get("/api/admin/session/me", bearer: token))).Describe());

        carriers.AddRange(logs);
        Assert.NotEmpty(tagValues);
        carriers.AddRange(tagValues);
        carriers.AddRange((await LoadAuditRowsAsync()).Select(row => JsonSerializer.Serialize(row)));
        await using (var scope = host.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            carriers.AddRange(await SharedSettingTestDatabase.LoadSharedAuditJsonAsync(db, Ct));
        }

        Assert.Contains(carriers, value => value.Contains(created, StringComparison.Ordinal));
        AssertNoCanary(carriers, token, token[..16], token[^16..]);
    }

    [Fact]
    public void TheCanaryScanner_FindsAPlantedCanary()
    {
        var canary = ManagementBearerToken.Generate();
        Assert.ThrowsAny<Exception>(() => AssertNoCanary(["Authorization: Bearer " + canary], canary));
        Assert.ThrowsAny<Exception>(() => AssertNoCanary([canary.ToUpperInvariant()], canary));
        AssertNoCanary(["nothing to see"], canary);
    }

    // ---- Helpers ----

    private WebApplicationFactory<Program> CreateHost(Action<IServiceCollection>? configure = null) =>
        _fixture.WithTestServices(services => configure?.Invoke(services));

    private static HttpClient Client(WebApplicationFactory<Program> host) =>
        host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = false
        });

    private static ManagementBearerSessionService Service(WebApplicationFactory<Program> host) =>
        host.Services.GetRequiredService<ManagementBearerSessionService>();

    private static async Task<string> IssueAsync(WebApplicationFactory<Program> host, Guid accountId)
    {
        var issued = await Service(host).IssueAsync(accountId, Ct);
        Assert.Equal(ManagementBearerIssueStatus.Issued, issued.Status);
        return issued.Token!;
    }

    private static async Task<string> LoginCookieAsync(WebApplicationFactory<Program> host)
    {
        using var client = Client(host);
        using var login = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
        {
            Content = JsonContent.Create(new
            {
                username = IdentityServerFixture.AdminUsername,
                password = IdentityServerFixture.AdminPassword
            })
        };
        login.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        using var response = await client.SendAsync(login, Ct);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(response.Headers.NonValidated.TryGetValues("Set-Cookie", out var cookies));
        return cookies
            .Single(value => value.StartsWith($"{ManagementSessionDefaults.CookieName}=", StringComparison.Ordinal))
            .Split(';')[0];
    }

    private static HttpRequestMessage Get(string path, string? bearer = null, string? cookie = null) =>
        Request(HttpMethod.Get, path, bearer, cookie);

    private static HttpRequestMessage Request(HttpMethod method, string path, string? bearer, string? cookie)
    {
        var request = new HttpRequestMessage(method, path);
        if (bearer is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        }

        if (cookie is not null)
        {
            request.Headers.TryAddWithoutValidation("Cookie", cookie);
        }

        request.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        return request;
    }

    /// <summary>The four cookie-only entries, each built for a bearer and/or a cookie.</summary>
    private static IEnumerable<Func<string?, string?, HttpRequestMessage>> CookieOnlyRequests()
    {
        yield return (bearer, cookie) => Get("/management/v1/session", bearer, cookie);
        yield return (bearer, cookie) =>
        {
            var request = Request(HttpMethod.Put, "/management/v1/bootstrap", bearer, cookie);
            request.Content = JsonContent.Create(new { });
            return request;
        };
        yield return (bearer, cookie) => Get("/api/admin/bootstrap", bearer, cookie);
        yield return (bearer, cookie) =>
        {
            var request = Request(HttpMethod.Post, "/api/admin/bootstrap/test", bearer, cookie);
            request.Content = JsonContent.Create(new { });
            return request;
        };
    }

    private sealed record Answer(HttpStatusCode Status, string Body, string CacheControl, string Headers)
    {
        public string Describe() => $"{(int)Status} {Headers} {Body}";
    }

    private static async Task<Answer> ReadAsync(WebApplicationFactory<Program> host, HttpRequestMessage request)
    {
        using var client = Client(host);
        using (request)
        using (var response = await client.SendAsync(request, Ct))
        {
            var headers = string.Join('\n', response.Headers.Concat(response.Content.Headers)
                .Select(header => $"{header.Key}: {string.Join(',', header.Value)}"));
            return new Answer(
                response.StatusCode,
                await response.Content.ReadAsStringAsync(Ct),
                response.Headers.CacheControl?.ToString() ?? string.Empty,
                headers);
        }
    }

    private static async Task<HttpContext> SendRawAsync(
        WebApplicationFactory<Program> host,
        string method,
        string path,
        StringValues authorization,
        string cookie)
    {
        using var _ = Client(host);
        return await host.Server.SendAsync(context =>
        {
            context.Request.Method = method;
            context.Request.Scheme = "https";
            context.Request.Host = new HostString("localhost");
            context.Request.Path = path;
            context.Request.Headers.Authorization = authorization;
            context.Request.Headers.Cookie = cookie;
        }, Ct);
    }

    private static async Task<string> ReadBodyAsync(HttpContext context)
    {
        using var reader = new StreamReader(context.Response.Body);
        return await reader.ReadToEndAsync(Ct);
    }

    private static async Task<string> CreateUserAsync(
        WebApplicationFactory<Program> host,
        string? bearer = null,
        string? cookie = null)
    {
        var request = Request(HttpMethod.Post, "/api/admin/users", bearer, cookie);
        request.Content = JsonContent.Create(new
        {
            username = $"bearer_user_{Guid.NewGuid():N}",
            password = "Bearer-Scheme-123!"
        });
        var response = await ReadAsync(host, request);
        Assert.True(response.Status == HttpStatusCode.OK, $"create user answered {(int)response.Status}: {response.Body}");
        return JsonDocument.Parse(response.Body).RootElement.GetProperty("userId").GetString()!;
    }

    private async Task<List<SharedSettingTestDatabase.SharedAuditRow>> LoadAuditRowsAsync()
    {
        using var scope = _fixture.Services.CreateScope();
        return await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
            scope.ServiceProvider.GetRequiredService<IdentityDbContext>(), Ct);
    }

    private async Task ExpireAsync(string token)
    {
        using var scope = _fixture.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var digest = ManagementBearerToken.ComputeDigest(token);
        var session = await db.ManagementBearerSessions.SingleAsync(row => row.TokenDigest == digest, Ct);
        session.CreatedAt = DateTimeOffset.UtcNow.AddHours(-2);
        session.ExpiresAt = DateTimeOffset.UtcNow.AddHours(-1);
        await db.SaveChangesAsync(Ct);
    }

    private async Task<Guid> SeedAccountAsync()
    {
        var accountId = Guid.NewGuid();
        await _fixture.SeedGatewayUserAsync(
            accountId,
            $"bearer_other_{Guid.NewGuid():N}",
            $"139{Random.Shared.Next(10_000_000, 99_999_999)}",
            remark: null);
        return accountId;
    }

    /// <summary>Replaces the host's service with one whose per-operation context carries an interceptor.</summary>
    private static void ReplaceService(IServiceCollection services, IInterceptor interceptor) =>
        services.Replace(ServiceDescriptor.Singleton(serviceProvider => new ManagementBearerSessionService(
            serviceProvider.GetRequiredService<DatabaseOptions>(),
            serviceProvider.GetRequiredService<AdminIdentityOptions>(),
            serviceProvider.GetRequiredService<IManagementBearerSessionRepository>(),
            serviceProvider.GetRequiredService<TimeProvider>(),
            serviceProvider.GetRequiredService<ILogger<ManagementBearerSessionService>>(),
            builder => builder.AddInterceptors(interceptor))));

    private static bool ReadsSessions(DbCommand command) =>
        command.CommandText.TrimStart().StartsWith("SELECT", StringComparison.OrdinalIgnoreCase)
        && command.CommandText.Contains("management_bearer_sessions", StringComparison.Ordinal);

    private static void RecordTags(ReadOnlySpan<KeyValuePair<string, object?>> tags, ConcurrentQueue<string> values)
    {
        foreach (var tag in tags)
        {
            values.Enqueue($"{tag.Key}={tag.Value}");
        }
    }

    private static void AssertNoCanary(IReadOnlyCollection<string> values, params string[] canaries)
    {
        var index = 0;
        foreach (var value in values)
        {
            for (var c = 0; c < canaries.Length; c++)
            {
                if (value.Contains(canaries[c], StringComparison.OrdinalIgnoreCase))
                {
                    Assert.Fail($"Scanned value #{index} contains canary #{c}.");
                }
            }

            index++;
        }
    }

    /// <summary>Counts the credential lookups: one per validation.</summary>
    private sealed class SessionReadCounter : DbCommandInterceptor
    {
        private int _count;

        public int Count => Volatile.Read(ref _count);

        public void Reset() => Interlocked.Exchange(ref _count, 0);

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            if (ReadsSessions(command))
            {
                Interlocked.Increment(ref _count);
            }

            return ValueTask.FromResult(result);
        }
    }

    /// <summary>Holds the credential lookup until the caller cancels.</summary>
    private sealed class BlockingSessionRead : DbCommandInterceptor
    {
        private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task Entered => _entered.Task;

        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            if (ReadsSessions(command))
            {
                _entered.TrySetResult();
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }

            return result;
        }
    }

    /// <summary>What left the pipeline: an exception, and whether a response had started.</summary>
    private sealed class PipelineOutcome
    {
        private readonly TaskCompletionSource<(Exception?, bool, int)> _completed =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<(Exception? Exception, bool Started, int Status)> Completed => _completed.Task;

        public void Record(Exception? exception, HttpResponse response) =>
            _completed.TrySetResult((exception, response.HasStarted, response.StatusCode));
    }

    private sealed class OutcomeStartupFilter(PipelineOutcome outcome) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, following) =>
            {
                if (!context.Request.Path.StartsWithSegments("/api/admin/users"))
                {
                    await following(context);
                    return;
                }

                try
                {
                    await following(context);
                    outcome.Record(null, context.Response);
                }
                catch (Exception exception)
                {
                    outcome.Record(exception, context.Response);
                    throw;
                }
            });
            next(app);
        };
    }

    private sealed class CaptureLoggerProvider(ConcurrentQueue<string> lines) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new CaptureLogger(lines, categoryName);

        public void Dispose()
        {
        }

        private sealed class CaptureLogger(ConcurrentQueue<string> lines, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var properties = state is IEnumerable<KeyValuePair<string, object?>> pairs
                    ? string.Join(' ', pairs.Select(pair => $"{pair.Key}={pair.Value}"))
                    : string.Empty;
                lines.Enqueue($"{category} {formatter(state, exception)} {properties} {exception}");
            }
        }
    }
}
