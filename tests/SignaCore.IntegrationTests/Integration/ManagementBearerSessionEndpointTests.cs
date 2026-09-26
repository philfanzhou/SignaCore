using System.Collections.Concurrent;
using System.Data.Common;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using ServiceMantle.AspNetCore.Management;
using ServiceMantle.Management;
using SignaCore.Database;
using SignaCore.Database.Repositories;
using SignaCore.Host;
using SignaCore.Host.Management;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The explicit management bearer session entries (#392) over the real host: login issues a fixed
/// three-field credential only after the shared management login chain authenticated the bootstrap
/// administrator, every malformed request is a fixed 400 before authentication, failures are
/// indistinguishable, the budget and caller cancellation never hand out a credential, and logout
/// revokes exactly the bearer that authenticated it.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class ManagementBearerSessionEndpointTests : IClassFixture<IdentityServerFixture>
{
    private const string LoginPath = "/api/admin/session/bearer/login";
    private const string LogoutPath = "/api/admin/session/bearer/logout";
    private const string InvalidRequestBody = """{"errorCode":"management.request.invalid"}""";
    private const string UnauthenticatedBody = """{"errorCode":"management.session.unauthenticated"}""";
    private const string UnavailableBody = """{"errorCode":"management.session.unavailable"}""";
    private const string BearerUnauthenticatedBody = """{"errorCode":"management.bearer.unauthenticated"}""";
    private const string BearerUnavailableBody = """{"errorCode":"management.bearer.unavailable"}""";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly IdentityServerFixture _fixture;

    public ManagementBearerSessionEndpointTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- Login success, use, and logout ----

    [Fact]
    public async Task Login_IssuesAFixedCredential_ThatAuthorizesTheAdminApi_UntilLogoutRevokesIt()
    {
        using var host = CreateHost();
        var before = await CountBearerRowsAsync();

        var login = await SendAsync(host, LoginRequest(IdentityServerFixture.AdminUsername, IdentityServerFixture.AdminPassword));

        Assert.Equal(HttpStatusCode.OK, login.Status);
        Assert.Equal("no-store", login.CacheControl);
        Assert.StartsWith("application/json", login.ContentType, StringComparison.Ordinal);
        Assert.DoesNotContain("Set-Cookie", login.Headers, StringComparison.OrdinalIgnoreCase);
        using var document = JsonDocument.Parse(login.Body);
        Assert.Equal(
            ["accessToken", "expiresAtUtc", "tokenType"],
            document.RootElement.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal));
        Assert.Equal("Bearer", document.RootElement.GetProperty("tokenType").GetString());
        var expires = document.RootElement.GetProperty("expiresAtUtc").GetDateTimeOffset();
        Assert.InRange(expires - DateTimeOffset.UtcNow, TimeSpan.FromMinutes(14), TimeSpan.FromMinutes(15.5));
        var token = document.RootElement.GetProperty("accessToken").GetString()!;
        Assert.Equal(before + 1, await CountBearerRowsAsync());

        Assert.Equal(HttpStatusCode.OK, (await SendAsync(host, Get("/api/admin/users", bearer: token))).Status);

        var logout = await SendAsync(host, LogoutRequest(token));
        Assert.Equal(HttpStatusCode.NoContent, logout.Status);
        Assert.Equal("no-store", logout.CacheControl);
        Assert.Empty(logout.Body);

        var after = await SendAsync(host, Get("/api/admin/users", bearer: token));
        Assert.Equal(HttpStatusCode.Unauthorized, after.Status);
        var again = await SendAsync(host, LogoutRequest(token));
        Assert.Equal(HttpStatusCode.Unauthorized, again.Status);
        Assert.Equal(BearerUnauthenticatedBody, again.Body);
    }

    [Theory]
    [InlineData("authorization")]
    [InlineData("cookie")]
    public async Task Login_IgnoresAnyAccompanyingCredential(string accompanying)
    {
        using var host = CreateHost();
        var cookie = accompanying == "cookie" ? await LoginCookieAsync(host) : null;
        var request = LoginRequest(IdentityServerFixture.AdminUsername, IdentityServerFixture.AdminPassword);
        if (accompanying == "authorization")
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "not-a-real-credential");
        }
        else
        {
            request.Headers.TryAddWithoutValidation("Cookie", cookie);
        }

        var response = await SendAsync(host, request);

        Assert.Equal(HttpStatusCode.OK, response.Status);
        Assert.DoesNotContain("Set-Cookie", response.Headers, StringComparison.OrdinalIgnoreCase);
        if (cookie is not null)
        {
            // The cookie session was neither renewed nor revoked.
            Assert.Equal(HttpStatusCode.OK, (await SendAsync(host, Get("/management/v1/session", cookie: cookie))).Status);
        }
    }

    // ---- Input ----

    public static TheoryData<string> MalformedRequests => new()
    {
        "no-unsafe-header",
        "wrong-unsafe-header",
        "two-unsafe-headers",
        "text-plain",
        "latin1-charset",
        "query-string",
        "content-encoding",
        "declared-oversize",
        "chunked-oversize",
        "bad-json",
        "array-root",
        "number-username",
    };

    [Theory]
    [MemberData(nameof(MalformedRequests))]
    public async Task Login_MalformedRequests_AreAFixed400BeforeAuthentication(string shape)
    {
        var counter = new ProviderCounter();
        using var host = CreateHost(services => CountProvider(services, counter));
        var before = await CountBearerRowsAsync();

        var response = await SendAsync(host, Malformed(shape));

        Assert.Equal(HttpStatusCode.BadRequest, response.Status);
        Assert.Equal(InvalidRequestBody, response.Body);
        Assert.Equal("no-store", response.CacheControl);
        Assert.Equal(0, counter.Calls);
        Assert.Equal(before, await CountBearerRowsAsync());
    }

    // ---- Authentication ----

    [Fact]
    public async Task Login_WrongPasswordAndNonAdministrator_AreIndistinguishable()
    {
        using var host = CreateHost();
        var other = $"bearer_other_{Guid.NewGuid():N}";
        await _fixture.SeedGatewayUserAsync(Guid.NewGuid(), other, $"138{Random.Shared.Next(10_000_000, 99_999_999)}", remark: null);
        var before = await CountBearerRowsAsync();

        var wrongPassword = await SendAsync(host, LoginRequest(IdentityServerFixture.AdminUsername, "Wrong-Password-1"));
        var nonAdministrator = await SendAsync(host, LoginRequest(other, "SecurePassword123!"));

        foreach (var response in new[] { wrongPassword, nonAdministrator })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
            Assert.Equal(UnauthenticatedBody, response.Body);
            Assert.Equal("no-store", response.CacheControl);
            Assert.DoesNotContain("WWW-Authenticate", response.Headers, StringComparison.OrdinalIgnoreCase);
        }

        Assert.Equal(StripVolatile(wrongPassword.Headers), StripVolatile(nonAdministrator.Headers));
        Assert.Equal(before, await CountBearerRowsAsync());
    }

    [Fact]
    public async Task Login_RecordsTheSameLoginAttemptAsTheCookieLogin()
    {
        using var host = CreateHost();
        var cookieName = $"unknown_{Guid.NewGuid():N}";
        var bearerName = $"unknown_{Guid.NewGuid():N}";

        using (var client = Client(host))
        using (var cookieLogin = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
               {
                   Content = JsonContent.Create(new { username = cookieName, password = "Wrong-Password-1" })
               })
        {
            cookieLogin.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
            using var _ = await client.SendAsync(cookieLogin, Ct);
        }

        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(host, LoginRequest(bearerName, "Wrong-Password-1"))).Status);

        var cookieRows = await LoginHistoryAsync(cookieName);
        var bearerRows = await LoginHistoryAsync(bearerName);
        var cookieRow = Assert.Single(cookieRows);
        var bearerRow = Assert.Single(bearerRows);
        Assert.Equal((cookieRow.EventType, cookieRow.FailureReason, cookieRow.AuthMethod),
            (bearerRow.EventType, bearerRow.FailureReason, bearerRow.AuthMethod));
    }

    [Fact]
    public async Task Login_SharesTheSetupRateLimitBudgetWithTheCookieLogin()
    {
        using var host = CreateHost();
        using var client = Client(host);
        var statuses = new List<HttpStatusCode>();
        for (var attempt = 0; attempt < 6; attempt++)
        {
            // Throwaway usernames: the budget is per source address, and repeated failures against
            // the bootstrap administrator would lock it out for the rest of the class.
            var username = $"unknown_{Guid.NewGuid():N}";
            using var request = attempt % 2 == 0
                ? LoginRequest(username, "Wrong-Password-1")
                : CookieLoginRequest(username, "Wrong-Password-1");
            using var response = await client.SendAsync(request, Ct);
            statuses.Add(response.StatusCode);
        }

        Assert.All(statuses.Take(5), status => Assert.Equal(HttpStatusCode.Unauthorized, status));
        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[^1]);
    }

    // ---- Storage failure, budget, and cancellation ----

    [Fact]
    public async Task Login_IssuanceStorageFailure_Is503WithoutACredential()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}", "bearer.db");
        using var host = CreateHost(services => services.Replace(ServiceDescriptor.Singleton(serviceProvider =>
            new ManagementBearerSessionService(
                new DatabaseOptions { Provider = "SQLite", ConnectionString = $"Data Source={missing};Pooling=false" },
                serviceProvider.GetRequiredService<AdminIdentityOptions>(),
                serviceProvider.GetRequiredService<IManagementBearerSessionRepository>(),
                serviceProvider.GetRequiredService<TimeProvider>(),
                serviceProvider.GetRequiredService<ILogger<ManagementBearerSessionService>>()))));

        var response = await SendAsync(host, LoginRequest(IdentityServerFixture.AdminUsername, IdentityServerFixture.AdminPassword));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.Status);
        Assert.Equal(UnavailableBody, response.Body);
        Assert.Equal("no-store", response.CacheControl);
    }

    [Fact]
    public async Task Login_ExceedingTheBudget_Is503WithoutACredential()
    {
        using var host = CreateHost(services =>
            services.Replace(ServiceDescriptor.Scoped<IManagementIdentityProvider, NeverAnsweringProvider>()));
        var before = await CountBearerRowsAsync();

        var started = DateTimeOffset.UtcNow;
        var response = await SendAsync(host, LoginRequest(IdentityServerFixture.AdminUsername, IdentityServerFixture.AdminPassword));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.Status);
        Assert.Equal(UnavailableBody, response.Body);
        Assert.InRange(DateTimeOffset.UtcNow - started, TimeSpan.FromSeconds(9), TimeSpan.FromSeconds(30));
        Assert.Equal(before, await CountBearerRowsAsync());
    }

    [Fact]
    public async Task Login_CallerCancellation_PropagatesWithoutACredential()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var host = CreateHost(services => services.Replace(ServiceDescriptor.Scoped<IManagementIdentityProvider>(
            _ => new NeverAnsweringProvider(entered))));
        var before = await CountBearerRowsAsync();
        using var client = Client(host);
        using var abort = new CancellationTokenSource();

        var pending = client.SendAsync(
            LoginRequest(IdentityServerFixture.AdminUsername, IdentityServerFixture.AdminPassword),
            abort.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), Ct);
        await abort.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await pending);
        Assert.Equal(before, await CountBearerRowsAsync());
    }

    // ---- Logout ----

    [Fact]
    public async Task Logout_RequiresTheBearerScheme_AndTheUnsafeHeaderBeforeRevoking()
    {
        using var host = CreateHost();
        var cookie = await LoginCookieAsync(host);
        var token = await LoginBearerAsync(host);

        var cookieOnly = await SendAsync(host, Post(LogoutPath, cookie: cookie));
        Assert.Equal(HttpStatusCode.Unauthorized, cookieOnly.Status);
        Assert.Equal(BearerUnauthenticatedBody, cookieOnly.Body);
        Assert.Contains("WWW-Authenticate: Bearer", cookieOnly.Headers, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(host, Get("/management/v1/session", cookie: cookie))).Status);

        foreach (var header in new[] { null, "2" })
        {
            var missing = await SendAsync(host, Post(LogoutPath, bearer: token, unsafeHeader: header));
            Assert.Equal(HttpStatusCode.BadRequest, missing.Status);
            Assert.Equal(InvalidRequestBody, missing.Body);
        }

        Assert.Equal(HttpStatusCode.OK, (await SendAsync(host, Get("/api/admin/users", bearer: token))).Status);
    }

    [Fact]
    public async Task Logout_TwoConcurrentRevocations_ExactlyOneSucceeds()
    {
        using var host = CreateHost();
        var token = await LoginBearerAsync(host);

        var answers = await Task.WhenAll(
            Enumerable.Range(0, 2).Select(_ => Task.Run(() => SendAsync(host, LogoutRequest(token)), Ct)));

        Assert.Single(answers, answer => answer.Status == HttpStatusCode.NoContent);
        var loser = Assert.Single(answers, answer => answer.Status == HttpStatusCode.Unauthorized);
        Assert.Equal(BearerUnauthenticatedBody, loser.Body);
    }

    [Fact]
    public async Task Logout_AnExpiredCredential_Is401()
    {
        using var host = CreateHost();
        var token = await LoginBearerAsync(host);
        await ExpireAsync(token);

        var response = await SendAsync(host, LogoutRequest(token));

        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal(BearerUnauthenticatedBody, response.Body);
    }

    [Fact]
    public async Task Logout_RevocationStorageFailure_Is503()
    {
        using var host = CreateHost(services => services.Replace(ServiceDescriptor.Singleton(serviceProvider =>
            new ManagementBearerSessionService(
                serviceProvider.GetRequiredService<DatabaseOptions>(),
                serviceProvider.GetRequiredService<AdminIdentityOptions>(),
                serviceProvider.GetRequiredService<IManagementBearerSessionRepository>(),
                serviceProvider.GetRequiredService<TimeProvider>(),
                serviceProvider.GetRequiredService<ILogger<ManagementBearerSessionService>>(),
                builder => builder.AddInterceptors(new FailingRevocation())))));
        var token = await LoginBearerAsync(host);

        var response = await SendAsync(host, LogoutRequest(token));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.Status);
        Assert.Equal(BearerUnavailableBody, response.Body);
        Assert.Equal("no-store", response.CacheControl);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(host, Get("/api/admin/users", bearer: token))).Status);
    }

    // ---- Sensitive carriers ----

    [Fact]
    public async Task NoCarrier_HoldsThePasswordOrTheCredential()
    {
        var logs = new ConcurrentQueue<string>();
        var tags = new ConcurrentQueue<string>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) => meterListener.EnableMeasurementEvents(instrument);
        listener.SetMeasurementEventCallback<int>((_, _, measurementTags, _) => RecordTags(measurementTags, tags));
        listener.SetMeasurementEventCallback<long>((_, _, measurementTags, _) => RecordTags(measurementTags, tags));
        listener.SetMeasurementEventCallback<double>((_, _, measurementTags, _) => RecordTags(measurementTags, tags));
        listener.Start();
        using var host = CreateHost(services =>
        {
            services.RemoveAll<ILoggerFactory>();
            services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
            {
                logging.AddProvider(new CaptureLoggerProvider(logs));
                logging.SetMinimumLevel(LogLevel.Trace);
            }));
        });
        var wrongPassword = "Canary-Password-" + Guid.NewGuid().ToString("N");

        var carriers = new List<string>();
        var failed = await SendAsync(host, LoginRequest(IdentityServerFixture.AdminUsername, wrongPassword));
        var issued = await SendAsync(host, LoginRequest(IdentityServerFixture.AdminUsername, IdentityServerFixture.AdminPassword));
        var token = JsonDocument.Parse(issued.Body).RootElement.GetProperty("accessToken").GetString()!;
        var used = await SendAsync(host, Get("/api/admin/users", bearer: token));
        var revoked = await SendAsync(host, LogoutRequest(token));
        var rejected = await SendAsync(host, LogoutRequest(token));
        listener.Dispose();

        carriers.AddRange(new[] { failed, used, revoked, rejected }.Select(answer => answer.Describe()));
        carriers.Add(issued.Headers);
        carriers.AddRange(logs);
        carriers.AddRange(tags);
        carriers.AddRange((await LoadAuditRowsAsync()).Select(row => JsonSerializer.Serialize(row)));
        carriers.AddRange((await LoginHistoryAsync(IdentityServerFixture.AdminUsername)).Select(row => JsonSerializer.Serialize(row)));

        AssertNoCanary(carriers, wrongPassword, IdentityServerFixture.AdminPassword, token);
        // The scanner itself fails on a carrier that does hold a canary.
        Assert.ThrowsAny<Exception>(() => AssertNoCanary([.. carriers, "x" + token + "y"], token));
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

    private static HttpRequestMessage LoginRequest(string username, string password)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, LoginPath)
        {
            Content = JsonContent.Create(new { username, password })
        };
        request.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        return request;
    }

    private static HttpRequestMessage CookieLoginRequest(string username, string password)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
        {
            Content = JsonContent.Create(new { username, password })
        };
        request.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        return request;
    }

    private static HttpRequestMessage LogoutRequest(string token) => Post(LogoutPath, bearer: token);

    private static HttpRequestMessage Post(string path, string? bearer = null, string? cookie = null, string? unsafeHeader = "1")
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path);
        if (bearer is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        }

        if (cookie is not null)
        {
            request.Headers.TryAddWithoutValidation("Cookie", cookie);
        }

        if (unsafeHeader is not null)
        {
            request.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", unsafeHeader);
        }

        return request;
    }

    private static HttpRequestMessage Get(string path, string? bearer = null, string? cookie = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (bearer is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        }

        if (cookie is not null)
        {
            request.Headers.TryAddWithoutValidation("Cookie", cookie);
        }

        return request;
    }

    private static HttpRequestMessage Malformed(string shape)
    {
        var json = """{"username":"admin","password":"secret"}""";
        var request = new HttpRequestMessage(HttpMethod.Post, shape == "query-string" ? LoginPath + "?x=1" : LoginPath);
        HttpContent content = shape switch
        {
            "text-plain" => new StringContent(json, Encoding.UTF8, "text/plain"),
            "latin1-charset" => new StringContent(json, Encoding.Latin1, "application/json"),
            "declared-oversize" => new StringContent(new string(' ', ManagementBearerSessionEndpoints.MaximumBodyLength) + json, Encoding.UTF8, "application/json"),
            "chunked-oversize" => new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes(new string(' ', ManagementBearerSessionEndpoints.MaximumBodyLength) + json))),
            "bad-json" => new StringContent("{\"username\":", Encoding.UTF8, "application/json"),
            "array-root" => new StringContent("[]", Encoding.UTF8, "application/json"),
            "number-username" => new StringContent("""{"username":1,"password":"secret"}""", Encoding.UTF8, "application/json"),
            _ => new StringContent(json, Encoding.UTF8, "application/json"),
        };
        if (shape == "chunked-oversize")
        {
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            request.Headers.TransferEncodingChunked = true;
        }

        if (shape == "content-encoding")
        {
            content.Headers.ContentEncoding.Add("gzip");
        }

        request.Content = content;
        switch (shape)
        {
            case "no-unsafe-header":
                break;
            case "wrong-unsafe-header":
                request.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "2");
                break;
            case "two-unsafe-headers":
                request.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", ["1", "1"]);
                break;
            default:
                request.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
                break;
        }

        return request;
    }

    private sealed record Answer(HttpStatusCode Status, string Body, string CacheControl, string ContentType, string Headers)
    {
        public string Describe() => $"{(int)Status} {Headers} {Body}";
    }

    private static async Task<Answer> SendAsync(WebApplicationFactory<Program> host, HttpRequestMessage request)
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
                response.Content.Headers.ContentType?.ToString() ?? string.Empty,
                headers);
        }
    }

    private static string StripVolatile(string headers) =>
        string.Join('\n', headers.Split('\n').Where(line =>
            !line.StartsWith("Date:", StringComparison.OrdinalIgnoreCase) &&
            !line.StartsWith("x-correlation-id:", StringComparison.OrdinalIgnoreCase)));

    private static async Task<string> LoginCookieAsync(WebApplicationFactory<Program> host)
    {
        using var client = Client(host);
        using var login = CookieLoginRequest(IdentityServerFixture.AdminUsername, IdentityServerFixture.AdminPassword);
        using var response = await client.SendAsync(login, Ct);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(response.Headers.NonValidated.TryGetValues("Set-Cookie", out var cookies));
        return cookies
            .Single(value => value.StartsWith($"{ManagementSessionDefaults.CookieName}=", StringComparison.Ordinal))
            .Split(';')[0];
    }

    private static async Task<string> LoginBearerAsync(WebApplicationFactory<Program> host)
    {
        var login = await SendAsync(host, LoginRequest(IdentityServerFixture.AdminUsername, IdentityServerFixture.AdminPassword));
        Assert.Equal(HttpStatusCode.OK, login.Status);
        return JsonDocument.Parse(login.Body).RootElement.GetProperty("accessToken").GetString()!;
    }

    private async Task<int> CountBearerRowsAsync()
    {
        using var scope = _fixture.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IdentityDbContext>()
            .ManagementBearerSessions.CountAsync(Ct);
    }

    private async Task<List<Database.Entity.LoginHistoryEntity>> LoginHistoryAsync(string username)
    {
        using var scope = _fixture.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IdentityDbContext>()
            .LoginHistories.AsNoTracking().Where(row => row.Username == username).ToListAsync(Ct);
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

    private static void CountProvider(IServiceCollection services, ProviderCounter counter) =>
        services.Replace(ServiceDescriptor.Scoped<IManagementIdentityProvider>(serviceProvider =>
            new CountingProvider(ActivatorUtilities.CreateInstance<SignaCoreManagementIdentityProvider>(serviceProvider), counter)));

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

    private sealed class ProviderCounter
    {
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public void Record() => Interlocked.Increment(ref _calls);
    }

    private sealed class CountingProvider(IManagementIdentityProvider inner, ProviderCounter counter) : IManagementIdentityProvider
    {
        public ValueTask<ManagementIdentityResult> GetIdentityAsync(CancellationToken cancellationToken = default)
        {
            counter.Record();
            return inner.GetIdentityAsync(cancellationToken);
        }
    }

    /// <summary>A provider that never answers until the login's own token is cancelled.</summary>
    private sealed class NeverAnsweringProvider(TaskCompletionSource? entered = null) : IManagementIdentityProvider
    {
        public NeverAnsweringProvider()
            : this(null)
        {
        }

        public async ValueTask<ManagementIdentityResult> GetIdentityAsync(CancellationToken cancellationToken = default)
        {
            entered?.TrySetResult();
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return ManagementIdentityResult.Unauthenticated();
        }
    }

    /// <summary>Fails the revocation statement the way an unavailable database does.</summary>
    private sealed class FailingRevocation : DbCommandInterceptor
    {
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default) =>
            command.CommandText.TrimStart().StartsWith("UPDATE", StringComparison.OrdinalIgnoreCase)
                ? throw new InjectedDbException()
                : ValueTask.FromResult(result);
    }

    private sealed class InjectedDbException() : DbException("Injected revocation failure.");

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
                Func<TState, Exception?, string> formatter) =>
                lines.Enqueue($"{category}: {formatter(state, exception)} {exception}");
        }
    }
}
