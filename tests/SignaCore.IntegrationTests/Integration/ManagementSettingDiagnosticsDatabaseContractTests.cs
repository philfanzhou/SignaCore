using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle.Logging.Remote;
using SignaCore.Database;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;
using SignaCore.Host.Management;
using SignaCore.Host.Startup;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The product settings diagnostics endpoint and the update compatibility field: safe closed
/// issue reporting for legacy unusable optional telemetry, on both providers.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class ManagementSettingDiagnosticsDatabaseContractTests
{
    private const string Root = "/management/v1/settings";
    private const string Diagnostics = Root + "/diagnostics";
    private const string LegacyOtlp = "ftp://collector.example.com:4317";
    private const string ValidAuthorization = "Basic dGVzdDpjYW5hcnk=";
    private const string RunningHeader = "X-SignaCore-Running-Configuration-Version";

    private static readonly string Required = SignaCoreSettingCompositeValidator.RequiredCode;
    private static readonly string RuntimeInvalid = SignaCoreSettingCompositeValidator.RuntimeInvalidCode;

    public static TheoryData<bool, string?, string?, string?, (string Key, string Code)[]> LegacyGroups => new()
    {
        { false, null, null, null, [] },
        { false, "http://loki.example.com:3100", null, null,
            [("loki.authorization", Required)] },
        { false, "http://loki.example.com:3100", ValidAuthorization, null, [] },
        { false, "https://loki.example.com", null, null,
            [("loki.authorization", Required)] },
        { false, null, ValidAuthorization, null,
            [("loki.uri", Required)] },
        { false, "https://loki.example.com", "Basic bad\nheader", null,
            [("loki.authorization", RuntimeInvalid)] },
        { false, null, null, LegacyOtlp,
            [("opentelemetry.otlp_endpoint", RuntimeInvalid)] },
        { false, "http://loki.example.com:3100", null, LegacyOtlp,
            [("loki.authorization", Required), ("opentelemetry.otlp_endpoint", RuntimeInvalid)] },
        { true, null, null, null, [] },
        { true, "http://loki.example.com:3100", null, null,
            [("loki.authorization", Required)] },
        { true, "http://loki.example.com:3100", ValidAuthorization, null, [] },
        { true, "https://loki.example.com", null, null,
            [("loki.authorization", Required)] },
        { true, null, ValidAuthorization, null,
            [("loki.uri", Required)] },
        { true, "https://loki.example.com", "Basic bad\nheader", null,
            [("loki.authorization", RuntimeInvalid)] },
        { true, null, null, LegacyOtlp,
            [("opentelemetry.otlp_endpoint", RuntimeInvalid)] },
        { true, "http://loki.example.com:3100", null, LegacyOtlp,
            [("loki.authorization", Required), ("opentelemetry.otlp_endpoint", RuntimeInvalid)] }
    };

    [Theory]
    [MemberData(nameof(LegacyGroups))]
    public async Task Diagnostics_ReportClosedIssuesForTheSavedVersion(
        bool postgres, string? uri, string? authorization, string? endpoint,
        (string Key, string Code)[] expectedIssues)
    {
        await using var fixture = await Fixture.CreateAsync(postgres, uri, authorization, endpoint);
        await using var factory = fixture.Host();
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anonymous.GetAsync(Diagnostics, TestContext.Current.CancellationToken)).StatusCode);
        using var admin = await LoginAsync(factory);
        var stored = await fixture.StoredAsync();
        var runtimeVersion = factory.Services.GetRequiredService<InstallationRuntimeState>()
            .ConfigurationVersion;

        using var response = await admin.GetAsync(Diagnostics, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        var body = await JsonAsync(response);

        // The JSON shape is fixed and bounded: exactly the three top-level members, and every
        // issue is exactly a registered key plus a product-fixed code.
        Assert.Equal(["issues", "runningVersion", "version"],
            body.EnumerateObject().Select(property => property.Name).OrderBy(name => name).ToList());
        Assert.Equal(stored.Version, body.GetProperty("version").GetInt64());
        Assert.Equal(runtimeVersion, body.GetProperty("runningVersion").GetInt64());
        var actualIssues = body.GetProperty("issues").EnumerateArray().Select(issue =>
            (Key: issue.GetProperty("key").GetString()!, Code: issue.GetProperty("errorCode").GetString()!)).ToList();
        Assert.Equal(
            expectedIssues.Select(issue => (Key: issue.Key, Code: issue.Code))
                .OrderBy(issue => issue.Key, StringComparer.Ordinal).ToList(),
            actualIssues.OrderBy(issue => issue.Key, StringComparer.Ordinal).ToList());
        foreach (var issue in body.GetProperty("issues").EnumerateArray())
        {
            Assert.Equal(["errorCode", "key"],
                issue.EnumerateObject().Select(property => property.Name).OrderBy(name => name).ToList());
        }

        // No stored value, credential, endpoint, or arbitrary text may appear anywhere.
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        foreach (var value in new[] { "loki.example.com", "collector.example.com",
                     "Basic dGVzdDpjYW5hcnk=", "recovery-tests-root-key" })
            Assert.DoesNotContain(value, raw, StringComparison.Ordinal);

        // After a restart the running version follows the snapshot this process activated.
        await using var restarted = fixture.Host();
        using var restartedAdmin = await LoginAsync(restarted);
        using var restartedResponse = await restartedAdmin.GetAsync(
            Diagnostics, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, restartedResponse.StatusCode);
        var restartedBody = await JsonAsync(restartedResponse);
        Assert.Equal((await fixture.StoredAsync()).Version,
            restartedBody.GetProperty("runningVersion").GetInt64());
        Assert.Equal(runtimeVersion, restartedBody.GetProperty("runningVersion").GetInt64());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Diagnostics_UnknownQueryAndOtherMethodsHaveFixedAnswers(bool postgres)
    {
        await using var fixture = await Fixture.CreateAsync(postgres, null, null, null);
        await using var factory = fixture.Host();
        using var admin = await LoginAsync(factory);

        foreach (var query in new[] { "?group=loki", "?unknown=1" })
        {
            using var rejected = await admin.GetAsync(
                Diagnostics + query, TestContext.Current.CancellationToken);
            var raw = await rejected.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            var headers = string.Join(" | ", rejected.Headers.Select(h => $"{h.Key}={string.Join(",", h.Value)}")
                .Concat(rejected.Content.Headers.Select(h => $"{h.Key}={string.Join(",", h.Value)}")));
            Assert.True(HttpStatusCode.BadRequest == rejected.StatusCode,
                $"status={rejected.StatusCode} contentType={rejected.Content.Headers.ContentType} body='{raw}' headers=[{headers}]");
            Assert.Equal("management.request.invalid",
                (await JsonAsync(rejected)).GetProperty("errorCode").GetString());
        }

        // No other method is mapped: the shared management surface answers unmapped methods for
        // this group exactly as it does for the shared read-only definitions route — never 200.
        using var definitionsPosted = await admin.PostAsync(Root + "/definitions", null,
            TestContext.Current.CancellationToken);
        using var posted = await admin.PostAsync(Diagnostics, null,
            TestContext.Current.CancellationToken);
        Assert.Equal(definitionsPosted.StatusCode, posted.StatusCode);
        Assert.NotEqual(HttpStatusCode.OK, posted.StatusCode);
        using var put = await admin.PutAsync(Diagnostics, null,
            TestContext.Current.CancellationToken);
        Assert.Equal(definitionsPosted.StatusCode, put.StatusCode);
        Assert.NotEqual(HttpStatusCode.OK, put.StatusCode);
    }

    [Theory]
    [InlineData(false, "unknown")]
    [InlineData(false, "decrypt")]
    [InlineData(false, "critical")]
    [InlineData(false, "type")]
    [InlineData(true, "unknown")]
    [InlineData(true, "decrypt")]
    [InlineData(true, "critical")]
    [InlineData(true, "type")]
    public async Task CorruptBaseline_DiagnosticsFailClosedWithTheSharedFixed503(
        bool postgres, string kind)
    {
        await using var fixture = await Fixture.CreateAsync(postgres,
            "http://loki.example.com", ValidAuthorization, LegacyOtlp);
        await using var factory = fixture.Host();
        using var admin = await LoginAsync(factory);
        var before = await fixture.StoredAsync();
        var values = SharedSettingTestDatabase.ParseValues(before);
        values[kind switch
        {
            "unknown" => "unknown.persisted.key", "decrypt" => "loki.authorization",
            "critical" => "jwt.issuer", _ => "jwt.token_expiration_hours"
        }] = kind switch
        {
            "decrypt" => "sm:v1:invalid-ciphertext", "critical" => "https://other.example.com", _ => "invalid"
        };
        await using (var context = fixture.Context())
            await context.Database.ExecuteSqlAsync(
                $"UPDATE service_settings SET values_json = {JsonSerializer.Serialize(values)} WHERE service_id = 'signacore'",
                TestContext.Current.CancellationToken);

        using var response = await admin.GetAsync(Diagnostics, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("{\"errorCode\":\"management.settings.unavailable\"}",
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task DiagnosticsCancellation_PropagatesTheCallerToken()
    {
        await using var fixture = await Fixture.CreateAsync(false,
            "http://loki.example.com", ValidAuthorization, LegacyOtlp);
        await using var factory = fixture.Host();
        var snapshot = factory.Services.GetRequiredService<ManagementSettingQuerySnapshot>();
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.Current.CancellationToken);
        await cancellation.CancelAsync();

        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => snapshot.GetDiagnosticsAsync(cancellation.Token).AsTask());

        Assert.Equal(cancellation.Token, error.CancellationToken);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DefiniteValidationFailure_AnswersTheCompatibilityField(bool postgres)
    {
        await using var fixture = await Fixture.CreateAsync(postgres,
            "http://loki.example.com:3100", ValidAuthorization, LegacyOtlp);
        await using var factory = fixture.Host();
        using var admin = await LoginAsync(factory);
        var before = await fixture.StoredAsync();
        var audits = (await fixture.AuditsAsync()).Count;

        // Touching the OTLP group with another unusable endpoint is a definite validation
        // failure: fixed top-level code plus the closed per-key list.
        using var touched = await PostAsync(admin, before.Version,
            new() { ["opentelemetry.otlp_endpoint"] = "https://new-collector.example.com/#fragment" });
        Assert.Equal(HttpStatusCode.BadRequest, touched.StatusCode);
        var touchedBody = await touched.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("management.request.invalid", touchedBody, StringComparison.Ordinal);
        using var touchedDocument = JsonDocument.Parse(touchedBody);
        var touchedJson = touchedDocument.RootElement;
        Assert.Equal(["errorCode", "validationErrors"],
            touchedJson.EnumerateObject().Select(property => property.Name).OrderBy(name => name).ToList());
        Assert.Equal([("opentelemetry.otlp_endpoint", RuntimeInvalid)],
            touchedJson.GetProperty("validationErrors").EnumerateArray().Select(issue =>
                (issue.GetProperty("key").GetString()!, issue.GetProperty("errorCode").GetString()!)).ToList());

        // A null-key runtime rejection keeps its fixed classification: an explicit JSON null.
        using var nullKey = await PostAsync(admin, before.Version,
            new() { ["sms.otp_hmac_key"] = "bad-key" });
        Assert.Equal(HttpStatusCode.BadRequest, nullKey.StatusCode);
        var nullKeyErrors = (await JsonAsync(nullKey)).GetProperty("validationErrors").EnumerateArray()
            .Select(issue => (Key: issue.GetProperty("key"), Code: issue.GetProperty("errorCode").GetString()))
            .ToList();
        Assert.Contains(nullKeyErrors, issue =>
            issue.Key.ValueKind == JsonValueKind.Null && issue.Code == RuntimeInvalid);

        // Parse rejections happen before the executor: the generic body, no reflected keys.
        using var malformed = await admin.PostAsync(Root,
            new StringContent("not-json-at-all", Encoding.UTF8, "application/json"),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        var malformedBody = await malformed.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("validationErrors", malformedBody, StringComparison.Ordinal);
        using var unknownKey = await PostAsync(admin, before.Version,
            new() { ["unknown.key"] = "value" });
        Assert.Equal(HttpStatusCode.BadRequest, unknownKey.StatusCode);
        Assert.DoesNotContain("unknown.key",
            await unknownKey.Content.ReadAsStringAsync(TestContext.Current.CancellationToken),
            StringComparison.Ordinal);

        // Old shapes stay: 409 conflict, 200 applied, and no retry-side writes on rejection.
        using var stale = await PostAsync(admin, before.Version - 1,
            new() { ["jwt.audience"] = "valid-audience" });
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        Assert.DoesNotContain("validationErrors",
            await stale.Content.ReadAsStringAsync(TestContext.Current.CancellationToken),
            StringComparison.Ordinal);

        using var repaired = await PostAsync(admin, before.Version, new()
        {
            ["loki.uri"] = "https://loki.example.com", ["loki.authorization"] = ValidAuthorization
        });
        Assert.Equal(HttpStatusCode.OK, repaired.StatusCode);
        Assert.Equal(before.Version + 1, (await JsonAsync(repaired)).GetProperty("version").GetInt64());
        Assert.Equal(before.Version, (await fixture.StoredAsync()).Version - 1);
        // One audit row per changed key: the repair saves exactly the two Loki keys.
        Assert.Equal(audits + 2, (await fixture.AuditsAsync()).Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CorruptBaseline_KeepsTheShared503WithoutCompatibilityField(bool postgres)
    {
        await using var fixture = await Fixture.CreateAsync(postgres,
            "http://loki.example.com", ValidAuthorization, LegacyOtlp);
        await using var factory = fixture.Host();
        using var admin = await LoginAsync(factory);
        var before = await fixture.StoredAsync();
        var values = SharedSettingTestDatabase.ParseValues(before);
        values["loki.authorization"] = "sm:v1:invalid-ciphertext";
        await using (var context = fixture.Context())
            await context.Database.ExecuteSqlAsync(
                $"UPDATE service_settings SET values_json = {JsonSerializer.Serialize(values)} WHERE service_id = 'signacore'",
                TestContext.Current.CancellationToken);

        using var rejected = await PostAsync(admin, before.Version,
            new() { ["jwt.audience"] = "valid-audience" });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, rejected.StatusCode);
        Assert.Equal("{\"errorCode\":\"management.settings.update_unavailable\"}",
            await rejected.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    private static Task<JsonElement> JsonAsync(HttpResponseMessage response) =>
        response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: TestContext.Current.CancellationToken);

    private static Task<HttpResponseMessage> PostAsync(HttpClient admin, long version,
        Dictionary<string, string?> changes) => admin.PostAsJsonAsync(Root, new
        {
            expectedVersion = version, changes = changes.Select(pair => new { key = pair.Key, value = pair.Value })
        }, TestContext.Current.CancellationToken);

    private static async Task<HttpClient> LoginAsync(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        client.DefaultRequestHeaders.Add("X-ServiceMantle-Request", "1");
        using var login = await client.PostAsJsonAsync("/management/v1/session/login",
            new { username = "recovery-admin", password = "RecoveryTest123" }, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
        return client;
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly string directory = Path.Combine(PhysicalTempPath.Root(), $"signacore-diagnostics-{Guid.NewGuid():N}");
        private PostgreSqlContainer? postgres;
        private DatabaseOptions database = null!;
        private string bootstrap = string.Empty;

        internal static async Task<Fixture> CreateAsync(bool usePostgres,
            string? uri, string? authorization, string? endpoint)
        {
            Assert.SkipUnless(!usePostgres || Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true",
                "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true for PostgreSQL diagnostics contracts.");
            var fixture = new Fixture();
            Directory.CreateDirectory(fixture.directory);
            if (usePostgres)
            {
                fixture.postgres = new PostgreSqlBuilder(Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE")
                    ?? "postgres:15-alpine").WithDatabase("identity").WithUsername("postgres").WithPassword("postgres").Build();
                await fixture.postgres.StartAsync(TestContext.Current.CancellationToken);
                fixture.database = new() { Provider = "PostgreSQL", ServerVersion = "15",
                    ConnectionString = fixture.postgres.GetConnectionString() };
            }
            else fixture.database = new() { Provider = "SQLite", ConnectionString = new SqliteConnectionStringBuilder
                { DataSource = Path.Combine(fixture.directory, "identity.db") }.ConnectionString };
            var overrides = new Dictionary<string, string>();
            if (uri is not null) overrides[SystemSettingKeys.LokiUri] = uri;
            if (authorization is not null) overrides[SystemSettingKeys.LokiAuthorization] = authorization;
            if (endpoint is not null) overrides[SystemSettingKeys.OpenTelemetryOtlpEndpoint] = endpoint;
            fixture.bootstrap = await InstallationTestSupport.PrepareCompletedInstallationAsync(
                fixture.directory, fixture.database, "recovery-tests-root-key", "recovery-admin", "RecoveryTest123",
                overrides, TestContext.Current.CancellationToken);
            return fixture;
        }

        internal WebApplicationFactory<Program> Host() => new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("Bootstrap:FilePath", bootstrap);
                builder.UseSetting("Endpoints:Http", "0");
            });

        internal IdentityDbContext Context()
        {
            var builder = new DbContextOptionsBuilder<IdentityDbContext>();
            builder.UseIdentityDatabase(database);
            return new(builder.Options);
        }

        internal async Task<SharedSettingTestDatabase.AggregateRow> StoredAsync()
        {
            await using var context = Context();
            return (await SharedSettingTestDatabase.LoadAggregateAsync(context, TestContext.Current.CancellationToken))!;
        }

        internal async Task<List<string>> AuditsAsync()
        {
            await using var context = Context();
            return await SharedSettingTestDatabase.LoadSharedAuditJsonAsync(context, TestContext.Current.CancellationToken);
        }

        public async ValueTask DisposeAsync()
        {
            if (postgres is not null) await postgres.DisposeAsync();
            TestSqlitePools.ClearAll();
            Directory.Delete(directory, true);
        }
    }
}
