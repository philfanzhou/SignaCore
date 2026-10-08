using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle.Configuration;
using ServiceMantle.Logging.Remote;
using ServiceMantle.Logging;
using SignaCore.Database;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>Real protected HTTP recovery, persistence, runtime isolation, and restart on both providers.</summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed partial class ManagementSettingRecoveryDatabaseContractTests
{
    private const string Root = "/management/v1/settings";
    private const string LegacyOtlp = "collector.example.com:4317";
    private const string ValidAuthorization = "Basic dGVzdDpjYW5hcnk=";
    private const string RunningHeader = "X-SignaCore-Running-Configuration-Version";

    public static TheoryData<bool, string?, string?, string?> LegacyGroups => new()
    {
        { false, "http://loki.example.com:3100", null, null },
        { false, "https://loki.example.com", null, null },
        { false, null, ValidAuthorization, null },
        { false, "https://loki.example.com", "Basic bad\nheader", null },
        { false, null, null, LegacyOtlp },
        { false, "http://loki.example.com:3100", null, LegacyOtlp },
        { true, "http://loki.example.com:3100", null, null },
        { true, "https://loki.example.com", null, null },
        { true, null, ValidAuthorization, null },
        { true, "https://loki.example.com", "Basic bad\nheader", null },
        { true, null, null, LegacyOtlp },
        { true, "http://loki.example.com:3100", null, LegacyOtlp }
    };

    [Theory]
    [MemberData(nameof(LegacyGroups))]
    public async Task LegacyGroups_ReadAndUnrelatedUpdatePreserveValuesAndRuntime(
        bool postgres, string? uri, string? authorization, string? endpoint)
    {
        await using var fixture = await Fixture.CreateAsync(postgres, uri, authorization, endpoint);
        await using var factory = fixture.Host();
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anonymous.GetAsync(Root, TestContext.Current.CancellationToken)).StatusCode);
        using var admin = await LoginAsync(factory);
        Assert.True(factory.Services.GetRequiredService<IServiceSettingCurrentSnapshotAccessor>().TryGetCurrent(out var running));
        var before = await fixture.StoredAsync();
        var audits = await fixture.AuditsAsync();
        var beforeValues = SharedSettingTestDatabase.ParseValues(before);
        AssertDisabled(factory);
        using (var read = await admin.GetAsync(Root, TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.OK, read.StatusCode);
            var body = await JsonAsync(read);
            Assert.Equal(before.Version, body.GetProperty("version").GetInt64());
            foreach (var value in body.GetProperty("values").EnumerateArray())
                if (value.GetProperty("isSensitive").GetBoolean())
                    Assert.Equal(JsonValueKind.Null, value.GetProperty("value").ValueKind);
        }
        foreach (var change in new[]
        {
            new Dictionary<string, string?> { ["jwt.audience"] = "recovered-audience" },
            new Dictionary<string, string?> { ["sms.max_sends_per_day"] = "9" }
        })
        {
            var version = (await fixture.StoredAsync()).Version;
            using var update = await PostAsync(admin, version, change);
            Assert.Equal(HttpStatusCode.OK, update.StatusCode);
            Assert.Equal(version + 1, (await JsonAsync(update)).GetProperty("version").GetInt64());
            using var read = await admin.GetAsync(Root, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, read.StatusCode);
            Assert.Equal(before.Version.ToString(), read.Headers.GetValues(RunningHeader).Single());
            Assert.True(factory.Services.GetRequiredService<IServiceSettingCurrentSnapshotAccessor>().TryGetCurrent(out var afterRead));
            Assert.Same(running, afterRead);
            AssertDisabled(factory);
        }
        var afterValues = SharedSettingTestDatabase.ParseValues(await fixture.StoredAsync());
        foreach (var key in new[] { "loki.uri", "loki.authorization", "opentelemetry.otlp_endpoint" })
        {
            Assert.Equal(beforeValues.ContainsKey(key), afterValues.ContainsKey(key));
            if (beforeValues.TryGetValue(key, out var value)) Assert.Equal(value, afterValues[key]);
        }
        var afterAudits = await fixture.AuditsAsync();
        Assert.Equal(audits.Count + 2, afterAudits.Count);
        foreach (var key in new[] { "jwt.audience", "sms.max_sends_per_day" })
            Assert.Equal(audits.Count(audit => audit.Contains(key, StringComparison.Ordinal)) + 1,
                afterAudits.Count(audit => audit.Contains(key, StringComparison.Ordinal)));
        // The retired transport keys are unknown keys: rejected without any write.
        foreach (var key in new[] { "security.hosted_login_http_test_origins", "security.allow_non_https_issuer" })
        {
            using var retired = await PostAsync(admin, (await fixture.StoredAsync()).Version,
                new() { [key] = "true" });
            Assert.Equal(HttpStatusCode.BadRequest, retired.StatusCode);
        }
        await using var restarted = fixture.Host();
        AssertDisabled(restarted);
        using var restartedAdmin = await LoginAsync(restarted);
        using var restartedRead = await restartedAdmin.GetAsync(Root, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, restartedRead.StatusCode);
        Assert.Equal((await fixture.StoredAsync()).Version.ToString(),
            restartedRead.Headers.GetValues(RunningHeader).Single());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TouchedGroupsAndCriticalErrorsStayStrict_IndependentRepairsAreAtomic(bool postgres)
    {
        await using var fixture = await Fixture.CreateAsync(postgres,
            "http://loki.example.com:3100", "Basic bad\nheader", LegacyOtlp);
        await using var factory = fixture.Host();
        using var admin = await LoginAsync(factory);
        var before = await fixture.StoredAsync();
        var auditCount = (await fixture.AuditsAsync()).Count;
        var rejected = new Dictionary<string, string?>[]
        {
            // Touching only the URI keeps the stored unusable authorization in the candidate.
            new() { ["loki.uri"] = "http://loki.example.com:3100" },
            new() { ["LOKI.URI"] = "http://loki.example.com:3100" },
            new() { [" loki.uri "] = "http://loki.example.com:3100" },
            new() { ["loki.uri"] = null },
            new() { ["loki.authorization"] = null },
            new() { ["loki.uri"] = "https://loki.example.com" },
            new() { ["loki.uri"] = "https://loki.example.com", ["loki.authorization"] = "bad\nheader" },
            new() { ["opentelemetry.otlp_endpoint"] = LegacyOtlp },
            new() { ["jwt.issuer"] = "https://other.example.com" },
            new() { ["admin.username"] = " " },
            new() { ["jwt.token_expiration_hours"] = "2.5" },
            new() { ["jwt.token_expiration_hours"] = "bad-number" },
            new() { ["security.allow_non_https_issuer"] = "bad-boolean" },
            new() { ["security.hosted_login_http_test_origins"] = "[\"http://localhost:5002\"]" },
            new() { ["sms.otp_hmac_key"] = "bad-key" },
            new() { ["unknown.key"] = "bad" },
            new(StringComparer.Ordinal) { ["jwt.audience"] = "a", ["JWT.AUDIENCE"] = "b" }
        };
        foreach (var changes in rejected)
        {
            using var response = await PostAsync(admin, before.Version, changes);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("management.request.invalid", (await JsonAsync(response)).GetProperty("errorCode").GetString());
            var after = await fixture.StoredAsync();
            Assert.Equal(before.Version, after.Version);
            Assert.Equal(before.ValuesJson, after.ValuesJson);
            Assert.Equal(auditCount, (await fixture.AuditsAsync()).Count);
        }
        // Repair Loki while the untouched OTLP group remains unusable.
        using var repaired = await PostAsync(admin, before.Version, new()
        {
            ["loki.uri"] = "https://loki.example.com", ["loki.authorization"] = ValidAuthorization
        });
        Assert.Equal(HttpStatusCode.OK, repaired.StatusCode);
        AssertDisabled(factory);
        Assert.Equal(LegacyOtlp,
            SharedSettingTestDatabase.ParseValues(await fixture.StoredAsync())["opentelemetry.otlp_endpoint"]);
        await using (var repairedHost = fixture.Host())
        {
            Assert.Single(repairedHost.Services.GetServices<IRemoteLogAuthorizationResolver>());
            Assert.Null(repairedHost.Services.GetService(OtlpRuntime));
        }
        using var disableLoki = await PostAsync(admin, before.Version + 1,
            new() { ["loki.uri"] = null, ["loki.authorization"] = null });
        Assert.Equal(HttpStatusCode.OK, disableLoki.StatusCode);
        // A newly invalid group never receives a waiver merely because a different group is old.
        using var newlyInvalid = await PostAsync(admin, before.Version + 2,
            new() { ["loki.uri"] = "https://new-loki.example.com/#fragment" });
        Assert.Equal(HttpStatusCode.BadRequest, newlyInvalid.StatusCode);
        using var repairOtlp = await PostAsync(admin, before.Version + 2,
            new() { ["opentelemetry.otlp_endpoint"] = "https://127.0.0.1:4317" });
        Assert.Equal(HttpStatusCode.OK, repairOtlp.StatusCode);
        await using (var repairedHost = fixture.Host())
        {
            Assert.Empty(repairedHost.Services.GetServices<IRemoteLogAuthorizationResolver>());
            Assert.NotNull(repairedHost.Services.GetService(OtlpRuntime));
        }
        using var disableOtlp = await PostAsync(admin, before.Version + 3,
            new() { ["opentelemetry.otlp_endpoint"] = null });
        Assert.Equal(HttpStatusCode.OK, disableOtlp.StatusCode);
        await using var disabledHost = fixture.Host();
        AssertDisabled(disabledHost);
        var finalValues = SharedSettingTestDatabase.ParseValues(await fixture.StoredAsync());
        Assert.DoesNotContain("loki.uri", finalValues.Keys);
        Assert.DoesNotContain("loki.authorization", finalValues.Keys);
        Assert.DoesNotContain("opentelemetry.otlp_endpoint", finalValues.Keys);
        Assert.Equal(auditCount + 6, (await fixture.AuditsAsync()).Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OptInKeys_SelectTheWholeGroupForStrictEvaluation(bool postgres)
    {
        // A plain-HTTP endpoint with a stored credential is a usable pair now; the stored OTLP
        // endpoint stays unusable, so an untouched group keeps its waiver for unrelated updates —
        // but touching an opt-in key selects the whole Loki group for the strict rules.
        await using var fixture = await Fixture.CreateAsync(postgres,
            "http://loki.example.com:3100", ValidAuthorization, LegacyOtlp);
        await using var factory = fixture.Host();
        using var admin = await LoginAsync(factory);
        var before = await fixture.StoredAsync();
        var auditCount = (await fixture.AuditsAsync()).Count;

        // The no-authentication switch conflicts with the stored credential; without the group
        // selection this batch would have smuggled an invalid combination past the legacy waiver.
        using var conflicted = await PostAsync(admin, before.Version,
            new() { ["loki.allow_no_authentication"] = "true" });
        Assert.Equal(HttpStatusCode.BadRequest, conflicted.StatusCode);
        Assert.Equal(before.Version, (await fixture.StoredAsync()).Version);
        Assert.Equal(auditCount, (await fixture.AuditsAsync()).Count);

        // A typed rejection on the no-authentication opt-in is likewise a group-touching strict
        // failure; the retired insecure-transport switch is a plain unknown key.
        using var badBoolean = await PostAsync(admin, before.Version,
            new() { ["loki.allow_no_authentication"] = "bad-boolean" });
        Assert.Equal(HttpStatusCode.BadRequest, badBoolean.StatusCode);
        using var retiredSwitch = await PostAsync(admin, before.Version,
            new() { ["loki.allow_insecure_http"] = "true" });
        Assert.Equal(HttpStatusCode.BadRequest, retiredSwitch.StatusCode);
        Assert.Equal(before.Version, (await fixture.StoredAsync()).Version);

        // Moving the endpoint to HTTPS keeps the stored credential and stays usable in one batch,
        // while the untouched OTLP group keeps its waiver.
        using var repaired = await PostAsync(admin, before.Version,
            new() { ["loki.uri"] = "https://loki.example.com" });
        Assert.Equal(HttpStatusCode.OK, repaired.StatusCode);
        var repairedValues = SharedSettingTestDatabase.ParseValues(await fixture.StoredAsync());
        Assert.Equal("https://loki.example.com", repairedValues["loki.uri"]);
        // The stored credential stays protected; only its presence is observable in the raw row.
        Assert.Contains("loki.authorization", repairedValues.Keys);
        Assert.NotEqual(ValidAuthorization, repairedValues["loki.authorization"]);
        // The retired switch never comes back, not even as a stored row.
        Assert.DoesNotContain("loki.allow_insecure_http", repairedValues.Keys);
        Assert.Equal(LegacyOtlp, repairedValues["opentelemetry.otlp_endpoint"]);
        await using (var httpHost = fixture.Host())
        {
            Assert.Single(httpHost.Services.GetServices<IRemoteLogAuthorizationResolver>());
            Assert.Null(httpHost.Services.GetService(OtlpRuntime));
        }

        // The no-authentication switch requires deleting the credential in the same batch.
        using var noAuthentication = await PostAsync(admin, before.Version + 1, new()
        {
            ["loki.authorization"] = null,
            ["loki.allow_no_authentication"] = "true"
        });
        Assert.Equal(HttpStatusCode.OK, noAuthentication.StatusCode);
        var finalValues = SharedSettingTestDatabase.ParseValues(await fixture.StoredAsync());
        Assert.DoesNotContain("loki.authorization", finalValues.Keys);
        Assert.Equal("true", finalValues["loki.allow_no_authentication"]);
        // The no-authentication mode registers no resolver at all, on both providers.
        await using (var noAuthHost = fixture.Host())
        {
            Assert.Empty(noAuthHost.Services.GetServices<IRemoteLogAuthorizationResolver>());
            Assert.Null(noAuthHost.Services.GetService(OtlpRuntime));
        }
        Assert.Equal(auditCount + 3, (await fixture.AuditsAsync()).Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RetiredKeyRows_NeverBlockStartupQueriesOrUpdates(bool postgres)
    {
        // An older release stored the retired insecure-transport switch. The row survives the
        // upgrade (dropping it is the operator's one-row cleanup), so every read of the stored
        // aggregate must ignore it: startup, the management query path, and unrelated updates.
        await using var fixture = await Fixture.CreateAsync(postgres,
            "https://loki.example.com", ValidAuthorization, null);
        var seeded = await fixture.StoredAsync();
        var values = SharedSettingTestDatabase.ParseValues(seeded);
        values["loki.allow_insecure_http"] = "true";
        await using (var context = fixture.Context())
            await context.Database.ExecuteSqlAsync(
                $"UPDATE service_settings SET values_json = {JsonSerializer.Serialize(values)} WHERE service_id = 'signacore'",
                TestContext.Current.CancellationToken);

        await using var factory = fixture.Host();
        using var admin = await LoginAsync(factory);
        using (var read = await admin.GetAsync(Root, TestContext.Current.CancellationToken))
        {
            Assert.Equal(HttpStatusCode.OK, read.StatusCode);
            // The retired key is not a catalog member any more: it never appears in the listing.
            Assert.DoesNotContain("loki.allow_insecure_http",
                await read.Content.ReadAsStringAsync(TestContext.Current.CancellationToken),
                StringComparison.Ordinal);
        }

        var version = (await fixture.StoredAsync()).Version;
        using var rejected = await PostAsync(admin, version,
            new() { ["loki.allow_insecure_http"] = "true" });
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);

        using var unrelated = await PostAsync(admin, version,
            new() { ["jwt.audience"] = "retired-key-audience" });
        Assert.Equal(HttpStatusCode.OK, unrelated.StatusCode);
        var after = SharedSettingTestDatabase.ParseValues(await fixture.StoredAsync());
        Assert.Equal("true", after["loki.allow_insecure_http"]);
        Assert.Equal("retired-key-audience", after["jwt.audience"]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RecoveryExecutor_ConcurrentExpectedVersionHasOneWinner(bool postgres)
    {
        await using var fixture = await Fixture.CreateAsync(postgres,
            "http://loki.example.com", ValidAuthorization, LegacyOtlp);
        await using var factory = fixture.Host();
        using var first = await LoginAsync(factory);
        using var second = await LoginAsync(factory);
        var before = await fixture.StoredAsync();
        var audits = (await fixture.AuditsAsync()).Count;
        var outcomes = await Task.WhenAll(
            PostAsync(first, before.Version, new() { ["jwt.audience"] = "first-audience" }),
            PostAsync(second, before.Version, new() { ["jwt.audience"] = "second-audience" }));
        Assert.Single(outcomes, response => response.StatusCode == HttpStatusCode.OK);
        Assert.Single(outcomes, response => response.StatusCode == HttpStatusCode.Conflict);
        foreach (var response in outcomes) response.Dispose();
        Assert.Equal(before.Version + 1, (await fixture.StoredAsync()).Version);
        Assert.Equal(audits + 1, (await fixture.AuditsAsync()).Count);
    }

    private static Type OtlpRuntime => typeof(ServiceMantle.Diagnostics.Instrumentation.OpenTelemetryOptions)
        .Assembly.GetType("ServiceMantle.Diagnostics.Export.Otlp.OtlpRuntime", true)!;

    private static void AssertDisabled(WebApplicationFactory<Program> factory)
    {
        Assert.Empty(factory.Services.GetServices<IRemoteLogAuthorizationResolver>());
        Assert.Null(factory.Services.GetService(OtlpRuntime));
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
        private readonly string directory = Path.Combine(PhysicalTempPath.Root(), $"signacore-recovery-{Guid.NewGuid():N}");
        private PostgreSqlContainer? postgres;
        private DatabaseOptions database = null!;
        private string bootstrap = string.Empty;

        internal static async Task<Fixture> CreateAsync(bool usePostgres,
            string? uri, string? authorization, string? endpoint)
        {
            Assert.SkipUnless(!usePostgres || Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true",
                "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true for PostgreSQL recovery contracts.");
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

        internal IdentityDbContext Context(bool retry = true)
        {
            var builder = new DbContextOptionsBuilder<IdentityDbContext>();
            builder.UseIdentityDatabase(database, enableRetryOnFailure: retry);
            return new(builder.Options);
        }

        internal IdentityDbContext ContextWithoutRetry() => Context(false);

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
