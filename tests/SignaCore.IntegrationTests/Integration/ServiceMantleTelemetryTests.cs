using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using ServiceMantle.Diagnostics;
using ServiceMantle.Diagnostics.Instrumentation;
using ServiceMantle.Health;
using ServiceMantle.Installation;
using ServiceMantle.Web.Health;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;
using SignaCore.Host.Telemetry;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The normal host's telemetry is registered only by ServiceMantle: the authorized Prometheus scrape
/// endpoint behind the GatewayApp policy, the product <c>SignaCore</c> meter actually exported, the
/// HTTPS-only OTLP trace exporter with its upgrade behavior, and the release of every provider when
/// the host stops.
/// </summary>
public sealed class ServiceMantleTelemetryTests : IAsyncLifetime
{
    private const string RootSecret = "test-master-key-for-telemetry-tests-only";
    private const string AdminUsername = "telemetry_admin";
    private const string AdminPassword = "TelemetryAdmin123";
    private const string ScraperId = "metrics-scraper";
    private const string PublicClientId = "metrics-public-client";
    private const string Root = "/management/v1";
    private const string OtlpWarning = "OTLP trace export is disabled";

    private readonly List<WebApplicationFactory<Program>> _factories = [];
    private readonly string _scraperSecret = "scraper-" + Guid.NewGuid().ToString("N");
    private string _directory = string.Empty;
    private string _connectionString = string.Empty;

    public ValueTask InitializeAsync()
    {
        _directory = Path.Combine(PhysicalTempPath.Root(), $"signacore-telemetry-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_directory);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(_directory, "identity.db")
        }.ConnectionString;
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var factory in _factories)
        {
            await factory.DisposeAsync();
        }

        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A pooled SQLite handle can outlive the host briefly; the directory is uniquely named.
        }
    }

    // ---- Architecture ----

    [Fact]
    public async Task Telemetry_IsRegisteredOnlyThroughServiceMantle()
    {
        var factory = await StartNormalHostAsync();
        var services = factory.Services;

        Assert.NotNull(services.GetService(ServiceMantleType("ServiceMantle.Diagnostics.Instrumentation.OpenTelemetryRegistration")));
        Assert.NotNull(services.GetService(ServiceMantleType("ServiceMantle.Diagnostics.Export.Prometheus.PrometheusRegistration")));
        var metrics = Assert.Single(
            services.GetServices<EndpointDataSource>().SelectMany(source => source.Endpoints).OfType<RouteEndpoint>(),
            endpoint => endpoint.RoutePattern.RawText == SignaCoreTelemetry.MetricsPath);
        Assert.Contains(metrics.Metadata, item => item.GetType().FullName ==
            "ServiceMantle.Diagnostics.Export.Prometheus.PrometheusEndpointMetadata");

        var hostAssembly = typeof(SignaCoreTelemetry).Assembly;
        Assert.Empty(LocalTelemetryReferences(hostAssembly));
        var project = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "SignaCore.Host", "SignaCore.Host.csproj"));
        Assert.Empty(DirectOpenTelemetryPackages(project));
        Assert.Contains("<PackageReference Include=\"ServiceMantle.Diagnostics\" />", project, StringComparison.Ordinal);

        // Negative variants: a local AddPrometheusExporter call and a direct package reference are
        // both detected by the same checks.
        Assert.Contains(
            "OpenTelemetry.Exporter.Prometheus.AspNetCore",
            LocalTelemetryReferences(typeof(ServiceMantleTelemetryTests).Assembly));
        Assert.Equal(
            ["OpenTelemetry.Exporter.Prometheus.AspNetCore"],
            DirectOpenTelemetryPackages(project.Replace(
                "<PackageReference Include=\"ServiceMantle.Diagnostics\" />",
                "<PackageReference Include=\"OpenTelemetry.Exporter.Prometheus.AspNetCore\" />",
                StringComparison.Ordinal)));
    }

    // ---- The authorized scrape endpoint ----

    [Fact]
    public async Task Metrics_RequireRegisteredApplicationCredentialsAndExportProductSeries()
    {
        var logs = new CapturingLoggerProvider();
        var factory = await StartNormalHostAsync(logs: logs);
        await SeedApplicationsAsync();
        using var client = factory.CreateClient();
        await DriveProductMetricAsync(client);
        var canary = "canary-" + Guid.NewGuid().ToString("N");

        using var anonymous = await ScrapeAsync(client, null, null);
        using var wrongSecret = await ScrapeAsync(client, ScraperId, canary);
        using var unknownApp = await ScrapeAsync(client, "no-such-app", canary);
        using var publicClient = await ScrapeAsync(client, PublicClientId, canary);
        using var scraped = await ScrapeAsync(client, ScraperId, _scraperSecret);
        using var post = await ScrapeAsync(client, ScraperId, _scraperSecret, HttpMethod.Post);

        foreach (var rejected in new[] { anonymous, wrongSecret, unknownApp, publicClient })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
            var body = await rejected.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.DoesNotContain(canary, body, StringComparison.Ordinal);
            Assert.DoesNotContain("http_server_request_duration", body, StringComparison.Ordinal);
        }

        Assert.NotEqual(HttpStatusCode.OK, post.StatusCode);
        Assert.Equal(HttpStatusCode.OK, scraped.StatusCode);
        var metrics = await scraped.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(ExportsProductSeries(metrics), "No SignaCore product series was exported.");
        Assert.Contains("http_server_request_duration", metrics, StringComparison.Ordinal);
        AssertSharedPhase(metrics, "completed");
        Assert.DoesNotContain(canary, metrics, StringComparison.Ordinal);
        Assert.DoesNotContain(_scraperSecret, metrics, StringComparison.Ordinal);
        Assert.DoesNotContain(logs.Lines, line => line.Contains(canary, StringComparison.Ordinal));
        Assert.DoesNotContain(logs.Lines, line => line.Contains(_scraperSecret, StringComparison.Ordinal));
    }

    [Fact]
    public async Task WithoutTheProductMeterSelection_TheProductSeriesAreNotExported()
    {
        // The regression variant of the #305 export gap: dropping only the SignaCore selection
        // removes the product series while the framework series stay.
        var factory = await StartNormalHostAsync(configureServices: services =>
        {
            var product = services.Single(descriptor =>
                descriptor.ImplementationInstance is SignaCoreTelemetry.MeterSelection selection &&
                selection.MeterNames.Contains(SignaCoreTelemetry.ProductSignalName));
            services.Remove(product);
        });
        await SeedApplicationsAsync();
        using var client = factory.CreateClient();
        await DriveProductMetricAsync(client);

        using var scraped = await ScrapeAsync(client, ScraperId, _scraperSecret);

        Assert.Equal(HttpStatusCode.OK, scraped.StatusCode);
        var metrics = await scraped.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.False(ExportsProductSeries(metrics));
        Assert.Contains("http_server_request_duration", metrics, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingAuthority_PublishesUnknown_AndKeepsTheExistingScrapePhaseGate()
    {
        var factory = await StartNormalHostAsync();
        await SeedApplicationsAsync();
        using var client = factory.CreateClient();
        await using (var db = CreateDbContext())
            await db.ServiceInstallations.ExecuteDeleteAsync(TestContext.Current.CancellationToken);
        using var ready = await client.GetAsync("/health/ready", TestContext.Current.CancellationToken);
        // Readiness contributors do not use the phase snapshot. A management read drives the
        // production authority observation, without trusting the process's startup intent.
        using var rejected = await client.GetAsync("/management/v1/settings", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, rejected.StatusCode);
        using var scraped = await ScrapeAsync(client, ScraperId, _scraperSecret);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, scraped.StatusCode);
        Assert.Equal("{\"errorCode\":\"service.phase.unavailable\"}", await scraped.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var publisher = factory.Services.GetRequiredService<ServiceMetrics>();
        var meter = (Meter)typeof(ServiceMetrics).GetProperty("Meter", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(publisher)!;
        var values = new Dictionary<string, long>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, owner) =>
        {
            if (ReferenceEquals(instrument.Meter, meter) && instrument.Name == ServiceMetrics.InstallationPhaseName)
                owner.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
        {
            foreach (var tag in tags) if (tag.Key == "phase") values.Add((string)tag.Value!, value);
        });
        listener.Start();
        listener.RecordObservableInstruments();
        Assert.Equal(4, values.Count);
        Assert.Equal(1, values["unknown"]);
        Assert.Equal(1, values.Values.Sum());
    }

    [Fact]
    public async Task ConcurrentScrapesAndHostDisposal_KeepOneHotPerHostObservations()
    {
        var first = await StartNormalHostAsync(track: false, configureServices: services =>
        {
            services.RemoveAll<IServiceHealthSnapshotSource>();
            services.AddSingleton<IServiceHealthSnapshotSource, ConfirmedSnapshot>();
        });
        try
        {
            // Reuse the installed file; preparing the same aggregate twice is a version conflict.
            var second = first.WithWebHostBuilder(builder => builder.UseSetting("Endpoints:Http", "0"));
            _factories.Add(second);
            _ = second.Services;
            await SeedApplicationsAsync();
            first.Services.GetRequiredService<ServiceMetrics>().SetUnknown();
            using var a = first.CreateClient();
            using var b = second.CreateClient();
            async Task Scrape(HttpClient client, string phase)
            {
                using var response = await ScrapeAsync(client, ScraperId, _scraperSecret);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                AssertSharedPhase(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), phase);
            }
            // Stay within the existing four concurrent scrape budget on each host.
            await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => Scrape(a, "unknown"))
                .Concat(Enumerable.Range(0, 3).Select(_ => Scrape(b, "completed"))));
            await first.DisposeAsync();
            await Scrape(b, "completed");
        }
        finally { await first.DisposeAsync(); }
    }

    private sealed class ConfirmedSnapshot : IServiceHealthSnapshotSource
    {
        public ValueTask<ServiceHealthSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new ServiceHealthSnapshot(ServiceStartupPhase.Completed,
                ServiceMigrationReadinessState.Succeeded, ServiceDatabaseReadinessState.Reachable));
        }
    }

    private static void AssertSharedPhase(string text, string expected)
    {
        var info = text.Split('\n').Where(line => line.StartsWith("servicemantle_service_info", StringComparison.Ordinal)).ToArray();
        Assert.Single(info);
        Assert.EndsWith(" 1", info[0], StringComparison.Ordinal);
        var lines = text.Split('\n').Where(line => line.StartsWith("servicemantle_installation_phase", StringComparison.Ordinal)).ToArray();
        Assert.Equal(4, lines.Length);
        foreach (var phase in new[] { "unknown", "bootstrap_configuration", "pending_setup", "completed" })
        {
            var line = Assert.Single(lines, item => item.Contains("phase=\"" + phase + "\"", StringComparison.Ordinal));
            Assert.EndsWith(phase == expected ? " 1" : " 0", line, StringComparison.Ordinal);
        }
    }

    // ---- OTLP ----

    [Fact]
    public async Task EmptyOtlpEndpoint_RegistersNoExporter()
    {
        var logs = new CapturingLoggerProvider();
        var factory = await StartNormalHostAsync(logs: logs);

        Assert.Null(factory.Services.GetService(ServiceMantleType("ServiceMantle.Diagnostics.Export.Otlp.OtlpRuntime")));
        Assert.DoesNotContain(logs.Lines, line => line.Contains(OtlpWarning, StringComparison.Ordinal));
    }

    [Fact]
    public async Task HttpsOtlpEndpoint_RegistersTheTraceExporter()
    {
        var factory = await StartNormalHostAsync(new Dictionary<string, string>
        {
            [SystemSettingKeys.OpenTelemetryOtlpEndpoint] = "https://127.0.0.1:4317"
        });
        using var client = factory.CreateClient();

        using var ready = await client.GetAsync("/health/ready", TestContext.Current.CancellationToken);

        // The host started, so the ServiceMantle OTLP startup validation accepted the endpoint.
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
        Assert.NotNull(factory.Services.GetService(ServiceMantleType("ServiceMantle.Diagnostics.Export.Otlp.OtlpRuntime")));
    }

    [Theory]
    [InlineData("ftp://otlp-legacy.example.com:4317")]
    [InlineData("https://user:fixture@otlp-legacy.example.com:4317")]
    [InlineData("https://otlp-legacy.example.com:4317/?tenant=fixture")]
    [InlineData("https://otlp-legacy.example.com:4317/#fixture")]
    public async Task StoredUnusableOtlpEndpoint_StartsWithOtlpOffAndAFixedWarning(string endpoint)
    {
        var logs = new CapturingLoggerProvider();
        var factory = await StartNormalHostAsync(
            new Dictionary<string, string>
            {
                [SystemSettingKeys.OpenTelemetryOtlpEndpoint] = endpoint
            },
            logs: logs);
        using var client = factory.CreateClient();

        using var ready = await client.GetAsync("/health/ready", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
        Assert.Null(factory.Services.GetService(ServiceMantleType("ServiceMantle.Diagnostics.Export.Otlp.OtlpRuntime")));
        Assert.Single(logs.Lines, line => line.Contains(OtlpWarning, StringComparison.Ordinal));
        Assert.DoesNotContain(logs.Lines, line => line.Contains("otlp-legacy", StringComparison.Ordinal));
        Assert.DoesNotContain(logs.Lines, line => line.Contains("fixture", StringComparison.Ordinal));

        // Legacy optional telemetry stays readable and no longer blocks unrelated valid updates.
        using var admin = await CreateAdminClientAsync(factory);
        await using var db = CreateDbContext();
        var version = (await SharedSettingTestDatabase.LoadAggregateAsync(
            db, TestContext.Current.CancellationToken))!.Version;
        var audits = await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(db, TestContext.Current.CancellationToken);
        Assert.Equal(version, await ReadVersionAsync(admin));
        using var accepted = await admin.PostAsJsonAsync(Root + "/settings", new
        {
            expectedVersion = version,
            changes = new[] { new { key = "jwt.audience", value = "recovered-audience" } }
        }, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal(version + 1, await ReadVersionAsync(admin));
        Assert.Equal(version + 1, (await SharedSettingTestDatabase.LoadAggregateAsync(
            db, TestContext.Current.CancellationToken))!.Version);
        Assert.Equal(audits.Count + 1, (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
            db, TestContext.Current.CancellationToken)).Count);
    }

    [Fact]
    public async Task ManagementUpdate_RejectsStructurallyUnusableOtlpEndpoints()
    {
        var factory = await StartNormalHostAsync();
        using var admin = await CreateAdminClientAsync(factory);
        var version = await ReadVersionAsync(admin);

        foreach (var endpoint in new[]
                 {
                     "ftp://collector.example.com:4317",
                     "https://user:pass@collector.example.com",
                     "https://collector.example.com/?x=1"
                 })
        {
            using var rejected = await PostSettingAsync(admin, version, endpoint);
            Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
            Assert.Contains(
                "management.request.invalid",
                await rejected.Content.ReadAsStringAsync(TestContext.Current.CancellationToken),
                StringComparison.Ordinal);
            Assert.Equal(version, await ReadVersionAsync(admin));
        }

        using var accepted = await PostSettingAsync(admin, version, "https://collector.example.com:4317");
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal(version + 1, await ReadVersionAsync(admin));
        // Plain http is accepted as an equal input since ServiceMantle 0.3.2.
        using var plainHttp = await PostSettingAsync(admin, version + 1, "http://collector.example.com:4317");
        Assert.Equal(HttpStatusCode.OK, plainHttp.StatusCode);
        Assert.Equal(version + 2, await ReadVersionAsync(admin));
    }

    // ---- Provider release ----

    [Fact]
    public async Task StoppingTheHost_ReleasesTheSharedProviders()
    {
        var factory = await StartNormalHostAsync(track: false);
        var meterProvider = factory.Services.GetRequiredService<MeterProvider>();
        var tracerProvider = factory.Services.GetRequiredService<TracerProvider>();
        Assert.False(IsDisposed(meterProvider));
        Assert.False(IsDisposed(tracerProvider));

        await factory.DisposeAsync();

        // The ServiceMantle-registered providers - and with them their meter and activity
        // listeners - were released with the host. A process-wide listener probe is not used:
        // other test hosts in the same process legitimately listen to the same meter name.
        Assert.True(IsDisposed(meterProvider));
        Assert.True(IsDisposed(tracerProvider));
    }

    /// <summary>Reads the OpenTelemetry SDK provider's own disposal flag.</summary>
    private static bool IsDisposed(object provider)
    {
        for (var type = provider.GetType(); type is not null; type = type.BaseType)
        {
            var field = type.GetField("Disposed", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (field?.FieldType == typeof(bool))
            {
                return (bool)field.GetValue(provider)!;
            }
        }

        throw new InvalidOperationException("The provider exposes no disposal flag.");
    }

    // ---- Checks ----

    /// <summary>
    /// Assembly references that mean the host itself composes OpenTelemetry instrumentation,
    /// exporters, or the hosting integration instead of ServiceMantle.
    /// </summary>
    private static IReadOnlyList<string> LocalTelemetryReferences(Assembly assembly) =>
        assembly.GetReferencedAssemblies()
            .Select(reference => reference.Name!)
            .Where(name =>
                name.StartsWith("OpenTelemetry.Exporter.", StringComparison.Ordinal) ||
                name.StartsWith("OpenTelemetry.Instrumentation.", StringComparison.Ordinal) ||
                name == "OpenTelemetry.Extensions.Hosting")
            .ToList();

    private static IReadOnlyList<string> DirectOpenTelemetryPackages(string project) =>
        Regex.Matches(project, "<PackageReference\\s+Include=\"(OpenTelemetry[^\"]*)\"")
            .Select(match => match.Groups[1].Value)
            .ToList();

    private static bool ExportsProductSeries(string metrics) =>
        metrics.Split('\n').Any(line =>
            line.StartsWith("auth_login_", StringComparison.Ordinal) ||
            line.StartsWith("oidc_", StringComparison.Ordinal));

    /// <summary>
    /// Keeps this assembly referencing the Prometheus exporter directly, so the negative variant of
    /// <see cref="LocalTelemetryReferences"/> has a real local call to find. Never invoked.
    /// </summary>
    internal static MeterProviderBuilder LocalExporterForNegativeCheck(MeterProviderBuilder builder) =>
        builder.AddPrometheusExporter();

    // ---- Host helpers ----

    private async Task<WebApplicationFactory<Program>> StartNormalHostAsync(
        IReadOnlyDictionary<string, string>? settingOverrides = null,
        CapturingLoggerProvider? logs = null,
        Action<IServiceCollection>? configureServices = null,
        bool track = true)
    {
        var bootstrapPath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
            Path.Combine(_directory, "normal"),
            new DatabaseOptions { Provider = "SQLite", ConnectionString = _connectionString },
            RootSecret,
            AdminUsername,
            AdminPassword,
            settingOverrides,
            TestContext.Current.CancellationToken);
        var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Bootstrap:FilePath", bootstrapPath);
            builder.UseSetting("Endpoints:Http", "0");
            builder.ConfigureTestServices(services =>
            {
                configureServices?.Invoke(services);
                if (logs is not null)
                {
                    services.RemoveAll<ILoggerFactory>();
                    services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
                    {
                        logging.AddProvider(logs);
                        logging.SetMinimumLevel(LogLevel.Information);
                    }));
                }
            });
        });
        if (track)
        {
            _factories.Add(factory);
        }

        _ = factory.Services;
        return factory;
    }

    private async Task SeedApplicationsAsync()
    {
        await using var db = CreateDbContext();
        db.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = ScraperId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(_scraperSecret),
            AppName = "Metrics Scraper",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        db.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = PublicClientId,
            AppSecretHash = string.Empty,
            AppName = "Metrics Public Client",
            ClientType = OidcClientType.Public,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    /// <summary>One gateway password-grant failure records the product login metrics.</summary>
    private async Task DriveProductMetricAsync(HttpClient client)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/token")
        {
            Content = JsonContent.Create(new { grantType = "password", username = "nobody", password = "wrong" })
        };
        request.Headers.Add("X-Admin-AppId", ScraperId);
        request.Headers.Add("X-Admin-AppSecret", _scraperSecret);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static Task<HttpResponseMessage> ScrapeAsync(
        HttpClient client,
        string? appId,
        string? appSecret,
        HttpMethod? method = null)
    {
        var request = new HttpRequestMessage(method ?? HttpMethod.Get, SignaCoreTelemetry.MetricsPath);
        if (appId is not null)
        {
            request.Headers.Add("X-Admin-AppId", appId);
        }

        if (appSecret is not null)
        {
            request.Headers.Add("X-Admin-AppSecret", appSecret);
        }

        return client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private IdentityDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<IdentityDbContext>();
        options.UseIdentityDatabase(new DatabaseOptions { Provider = "SQLite", ConnectionString = _connectionString });
        return new IdentityDbContext(options.Options);
    }

    private static async Task<HttpClient> CreateAdminClientAsync(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
        using var login = new HttpRequestMessage(HttpMethod.Post, Root + "/session/login")
        {
            Content = JsonContent.Create(new { username = AdminUsername, password = AdminPassword })
        };
        login.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        using var response = await client.SendAsync(login, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        client.DefaultRequestHeaders.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        return client;
    }

    private static async Task<long> ReadVersionAsync(HttpClient admin)
    {
        using var response = await admin.GetAsync(Root + "/settings", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>(
                cancellationToken: TestContext.Current.CancellationToken))
            .GetProperty("version").GetInt64();
    }

    private static Task<HttpResponseMessage> PostSettingAsync(HttpClient admin, long version, string endpoint) =>
        admin.PostAsJsonAsync(
            Root + "/settings",
            new
            {
                expectedVersion = version,
                changes = new[] { new { key = "opentelemetry.otlp_endpoint", value = endpoint } }
            },
            TestContext.Current.CancellationToken);

    private static Type ServiceMantleType(string fullName) =>
        typeof(OpenTelemetryOptions).Assembly.GetType(fullName, throwOnError: true)!;

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "SignaCore.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("The repository root was not found.");
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly List<string> _lines = [];

        public IReadOnlyList<string> Lines
        {
            get
            {
                lock (_lines)
                {
                    return _lines.ToArray();
                }
            }
        }

        public ILogger CreateLogger(string categoryName) => new Logger(this);

        public void Dispose()
        {
        }

        private sealed class Logger(CapturingLoggerProvider owner) : ILogger
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
                lock (owner._lines)
                {
                    owner._lines.Add(formatter(state, exception) + (exception is null ? string.Empty : " " + exception));
                }
            }
        }
    }
}
