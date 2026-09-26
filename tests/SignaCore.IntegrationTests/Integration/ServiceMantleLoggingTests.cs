using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ServiceMantle.AspNetCore.Logging;
using ServiceMantle.Logging;
using ServiceMantle.Serilog;
using ServiceMantle.Serilog.GrafanaLoki;
using SignaCore.Database;
using SignaCore.Host.Configuration;
using SignaCore.Host.Logging;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Console output is process-wide, so the classes that redirect it run alone: a parallel class
/// restoring <see cref="Console.Out"/> in the middle of a capture would drop lines silently.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class HostConsoleCaptureCollection
{
    public const string Name = "host-console-capture";
}

/// <summary>
/// The product host's logging runs only through the ServiceMantle Serilog pipeline: all three host
/// branches, the mandatory structured-field sanitization on the Console and on Loki, the Loki
/// configuration-state table, the management validation of the Loki pair, the shipped category
/// levels, and the one-time flush on shutdown.
/// </summary>
/// <remarks>
/// Loki delivery is captured by a loopback fake. The product host never accepts a plain-HTTP
/// endpoint, so the test enables the ServiceMantle test-only loopback option by adjusting the
/// already-registered options before the host is built; everything the product decided (enabled,
/// the stored HTTPS endpoint, the resolver name) is asserted before that adjustment.
/// </remarks>
[Collection(HostConsoleCaptureCollection.Name)]
public sealed class ServiceMantleLoggingTests : IAsyncLifetime
{
    private const string RootSecret = "test-master-key-for-logging-tests-only";
    private const string AdminUsername = "logging_admin";
    private const string AdminPassword = "LoggingAdmin123";
    private const string Root = "/management/v1";
    private const string LokiWarning = "Remote log shipping to Loki is disabled";

    private readonly List<WebApplicationFactory<Program>> _factories = [];
    private string _directory = string.Empty;
    private string _connectionString = string.Empty;

    public ValueTask InitializeAsync()
    {
        _directory = Path.Combine(Path.GetTempPath(), $"signacore-logging-{Guid.NewGuid():N}");
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
            // A pooled SQLite handle can outlive the host briefly; the temporary directory is
            // uniquely named, so leaving it behind cannot affect another test.
        }
    }

    // ---- Architecture: one pipeline, owned by ServiceMantle, in every host branch ----

    [Theory]
    [InlineData("bootstrap")]
    [InlineData("setup")]
    [InlineData("normal")]
    public async Task EveryHostBranch_UsesOnlyTheServiceMantlePipeline(string branch)
    {
        using var capture = new ConsoleCapture();
        var factory = branch switch
        {
            "bootstrap" => StartBootstrapModeHost(),
            "setup" => await StartSetupHostAsync(),
            _ => await StartNormalHostAsync()
        };

        var services = factory.Services;
        Assert.Empty(LoggingPipelineViolations(services));
        Assert.Equal(
            "ServiceMantle.Serilog",
            Assert.Single(services.GetServices<ILoggerProvider>()).GetType().Assembly.GetName().Name);
        Assert.StartsWith(
            "ServiceMantle",
            services.GetRequiredService<StructuredLogSanitizer>().GetType().Assembly.GetName().Name,
            StringComparison.Ordinal);

        // Only the normal host has a setting snapshot, so only it composes the Loki sink.
        var lokiRuntime = services.GetService(ServiceMantleType("ServiceMantle.Serilog.GrafanaLoki.GrafanaLokiRuntime"));
        var resolver = services.GetService<IRemoteLogAuthorizationResolver>();
        Assert.Equal(branch == "normal", lokiRuntime is not null);
        Assert.Equal(branch == "normal", resolver is not null);
    }

    [Fact]
    public async Task PipelineCheck_FailsWhenTheProviderIsReplacedByALocalWrapper()
    {
        // The negative variant of the check above: a transparent local wrapper around the very
        // same ServiceMantle provider is still a second, locally owned pipeline boundary.
        using var capture = new ConsoleCapture();
        var factory = await StartNormalHostAsync(configureServices: services =>
        {
            var runtimeProviderType = ServiceMantleType("ServiceMantle.Serilog.RuntimeLoggerProvider");
            services.RemoveAll<ILoggerProvider>();
            services.AddSingleton<ILoggerProvider>(serviceProvider => new TransparentLoggerProvider(
                (ILoggerProvider)ActivatorUtilities.CreateInstance(serviceProvider, runtimeProviderType)));
        });

        Assert.NotEmpty(LoggingPipelineViolations(factory.Services));
    }

    [Fact]
    public void HostAssemblyAndProject_CarryNoLocalLoggingInfrastructure()
    {
        var hostAssembly = typeof(SignaCoreLogging).Assembly;
        Assert.Empty(LocalLoggingInfrastructure(hostAssembly));
        Assert.DoesNotContain(
            hostAssembly.GetReferencedAssemblies(),
            reference => reference.Name!.StartsWith("Serilog", StringComparison.Ordinal));

        var project = File.ReadAllText(Path.Combine(RepositoryRoot(), "src", "SignaCore.Host", "SignaCore.Host.csproj"));
        Assert.Empty(DirectSerilogPackages(project));
        Assert.Contains("<PackageReference Include=\"ServiceMantle.Serilog\" />", project, StringComparison.Ordinal);

        // Negative variants: the same checks detect a local provider type and a direct package.
        Assert.Contains(
            nameof(TransparentLoggerProvider),
            LocalLoggingInfrastructure(typeof(ServiceMantleLoggingTests).Assembly));
        Assert.Equal(
            ["Serilog.Sinks.Console"],
            DirectSerilogPackages(project.Replace(
                "<PackageReference Include=\"ServiceMantle.Serilog\" />",
                "<PackageReference Include=\"Serilog.Sinks.Console\" />",
                StringComparison.Ordinal)));
    }

    // ---- Sanitized delivery to the Console and to Loki ----

    [Fact]
    public async Task EnabledLoki_ConsoleAndLokiCarryIdentityButNoCanary()
    {
        await using var loki = await FakeLoki.StartAsync();
        using var capture = new ConsoleCapture();
        var authorization = "Basic " + Convert.ToBase64String(Guid.NewGuid().ToByteArray());
        var decided = new List<(bool Enabled, Uri? Endpoint, string? ResolverName)>();
        var factory = await StartNormalHostAsync(
            new Dictionary<string, string>
            {
                [SystemSettingKeys.LokiUri] = loki.HttpsAddress,
                [SystemSettingKeys.LokiAuthorization] = authorization
            },
            services =>
            {
                var options = RegisteredLokiOptions(services);
                decided.Add((options.Enabled, options.Endpoint, options.AuthorizationHeaderResolverName));
                options.Endpoint = new Uri(loki.HttpAddress);
                options.AllowInsecureLoopbackForTesting = true;
            });

        var decision = Assert.Single(decided);
        Assert.True(decision.Enabled);
        Assert.Equal(new Uri(loki.HttpsAddress), decision.Endpoint);
        Assert.Equal(SignaCoreLogging.LokiAuthorizationResolverName, decision.ResolverName);

        var canary = "canary-" + Guid.NewGuid().ToString("N");
        var marker = "probe-" + Guid.NewGuid().ToString("N");
        WriteProbe(factory.Services, marker, canary);

        var batch = await loki.WaitForBodyContainingAsync(marker);
        Assert.Equal(authorization, batch.Authorization);
        foreach (var output in new[] { batch.Body, capture.Output })
        {
            Assert.DoesNotContain(canary, output, StringComparison.Ordinal);
            Assert.DoesNotContain(authorization, output, StringComparison.Ordinal);
            Assert.Contains(marker, output, StringComparison.Ordinal);
            Assert.Contains("ServiceName", output, StringComparison.Ordinal);
            Assert.Contains("ServiceVersion", output, StringComparison.Ordinal);
            Assert.Contains("InstanceId", output, StringComparison.Ordinal);
            Assert.Contains("signacore", output, StringComparison.Ordinal);
        }

        var probeLine = Assert.Single(capture.Lines(), line => line.Contains(marker, StringComparison.Ordinal));
        Assert.Contains("\"ServiceName\": \"signacore\"", probeLine, StringComparison.Ordinal);
        Assert.DoesNotContain(LokiWarning, capture.Output, StringComparison.Ordinal);
    }

    // ---- The configuration-state table ----

    [Fact]
    public async Task EmptySettings_ConsoleOnlyWithoutWarning()
    {
        await using var loki = await FakeLoki.StartAsync();
        using var capture = new ConsoleCapture();
        bool? enabled = null;
        var factory = await StartNormalHostAsync(configureServices: services =>
            enabled = RegisteredLokiOptions(services).Enabled);

        Assert.False(enabled);
        var marker = "probe-" + Guid.NewGuid().ToString("N");
        WriteProbe(factory.Services, marker, "unused");
        Assert.Contains(marker, capture.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(LokiWarning, capture.Output, StringComparison.Ordinal);
        Assert.Null(factory.Services.GetRequiredService<IRemoteLogAuthorizationResolver>()
            .ResolveAuthorizationHeader(SignaCoreLogging.LokiAuthorizationResolverName));
    }

    [Theory]
    [InlineData("http://loki-legacy.example.com:3100", "Basic bGVnYWN5OnZhbHVl", "endpoint_not_https")]
    [InlineData("http://loki-legacy.example.com:3100", "", "endpoint_not_https")]
    [InlineData("https://loki-legacy.example.com", "", "authorization_missing")]
    public async Task StoredValuesLokiCannotUse_StartWithLokiOffAndAFixedWarning(
        string uri,
        string authorization,
        string category)
    {
        using var capture = new ConsoleCapture();
        bool? enabled = null;
        var factory = await StartNormalHostAsync(
            new Dictionary<string, string>
            {
                [SystemSettingKeys.LokiUri] = uri,
                [SystemSettingKeys.LokiAuthorization] = authorization
            },
            services => enabled = RegisteredLokiOptions(services).Enabled);
        using var client = factory.CreateClient();

        using var ready = await client.GetAsync("/health/ready", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
        Assert.False(enabled);
        var warning = Assert.Single(capture.Lines(), line => line.Contains(LokiWarning, StringComparison.Ordinal));
        Assert.Contains(category, warning, StringComparison.Ordinal);
        Assert.DoesNotContain("loki-legacy", capture.Output, StringComparison.Ordinal);
        if (authorization.Length > 0)
        {
            Assert.DoesNotContain(authorization, capture.Output, StringComparison.Ordinal);
        }
    }

    // ---- Management validation of the Loki pair ----

    [Fact]
    public async Task ManagementUpdate_RejectsUnusableLokiPairsAndNeverEchoesTheCredential()
    {
        using var capture = new ConsoleCapture();
        var factory = await StartNormalHostAsync();
        using var admin = await CreateAdminClientAsync(factory);
        var version = await ReadVersionAsync(admin);
        var authorization = "Bearer " + Guid.NewGuid().ToString("N");

        (string Key, string Value)[][] rejected =
        [
            [("loki.uri", "http://loki.example.com:3100"), ("loki.authorization", authorization)],
            [("loki.uri", "https://user:pass@loki.example.com"), ("loki.authorization", authorization)],
            [("loki.uri", "https://loki.example.com/?tenant=a"), ("loki.authorization", authorization)],
            [("loki.uri", "https://loki.example.com/#fragment"), ("loki.authorization", authorization)],
            [("loki.uri", "https://loki.example.com")],
            [("loki.authorization", authorization)]
        ];
        foreach (var changes in rejected)
        {
            using var response = await PostSettingsAsync(admin, version, changes);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
            Assert.Contains("management.request.invalid", body, StringComparison.Ordinal);
            Assert.DoesNotContain(authorization, body, StringComparison.Ordinal);
            Assert.DoesNotContain("loki.example.com", body, StringComparison.Ordinal);
            Assert.Equal(version, await ReadVersionAsync(admin));
        }

        using (var accepted = await PostSettingsAsync(
                   admin,
                   version,
                   [("loki.uri", "https://loki.example.com"), ("loki.authorization", authorization)]))
        {
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        }

        Assert.Equal(version + 1, await ReadVersionAsync(admin));
        using var current = await admin.GetAsync(Root + "/settings", TestContext.Current.CancellationToken);
        var settings = await current.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("loki.authorization", settings, StringComparison.Ordinal);
        Assert.DoesNotContain(authorization, settings, StringComparison.Ordinal);
        Assert.DoesNotContain(authorization, capture.Output, StringComparison.Ordinal);

        await using var db = CreateDbContext();
        var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(db, TestContext.Current.CancellationToken);
        var stored = SharedSettingTestDatabase.ParseValues(aggregate!)["loki.authorization"];
        Assert.DoesNotContain(authorization, aggregate!.ValuesJson, StringComparison.Ordinal);
        Assert.NotEqual(authorization, stored);
        Assert.NotEmpty(stored);
    }

    // ---- Shipped category levels ----

    [Fact]
    public async Task ShippedCategoryLevels_KeepFrameworkCategoriesAtWarning()
    {
        var root = RepositoryRoot();
        using var shipped = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "src", "SignaCore.Host", "appsettings.json")));
        var levels = shipped.RootElement.GetProperty("Logging").GetProperty("LogLevel");
        Assert.Equal("Information", levels.GetProperty("Default").GetString());
        Assert.True(Enum.Parse<LogLevel>(levels.GetProperty("Microsoft.AspNetCore").GetString()!) >= LogLevel.Warning);
        Assert.True(Enum.Parse<LogLevel>(levels.GetProperty("Microsoft.EntityFrameworkCore").GetString()!) >= LogLevel.Warning);
        Assert.False(shipped.RootElement.TryGetProperty("Serilog", out _));
        using var production = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "src", "SignaCore.Host", "appsettings.Production.json")));
        Assert.Equal("Error", production.RootElement.GetProperty("Logging").GetProperty("LogLevel")
            .GetProperty("Microsoft.EntityFrameworkCore").GetString());

        // The running host applies them through the MEL filter in front of the shared pipeline.
        using var capture = new ConsoleCapture();
        var factory = await StartNormalHostAsync(environment: Environments.Production);
        var loggers = factory.Services.GetRequiredService<ILoggerFactory>();
        Assert.False(loggers.CreateLogger("Microsoft.AspNetCore.Hosting.Diagnostics").IsEnabled(LogLevel.Information));
        Assert.False(loggers.CreateLogger("Microsoft.EntityFrameworkCore.Database.Command").IsEnabled(LogLevel.Warning));
        Assert.True(loggers.CreateLogger("SignaCore.Host").IsEnabled(LogLevel.Information));
    }

    // ---- Shutdown flush ----

    [Fact]
    public async Task Shutdown_FlushesOnceAndWithoutLokiDoesNotWaitOnARemote()
    {
        using var capture = new ConsoleCapture();
        var factory = await StartNormalHostAsync(track: false);
        var runtime = factory.Services.GetRequiredService(ServiceMantleType("ServiceMantle.Serilog.SerilogRuntime"));

        var stopwatch = Stopwatch.StartNew();
        await factory.DisposeAsync();
        stopwatch.Stop();

        Assert.Equal(1, FlushInvocationCount(runtime));
        Assert.True(
            stopwatch.Elapsed < GrafanaLokiDefaults.ShutdownDrainTimeout,
            $"Stopping without Loki took {stopwatch.Elapsed}.");
    }

    [Fact]
    public async Task Shutdown_WithLoki_FlushesOnceAndDeliversTheLastEvents()
    {
        await using var loki = await FakeLoki.StartAsync();
        using var capture = new ConsoleCapture();
        var factory = await StartNormalHostAsync(
            new Dictionary<string, string>
            {
                [SystemSettingKeys.LokiUri] = loki.HttpsAddress,
                [SystemSettingKeys.LokiAuthorization] = "Bearer " + Guid.NewGuid().ToString("N")
            },
            services =>
            {
                var options = RegisteredLokiOptions(services);
                options.Endpoint = new Uri(loki.HttpAddress);
                options.AllowInsecureLoopbackForTesting = true;
            },
            track: false);
        var runtime = factory.Services.GetRequiredService(ServiceMantleType("ServiceMantle.Serilog.SerilogRuntime"));
        var marker = "probe-" + Guid.NewGuid().ToString("N");
        WriteProbe(factory.Services, marker, "unused");

        var stopwatch = Stopwatch.StartNew();
        await factory.DisposeAsync();
        stopwatch.Stop();

        // Stopping drains the pending batch; the whole stop stays inside the drain plus flush bounds.
        Assert.Contains(loki.Bodies, body => body.Contains(marker, StringComparison.Ordinal));
        Assert.Equal(1, FlushInvocationCount(runtime));
        Assert.True(
            stopwatch.Elapsed < GrafanaLokiDefaults.ShutdownDrainTimeout + SerilogDefaults.FlushTimeout + TimeSpan.FromSeconds(5),
            $"Stopping with Loki took {stopwatch.Elapsed}.");
    }

    // ---- Checks ----

    /// <summary>
    /// Every registered logger provider and the sanitizer must be ServiceMantle's own instances;
    /// a SignaCore or test type in front of them is a locally owned logging boundary.
    /// </summary>
    private static IReadOnlyList<string> LoggingPipelineViolations(IServiceProvider services)
    {
        var violations = new List<string>();
        var providers = services.GetServices<ILoggerProvider>().ToList();
        if (providers.Count != 1)
        {
            violations.Add($"provider-count:{providers.Count}");
        }

        violations.AddRange(providers
            .Where(provider => provider.GetType().Assembly.GetName().Name != "ServiceMantle.Serilog")
            .Select(provider => "provider:" + provider.GetType().Name));
        var sanitizer = services.GetService<StructuredLogSanitizer>();
        if (sanitizer is null ||
            sanitizer.GetType().Assembly.GetName().Name?.StartsWith("ServiceMantle", StringComparison.Ordinal) != true)
        {
            violations.Add("sanitizer");
        }

        return violations;
    }

    /// <summary>Types that implement a logging provider or any Serilog sink/enricher contract.</summary>
    private static IReadOnlyList<string> LocalLoggingInfrastructure(Assembly assembly) =>
        assembly.GetTypes()
            .Where(type =>
                typeof(ILoggerProvider).IsAssignableFrom(type) ||
                type.GetInterfaces().Any(contract => contract.Assembly.GetName().Name!.StartsWith("Serilog", StringComparison.Ordinal)) ||
                (type.BaseType?.Assembly.GetName().Name?.StartsWith("Serilog", StringComparison.Ordinal) ?? false))
            .Select(type => type.Name)
            .ToList();

    private static IReadOnlyList<string> DirectSerilogPackages(string project) =>
        Regex.Matches(project, "<PackageReference\\s+Include=\"(Serilog[^\"]*)\"")
            .Select(match => match.Groups[1].Value)
            .ToList();

    // ---- Host helpers ----

    private WebApplicationFactory<Program> StartBootstrapModeHost()
    {
        var bootstrapPath = Path.Combine(_directory, "unconfigured", "signacore.bootstrap.json");
        Directory.CreateDirectory(Path.GetDirectoryName(bootstrapPath)!);
        return Track(new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("environment", Environments.Production);
            builder.UseSetting("Bootstrap:FilePath", bootstrapPath);
            builder.UseSetting("Endpoints:Http", "0");
        }), start: true);
    }

    private async Task<WebApplicationFactory<Program>> StartSetupHostAsync()
    {
        var bootstrapPath = await InstallationTestSupport.PrepareUninstalledBootstrapAsync(
            Path.Combine(_directory, "setup"),
            new DatabaseOptions { Provider = "SQLite", ConnectionString = _connectionString },
            RootSecret,
            TestContext.Current.CancellationToken);
        return Track(new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("environment", Environments.Production);
            builder.UseSetting("Bootstrap:FilePath", bootstrapPath);
            builder.UseSetting("Endpoints:Http", "0");
        }), start: true);
    }

    private async Task<WebApplicationFactory<Program>> StartNormalHostAsync(
        IReadOnlyDictionary<string, string>? settingOverrides = null,
        Action<IServiceCollection>? configureServices = null,
        bool track = true,
        string? environment = null)
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
            if (environment is not null)
            {
                builder.UseSetting("environment", environment);
            }

            builder.UseSetting("Bootstrap:FilePath", bootstrapPath);
            builder.UseSetting("Endpoints:Http", "0");
            builder.ConfigureTestServices(services => configureServices?.Invoke(services));
        });
        return track ? Track(factory, start: true) : Start(factory);
    }

    private WebApplicationFactory<Program> Track(WebApplicationFactory<Program> factory, bool start)
    {
        _factories.Add(factory);
        return start ? Start(factory) : factory;
    }

    private static WebApplicationFactory<Program> Start(WebApplicationFactory<Program> factory)
    {
        _ = factory.Services;
        return factory;
    }

    /// <summary>
    /// The options the product registered with the ServiceMantle Loki entry point. The registration
    /// record is internal to ServiceMantle; its options object is the public, mutable one the
    /// product configured, read before ServiceMantle normalizes it when the host starts.
    /// </summary>
    private static GrafanaLokiOptions RegisteredLokiOptions(IServiceCollection services)
    {
        var registration = Assert.Single(services, descriptor =>
            descriptor.ServiceType.FullName == "ServiceMantle.Serilog.GrafanaLoki.GrafanaLokiRegistration");
        var instance = registration.ImplementationInstance!;
        return (GrafanaLokiOptions)instance.GetType().GetProperty("Options")!.GetValue(instance)!;
    }

    private static Type ServiceMantleType(string fullName) =>
        typeof(SerilogOptions).Assembly.GetType(fullName, throwOnError: true)!;

    private static int FlushInvocationCount(object runtime) =>
        (int)runtime.GetType()
            .GetProperty("FlushInvocationCount", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(runtime)!;

    /// <summary>
    /// Writes one event through the host's own <see cref="ILogger"/> inside the ServiceMantle
    /// identity scope, with the canary in fields the shared sanitizer must redact.
    /// </summary>
    private static void WriteProbe(IServiceProvider services, string marker, string canary)
    {
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("SignaCore.Host.LoggingProbe");
        using (services.GetRequiredService<ServiceLogContext>().BeginScope(logger))
        {
            logger.LogWarning(
                "Logging probe {Marker} {password} {client_secret} {Authorization}",
                marker,
                canary,
                canary,
                canary);
        }
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

    private static Task<HttpResponseMessage> PostSettingsAsync(
        HttpClient admin,
        long version,
        IEnumerable<(string Key, string Value)> changes) =>
        admin.PostAsJsonAsync(
            Root + "/settings",
            new
            {
                expectedVersion = version,
                changes = changes.Select(change => new { key = change.Key, value = change.Value }).ToArray()
            },
            TestContext.Current.CancellationToken);

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

    /// <summary>A local provider wrapping the shared one: exactly what the pipeline check forbids.</summary>
    private sealed class TransparentLoggerProvider(ILoggerProvider inner) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => inner.CreateLogger(categoryName);

        public void Dispose() => inner.Dispose();
    }

    private sealed class ConsoleCapture : IDisposable
    {
        private readonly TextWriter _original = Console.Out;
        private readonly StringWriter _buffer = new();

        public ConsoleCapture() => Console.SetOut(TextWriter.Synchronized(_buffer));

        public string Output
        {
            get
            {
                lock (_buffer)
                {
                    return _buffer.ToString();
                }
            }
        }

        public IEnumerable<string> Lines() => Output.Split('\n');

        public void Dispose()
        {
            Console.SetOut(_original);
            _buffer.Dispose();
        }
    }

    /// <summary>A loopback Loki push endpoint recording each batch and its Authorization header.</summary>
    private sealed class FakeLoki : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly ConcurrentQueue<(string Authorization, string Body)> _batches = new();

        private FakeLoki(WebApplication app, int port)
        {
            _app = app;
            HttpAddress = $"http://127.0.0.1:{port}/";
            HttpsAddress = $"https://127.0.0.1:{port}/";
        }

        public string HttpAddress { get; }

        /// <summary>The address stored as the product setting; only the scheme differs.</summary>
        public string HttpsAddress { get; }

        public IReadOnlyList<string> Bodies => _batches.Select(batch => batch.Body).ToList();

        public static async Task<FakeLoki> StartAsync()
        {
            var builder = WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            var app = builder.Build();
            FakeLoki? fake = null;
            app.MapPost("/loki/api/v1/push", async (HttpContext context) =>
            {
                using var reader = new StreamReader(context.Request.Body);
                var body = await reader.ReadToEndAsync(context.RequestAborted);
                fake!._batches.Enqueue((context.Request.Headers.Authorization.ToString(), body));
                return Results.NoContent();
            });
            await app.StartAsync(TestContext.Current.CancellationToken);
            var port = new Uri(app.Urls.Single()).Port;
            fake = new FakeLoki(app, port);
            return fake;
        }

        public async Task<(string Authorization, string Body)> WaitForBodyContainingAsync(string marker)
        {
            var deadline = DateTime.UtcNow.AddSeconds(30);
            while (DateTime.UtcNow < deadline)
            {
                foreach (var batch in _batches)
                {
                    if (batch.Body.Contains(marker, StringComparison.Ordinal))
                    {
                        return batch;
                    }
                }

                await Task.Delay(100, TestContext.Current.CancellationToken);
            }

            throw new TimeoutException("The fake Loki did not receive the probe batch.");
        }

        public async ValueTask DisposeAsync() => await _app.DisposeAsync();
    }
}
