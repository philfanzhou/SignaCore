using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ServiceMantle.Logging.Pipeline;
using ServiceMantle.Logging.Remote;
using ServiceMantle.Logging;
using ServiceMantle.Web.Logging;
using SignaCore.Database;
using SignaCore.Host.Configuration;
using SignaCore.Host.Logging;
using SignaCore.Host.Startup;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Http.Json;
using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
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
/// Loki delivery is captured by a loopback fake that speaks plain HTTP — the stored endpoint the
/// product itself now accepts and delivers to, with no test-only adjustment of the registered
/// options: plain http and https are equal inputs, so the stored value is the delivered value.
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
        _directory = Path.Combine(PhysicalTempPath.Root(), $"signacore-logging-{Guid.NewGuid():N}");
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
            "ServiceMantle.Logging",
            Assert.Single(services.GetServices<ILoggerProvider>()).GetType().Assembly.GetName().Name);
        Assert.StartsWith(
            "ServiceMantle",
            services.GetRequiredService<StructuredLogSanitizer>().GetType().Assembly.GetName().Name,
            StringComparison.Ordinal);

        // Only the normal host has a setting snapshot, so only it composes the Loki sink.
        var lokiRuntime = services.GetService(ServiceMantleType("ServiceMantle.Logging.Remote.GrafanaLokiRuntime"));
        var resolver = services.GetService<IRemoteLogAuthorizationResolver>();
        Assert.Equal(branch == "normal", lokiRuntime is not null);
        Assert.Null(resolver);
    }

    [Fact]
    public async Task PipelineCheck_FailsWhenTheProviderIsReplacedByALocalWrapper()
    {
        // The negative variant of the check above: a transparent local wrapper around the very
        // same ServiceMantle provider is still a second, locally owned pipeline boundary.
        using var capture = new ConsoleCapture();
        var factory = await StartNormalHostAsync(configureServices: services =>
        {
            var runtimeProviderType = ServiceMantleType("ServiceMantle.Logging.Pipeline.RuntimeLoggerProvider");
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
        Assert.Contains("<PackageReference Include=\"ServiceMantle.Logging\" />", project, StringComparison.Ordinal);

        // Negative variants: the same checks detect a local provider type and a direct package.
        Assert.Contains(
            nameof(TransparentLoggerProvider),
            LocalLoggingInfrastructure(typeof(ServiceMantleLoggingTests).Assembly));
        Assert.Equal(
            ["Serilog.Sinks.Console"],
            DirectSerilogPackages(project.Replace(
                "<PackageReference Include=\"ServiceMantle.Logging\" />",
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
                [SystemSettingKeys.LokiUri] = loki.HttpAddress,
                [SystemSettingKeys.LokiAuthorization] = authorization
            },
            services =>
            {
                var options = RegisteredLokiOptions(services);
                decided.Add((options.Enabled, options.Endpoint, options.AuthorizationHeaderResolverName));
            });

        var decision = Assert.Single(decided);
        Assert.True(decision.Enabled);
        Assert.Equal(new Uri(loki.HttpAddress), decision.Endpoint);
        Assert.Equal(ServiceMantleGrafanaLokiHostApplicationBuilderExtensions.SettingDrivenAuthorizationResolverName, decision.ResolverName);

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

    [Fact]
    public async Task PlainHttpWithoutAuthentication_DeliversRealHttpWithNoAuthorizationHeader()
    {
        // The normal production path — a real Production environment, not the hosted-login Testing
        // policy: a plain-HTTP loopback endpoint behind the explicit no-authentication opt-in,
        // with no credential stored, no resolver registered, and no transport switch at all.
        await using var loki = await FakeLoki.StartAsync();
        using var capture = new ConsoleCapture();
        var decided = new List<(bool Enabled, Uri? Endpoint, string? ResolverName)>();
        var factory = await StartNormalHostAsync(
            new Dictionary<string, string>
            {
                [SystemSettingKeys.LokiUri] = loki.HttpAddress,
                [SystemSettingKeys.LokiAllowNoAuthentication] = "true"
            },
            services => decided.Add((RegisteredLokiOptions(services).Enabled,
                RegisteredLokiOptions(services).Endpoint,
                RegisteredLokiOptions(services).AuthorizationHeaderResolverName)),
            environment: Environments.Production);
        using var client = factory.CreateClient();

        using var ready = await client.GetAsync("/health/ready", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);

        var decision = Assert.Single(decided);
        Assert.True(decision.Enabled);
        Assert.Equal(new Uri(loki.HttpAddress), decision.Endpoint);
        Assert.Null(decision.ResolverName);
        Assert.Empty(factory.Services.GetServices<IRemoteLogAuthorizationResolver>());
        Assert.DoesNotContain(LokiWarning, capture.Output, StringComparison.Ordinal);

        var canary = "canary-" + Guid.NewGuid().ToString("N");
        var marker = "probe-" + Guid.NewGuid().ToString("N");
        WriteProbe(factory.Services, marker, canary);

        var batch = await loki.WaitForBodyContainingAsync(marker);
        // No authentication: the request carries no Authorization header at all.
        Assert.Equal(string.Empty, batch.Authorization);
        Assert.Contains(marker, batch.Body, StringComparison.Ordinal);
        Assert.DoesNotContain(canary, batch.Body, StringComparison.Ordinal);
        Assert.DoesNotContain(canary, capture.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnreachablePlainHttpLokiEndpoint_NeverBlocksTheIdentityService()
    {
        // The explicit opt-in never makes delivery a readiness concern: an endpoint nothing
        // listens on keeps the identity service ready, the probe write never throws, and the
        // Console keeps receiving the sanitized line.
        using var capture = new ConsoleCapture();
        var factory = await StartNormalHostAsync(new Dictionary<string, string>
        {
            [SystemSettingKeys.LokiUri] = "http://127.0.0.1:9/loki/api/v1/push",
            [SystemSettingKeys.LokiAllowNoAuthentication] = "true"
        });
        using var client = factory.CreateClient();

        using var ready = await client.GetAsync("/health/ready", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);

        var canary = "canary-" + Guid.NewGuid().ToString("N");
        var marker = "probe-" + Guid.NewGuid().ToString("N");
        WriteProbe(factory.Services, marker, canary);
        // Leave the doomed batch a delivery-attempt window; neither readiness nor the Console
        // depends on it.
        await Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
        Assert.Contains(marker, capture.Output, StringComparison.Ordinal);
        Assert.DoesNotContain(canary, capture.Output, StringComparison.Ordinal);
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
        Assert.Empty(factory.Services.GetServices<IRemoteLogAuthorizationResolver>());
    }

    [Theory]
    [InlineData("http://loki-legacy.example.com:3100", "", false, "authorization_missing")]
    [InlineData("http://loki-legacy.example.com:3100", "Basic bGVnYWN5OnZhbHVl", true, "authorization_invalid")]
    [InlineData("https://loki-legacy.example.com", "", false, "authorization_missing")]
    [InlineData("", "Bearer fixture", false, "endpoint_missing")]
    [InlineData("https://loki-legacy.example.com", "Bearer a\nb", false, "authorization_invalid")]
    [InlineData("https://loki-legacy.example.com", "Bearer fixture", true, "authorization_invalid")]
    public async Task StoredValuesLokiCannotUse_StartWithLokiOffAndAFixedWarning(
        string uri,
        string authorization,
        bool allowNoAuthentication,
        string category)
    {
        using var capture = new ConsoleCapture();
        bool? enabled = null;
        var overrides = new Dictionary<string, string>
        {
            [SystemSettingKeys.LokiUri] = uri,
            [SystemSettingKeys.LokiAuthorization] = authorization
        };
        if (allowNoAuthentication)
        {
            overrides[SystemSettingKeys.LokiAllowNoAuthentication] = "true";
        }

        var factory = await StartNormalHostAsync(
            overrides,
            services => enabled = RegisteredLokiOptions(services).Enabled);
        using var client = factory.CreateClient();

        using var ready = await client.GetAsync("/health/ready", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
        Assert.False(enabled);
        Assert.Empty(factory.Services.GetServices<IRemoteLogAuthorizationResolver>());
        var warning = Assert.Single(capture.Lines(), line => line.Contains(LokiWarning, StringComparison.Ordinal));
        Assert.Contains(category, warning, StringComparison.Ordinal);
        Assert.DoesNotContain("loki-legacy", capture.Output, StringComparison.Ordinal);
        if (authorization.Length > 0)
        {
            Assert.DoesNotContain(authorization, capture.Output, StringComparison.Ordinal);
        }

        // Legacy optional logging remains readable and cannot block unrelated valid saves.
        // Explicitly touching its group remains strict; capability validators do not change codes.
        using var admin = await CreateAdminClientAsync(factory);
        await using var db = CreateDbContext();
        var version = (await SharedSettingTestDatabase.LoadAggregateAsync(
            db, TestContext.Current.CancellationToken))!.Version;
        var audits = await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(db, TestContext.Current.CancellationToken);
        Assert.Equal(version, await ReadVersionAsync(admin));
        using var accepted = await PostSettingsAsync(admin, version, [("jwt.audience", "recovered-audience")]);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal(version + 1, await ReadVersionAsync(admin));
        Assert.Equal(version + 1, (await SharedSettingTestDatabase.LoadAggregateAsync(
            db, TestContext.Current.CancellationToken))!.Version);
        Assert.Equal(audits.Count + 1, (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
            db, TestContext.Current.CancellationToken)).Count);
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
            [("loki.uri", "https://user:pass@loki.example.com"), ("loki.authorization", authorization)],
            [("loki.uri", "http://user:pass@loki.example.com:3100"), ("loki.authorization", authorization)],
            [("loki.uri", "https://loki.example.com/?tenant=a"), ("loki.authorization", authorization)],
            [("loki.uri", "https://loki.example.com/#fragment"), ("loki.authorization", authorization)],
            [("loki.uri", "https://loki.example.com")],
            [("loki.authorization", authorization)],
            // The no-authentication opt-in cannot coexist with a stored credential in the same batch.
            [("loki.uri", "https://loki.example.com"), ("loki.authorization", authorization),
             ("loki.allow_no_authentication", "true")],
            // The retired insecure-transport switch is an unknown key: rejected like any other
            // retired name, with no typed rule behind it.
            [("loki.allow_insecure_http", "true")]
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
        var runtime = factory.Services.GetRequiredService(ServiceMantleType("ServiceMantle.Logging.Pipeline.SerilogRuntime"));

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
                [SystemSettingKeys.LokiUri] = loki.HttpAddress,
                [SystemSettingKeys.LokiAuthorization] = "Bearer " + Guid.NewGuid().ToString("N")
            },
            track: false);
        var runtime = factory.Services.GetRequiredService(ServiceMantleType("ServiceMantle.Logging.Pipeline.SerilogRuntime"));
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
    internal static IReadOnlyList<string> LoggingPipelineViolations(IServiceProvider services)
    {
        var violations = new List<string>();
        var providers = services.GetServices<ILoggerProvider>().ToList();
        if (providers.Count != 1)
        {
            violations.Add($"provider-count:{providers.Count}");
        }

        violations.AddRange(providers
            .Where(provider => provider.GetType().Assembly.GetName().Name != "ServiceMantle.Logging")
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
    internal static GrafanaLokiOptions RegisteredLokiOptions(IServiceCollection services)
    {
        var registration = Assert.Single(services, descriptor =>
            descriptor.ServiceType.FullName == "ServiceMantle.Logging.Remote.GrafanaLokiRegistration");
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
    internal static void WriteProbe(IServiceProvider services, string marker, string canary)
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

    internal static string RepositoryRoot()
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
    internal sealed class TransparentLoggerProvider(ILoggerProvider inner) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => inner.CreateLogger(categoryName);

        public void Dispose() => inner.Dispose();
    }

    internal sealed class ConsoleCapture : IDisposable
    {
        private readonly TextWriter _original = Console.Out;
        private readonly StringWriter _buffer = new();
        // The same synchronized wrapper Console.Out uses: reading the buffer takes the writer's
        // own lock, so a snapshot never races a concurrent pipeline write and corrupt the builder.
        private readonly TextWriter _captured;

        public ConsoleCapture()
        {
            _captured = TextWriter.Synchronized(_buffer);
            Console.SetOut(_captured);
        }

        public string Output
        {
            get
            {
                lock (_captured)
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
    internal sealed class FakeLoki : IAsyncDisposable
    {
        private readonly WebApplication _app;
        private readonly ConcurrentQueue<(string Authorization, string Body)> _batches = new();

        private FakeLoki(WebApplication app, int port)
        {
            _app = app;
            HttpAddress = $"http://127.0.0.1:{port}/";
        }

        /// <summary>
        /// The real loopback address, stored verbatim as the product setting: the endpoint accepts
        /// plain http, so the stored value is the delivered value.
        /// </summary>
        public string HttpAddress { get; }

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
