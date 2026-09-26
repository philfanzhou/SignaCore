using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ServiceMantle.Consul;
using ServiceMantle.Health;
using SignaCore.Database;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class ConsulRealAgentAcceptanceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TwoHosts_ReadinessRestartAndStop_PreserveIndependentRegistrations(bool reverse)
    {
        RequireAgent();
        await using var fixture = await AgentFixture.CreateAsync();
        var a = fixture.StartHost();
        var b = fixture.StartHost();
        var first = reverse ? b : a;
        var other = reverse ? a : b;
        await a.AssertReadyAsync(false);
        await b.AssertReadyAsync(false);
        await fixture.WaitAsync(() => Task.FromResult(a.Readiness.Samples >= 3 && b.Readiness.Samples >= 3));
        Assert.Empty(await fixture.ServicesAsync());
        Assert.Empty(fixture.Proxy.Requests);

        a.Readiness.Ready = b.Readiness.Ready = true;
        await a.AssertReadyAsync(true);
        await b.AssertReadyAsync(true);
        await fixture.WaitServicesAsync(2);
        var initial = await fixture.ServicesAsync();
        var firstId = IdAt(initial, first.Port);
        var otherId = IdAt(initial, other.Port);
        Assert.NotEqual(firstId, otherId);
        await fixture.AssertPassingAsync(firstId, first.Port, "/health/ready");
        await fixture.AssertPassingAsync(otherId, other.Port, "/health/ready");
        Assert.All(initial.Values, row =>
        {
            Assert.Equal("127.0.0.1", row.GetProperty("Address").GetString());
            Assert.Equal("SignaCore", row.GetProperty("Service").GetString());
        });
        var samples = a.Readiness.Samples;
        await fixture.WaitAsync(() => Task.FromResult(a.Readiness.Samples >= samples + 3));
        Assert.Equal(2, fixture.Proxy.Requests.Count(x => x.Kind == "register"));

        foreach (var host in new[] { first, other, first })
        {
            host.Readiness.Ready = false;
            await host.AssertReadyAsync(false);
            await fixture.WaitServicesAsync(1);
            var remaining = await fixture.ServicesAsync();
            Assert.True(remaining.ContainsKey(host == first ? otherId : firstId));
            host.Readiness.Ready = true;
            await fixture.WaitServicesAsync(2);
            Assert.Equal(initial.Keys.Order(), (await fixture.ServicesAsync()).Keys.Order());
        }

        // Both live owners retain version N after the authenticated aggregate update.
        await first.UpdateAsync(new Dictionary<string, string>
        {
            ["consul.discovery.service_name"] = "SignaCoreNext",
            ["consul.discovery.health_check_path"] = "/health"
        });
        first.Readiness.Ready = false;
        await fixture.WaitServicesAsync(1);
        first.Readiness.Ready = true;
        await fixture.WaitServicesAsync(2);
        Assert.All((await fixture.ServicesAsync()).Values,
            row => Assert.Equal("SignaCore", row.GetProperty("Service").GetString()));
        await fixture.AssertPassingAsync(firstId, first.Port, "/health/ready");
        await first.StopAsync();
        await fixture.WaitServicesAsync(1);
        Assert.True((await fixture.ServicesAsync()).ContainsKey(otherId));
        await other.StopAsync();
        await fixture.WaitServicesAsync(0);

        var nextA = fixture.StartHost(ready: true);
        var nextB = fixture.StartHost(ready: true);
        await fixture.WaitServicesAsync(2);
        var next = await fixture.ServicesAsync();
        Assert.All(next.Values, row => Assert.Equal("SignaCoreNext", row.GetProperty("Service").GetString()));
        Assert.DoesNotContain(firstId, next.Keys);
        Assert.DoesNotContain(otherId, next.Keys);
        await fixture.AssertPassingAsync(IdAt(next, nextA.Port), nextA.Port, "/health");
        await fixture.AssertPassingAsync(IdAt(next, nextB.Port), nextB.Port, "/health");
        await nextA.UpdateAsync(new Dictionary<string, string> { ["consul.discovery.enabled"] = "false" });
        await nextA.StopAsync();
        await nextB.StopAsync();
        await fixture.WaitServicesAsync(0);
        var beforeDisabled = fixture.Proxy.Requests.Count;
        var disabledA = fixture.StartHost(ready: true);
        var disabledB = fixture.StartHost(ready: true);
        await disabledA.AssertReadyAsync(true);
        await disabledB.AssertReadyAsync(true);
        await disabledA.StopAsync();
        await disabledB.StopAsync();
        Assert.Equal(0, disabledA.Clients.Created);
        Assert.Equal(0, disabledB.Clients.Created);
        Assert.Equal(beforeDisabled, fixture.Proxy.Requests.Count);
        fixture.AssertSafe();
    }

    [Fact]
    public async Task UnavailableThenLostResponse_RetriesTheSameIdentity_AndCancelledStopDoesNotClaimAbsence()
    {
        RequireAgent();
        await using var fixture = await AgentFixture.CreateAsync(startAgent: false);
        var host = fixture.StartHost(ready: true);
        await host.AssertReadyAsync(true);
        await fixture.WaitAsync(() => Task.FromResult(fixture.Proxy.Requests.Count >= 2));
        Assert.All(fixture.Proxy.Requests, request => Assert.False(request.Forwarded));
        fixture.Proxy.DropNextRegisterResponse = true;
        await fixture.StartAgentAsync();
        await fixture.WaitAsync(() => Task.FromResult(fixture.Proxy.Requests.Any(x => x.Dropped)));
        await fixture.WaitAsync(() => Task.FromResult(host.Clients.SuccessfulRegisters == 1));
        var registrations = fixture.Proxy.Requests.Where(x => x.Kind == "register").ToArray();
        Assert.True(registrations.Count(x => x.Forwarded) >= 2);
        Assert.Single(registrations.Select(x => x.Id).Distinct());
        var id = Assert.Single(await fixture.ServicesAsync()).Key;
        Assert.Equal(registrations[0].Id, id);
        Assert.Contains(host.Clients.Results, x => x == ConsulClientResult.Unavailable);
        // Unavailable after a forwarded request maps to Unknown in the shared state model;
        // observing one agent row alone would not prove that the owner retried.

        // Cancel while a real deregistration response is held after the agent accepted it.
        fixture.Proxy.HoldDeregisterResponse = true;
        using var cancellation = new CancellationTokenSource();
        var stopping = host.StopLifecycleAsync(cancellation.Token);
        await fixture.Proxy.DeregisterForwarded.Task.WaitAsync(TimeSpan.FromSeconds(20), TestContext.Current.CancellationToken);
        cancellation.Cancel();
        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => stopping);
        Assert.Equal(cancellation.Token, exception.CancellationToken);
        fixture.Scan(exception.ToString(), "cancelled stop exception");
        var registersAtStop = fixture.Proxy.Requests.Count(x => x.Kind == "register");
        fixture.Proxy.ReleaseDeregister.TrySetResult();
        // This experiment observed absence, but the cancelled owner may only report Unknown.
        Assert.False((await fixture.ServicesAsync()).ContainsKey(id));
        await host.DisposeAsync();
        Assert.Equal(registersAtStop, fixture.Proxy.Requests.Count(x => x.Kind == "register"));
        Assert.Equal(1, host.Clients.Disposed);
        Assert.Single(fixture.Proxy.Requests, x => x.Kind == "deregister");
        fixture.AssertSafe();
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, true, true)]
    [InlineData(true, false, false)]
    public async Task DisabledAndQueryOnly_CreateNoClientOrConnection(bool enabled, bool register, bool deregister)
    {
        RequireAgent();
        await using var fixture = await AgentFixture.CreateAsync(enabled: enabled, register: register, deregister: deregister);
        var a = fixture.StartHost(ready: true);
        var b = fixture.StartHost(ready: true);
        await a.AssertReadyAsync(true);
        await b.AssertReadyAsync(true);
        await a.StopAsync();
        await b.StopAsync();
        Assert.Equal(0, a.Clients.Created + b.Clients.Created);
        Assert.Empty(fixture.Proxy.Requests);
        Assert.Empty(await fixture.ServicesAsync());
        fixture.AssertSafe();
    }

    [Theory]
    [InlineData("host log")]
    [InlineData("metrics")]
    [InlineData("exception")]
    [InlineData("transport JSON/URL")]
    public void CanaryScanner_RejectsInjectedToken_WithoutPrintingIt(string carrier)
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ScanToken("prefix" + AgentFixture.Token, carrier));
        Assert.DoesNotContain(AgentFixture.Token, exception.ToString());
        Assert.Contains(carrier, exception.Message);
    }

    private static void RequireAgent() => Assert.SkipUnless(
        Environment.GetEnvironmentVariable("RUN_SIGNACORE_CONSUL_TESTS") == "true",
        "Set RUN_SIGNACORE_CONSUL_TESTS=true on a Linux Docker host to run real Consul acceptance.");

    private static string IdAt(Dictionary<string, JsonElement> services, int port) =>
        Assert.Single(services, x => x.Value.GetProperty("Port").GetInt32() == port).Key;

    private static void ScanToken(string text, string carrier)
    {
        if (text.Contains(AgentFixture.Token, StringComparison.Ordinal))
            throw new InvalidOperationException("Sensitive canary found in " + carrier);
    }

    private sealed class AgentFixture : IAsyncDisposable
    {
        internal const string Image = "hashicorp/consul:1.21.5@sha256:6126c30072690cb3173a450ff5bde120c3a01e11c9dccab83b1b2314d4c828bd";
        internal const string Token = "synthetic-consul-acceptance-canary";
        // /metrics is authorized by a registered application's gateway credentials.
        internal const string ScraperId = "consul-acceptance-scraper";
        internal const string ScraperSecret = "consul-acceptance-scraper-secret";
        private readonly string directory = Path.Combine(Path.GetTempPath(), "signacore-consul-real-" + Guid.NewGuid().ToString("N"));
        private readonly string container = "signacore-consul-test-" + Guid.NewGuid().ToString("N");
        private readonly int agentPort = FreePort();
        private readonly List<RealHost> hosts = [];
        private readonly HttpClient agent;
        private bool started;
        private string bootstrap = "";
        public RecordingProxy Proxy { get; }
        public CaptureLogs Logs { get; } = new();
        private AgentFixture()
        {
            Proxy = new RecordingProxy(agentPort);
            agent = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{agentPort}"), Timeout = TimeSpan.FromSeconds(2) };
        }

        public static async Task<AgentFixture> CreateAsync(bool startAgent = true, bool enabled = true, bool register = true, bool deregister = true)
        {
            Assert.True(OperatingSystem.IsLinux(), "Real Consul acceptance requires Linux host networking.");
            var fixture = new AgentFixture();
            try
            {
                Directory.CreateDirectory(fixture.directory);
                fixture.bootstrap = await InstallationTestSupport.PrepareCompletedInstallationAsync(
                    fixture.directory,
                    new DatabaseOptions { Provider = "SQLite", ConnectionString = new SqliteConnectionStringBuilder
                    { DataSource = Path.Combine(fixture.directory, "identity.db"), Pooling = false }.ConnectionString },
                    "consul-real-root-secret", "consul_real_admin", "ConsulReal1234",
                    new Dictionary<string, string>
                    {
                        [SystemSettingKeys.ConsulHost] = "127.0.0.1",
                        [SystemSettingKeys.ConsulPort] = fixture.Proxy.Port.ToString(),
                        [SystemSettingKeys.ConsulToken] = Token,
                        [SystemSettingKeys.ConsulDiscoveryEnabled] = enabled.ToString().ToLowerInvariant(),
                        [SystemSettingKeys.ConsulDiscoveryRegister] = register.ToString().ToLowerInvariant(),
                        [SystemSettingKeys.ConsulDiscoveryDeregister] = deregister.ToString().ToLowerInvariant()
                    }, TestContext.Current.CancellationToken);
                await fixture.SeedScraperAsync();
                if (startAgent) await fixture.StartAgentAsync();
                return fixture;
            }
            catch
            {
                await fixture.DisposeAsync();
                throw;
            }
        }

        private async Task SeedScraperAsync()
        {
            var options = new Microsoft.EntityFrameworkCore.DbContextOptionsBuilder<IdentityDbContext>();
            options.UseIdentityDatabase(new DatabaseOptions
            {
                Provider = "SQLite",
                ConnectionString = new SqliteConnectionStringBuilder
                    { DataSource = Path.Combine(directory, "identity.db"), Pooling = false }.ConnectionString
            });
            await using var db = new IdentityDbContext(options.Options);
            db.AppRegistrations.Add(new SignaCore.Database.Entity.AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = ScraperId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword(ScraperSecret),
                AppName = "Consul Acceptance Scraper",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            });
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        public async Task StartAgentAsync()
        {
            started = true; // Also clean up a container created by a failed/cancelled docker invocation.
            await DockerAsync("run", "-d", "--name", container, "--network", "host", Image,
                "agent", "-dev", "-client=127.0.0.1", $"-http-port={agentPort}",
                $"-serf-lan-port={FreePort()}", $"-serf-wan-port={FreePort()}", $"-server-port={FreePort()}",
                "-dns-port=0", "-grpc-port=0", "-grpc-tls-port=0");
            await WaitAsync(async () =>
            {
                try { using var response = await agent.GetAsync("/v1/agent/services"); return response.IsSuccessStatusCode; }
                catch (HttpRequestException) { return false; }
                catch (TaskCanceledException) { return false; }
            });
        }

        public RealHost StartHost(bool ready = false)
        {
            var host = new RealHost(bootstrap, Logs, ready);
            hosts.Add(host); // Retain ownership even when initialization fails.
            host.Start();
            return host;
        }
        public async Task<Dictionary<string, JsonElement>> ServicesAsync()
        {
            var all = await agent.GetFromJsonAsync<Dictionary<string, JsonElement>>("/v1/agent/services", TestContext.Current.CancellationToken);
            return all!.Where(x => x.Key.StartsWith("signacore:", StringComparison.Ordinal)).ToDictionary();
        }
        public Task WaitServicesAsync(int count) => WaitAsync(async () => (await ServicesAsync()).Count == count);
        public async Task AssertPassingAsync(string id, int port, string path)
        {
            await WaitAsync(async () =>
            {
                var checks = await agent.GetFromJsonAsync<Dictionary<string, JsonElement>>("/v1/agent/checks", TestContext.Current.CancellationToken);
                return checks!.TryGetValue("service:" + id, out var check) && check.GetProperty("Status").GetString() == "passing";
            });
            var registration = Proxy.Requests.Last(x => x.Kind == "register" && x.Id == id && x.Forwarded);
            Assert.Equal($"http://127.0.0.1:{port}{path}", registration.HealthUri);
        }
        public async Task WaitAsync(Func<Task<bool>> predicate)
        {
            var deadline = Stopwatch.StartNew();
            while (deadline.Elapsed < TimeSpan.FromSeconds(40))
            {
                TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
                if (await predicate()) return;
                await Task.Delay(100, TestContext.Current.CancellationToken);
            }
            throw new TimeoutException("Consul acceptance observation deadline expired.");
        }
        public void Scan(string text, string carrier) => ScanToken(text, carrier);
        public void AssertSafe()
        {
            Assert.NotEmpty(Logs.Messages);
            foreach (var message in Logs.Messages) Scan(message, "host log/state/exception");
            Assert.All(Proxy.Requests, x => Assert.True(x.TokenCorrect));
            Assert.False(Proxy.SensitiveTransportObserved, "Sensitive canary found in transport JSON/URL.");
        }
        public async ValueTask DisposeAsync()
        {
            try
            {
                Proxy.ReleaseDeregister.TrySetResult();
                var cleanupFailed = false;
                foreach (var host in hosts)
                {
                    try { await host.DisposeAsync(); }
                    catch { cleanupFailed = true; }
                }
                if (cleanupFailed) throw new InvalidOperationException("A host could not be released during acceptance cleanup.");
            }
            finally
            {
                try { if (started) await DockerAsync("rm", "-f", container); }
                finally
                {
                    await Proxy.DisposeAsync();
                    agent.Dispose();
                    TestSqlitePools.ClearAll();
                    if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
                }
            }
        }
        private static async Task DockerAsync(params string[] arguments)
        {
            using var process = new Process { StartInfo = new ProcessStartInfo("docker")
                { RedirectStandardOutput = true, RedirectStandardError = true } };
            foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
            process.Start();
            var output = process.StandardOutput.ReadToEndAsync();
            var error = process.StandardError.ReadToEndAsync();
            try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(90)); }
            catch { process.Kill(entireProcessTree: true); throw new InvalidOperationException("Docker operation did not finish."); }
            await Task.WhenAll(output, error); // Never copy agent or CLI output to test artifacts.
            Assert.True(process.ExitCode == 0, "Docker operation failed; verify the pinned image and Docker availability.");
        }
    }

    private sealed class RealHost : IAsyncDisposable
    {
        private readonly OwnedFactory factory;
        private HttpClient http = null!;
        private bool disposed;
        public int Port { get; } = FreePort();
        public ToggleReadiness Readiness { get; }
        public CountingClientFactory Clients { get; } = new();
        public RealHost(string bootstrap, CaptureLogs logs, bool ready)
        {
            Readiness = new ToggleReadiness { Ready = ready };
            factory = new OwnedFactory(builder =>
            {
                builder.UseSetting("Bootstrap:FilePath", bootstrap);
                builder.UseSetting("Endpoints:Http", Port.ToString());
                builder.UseSetting(WebHostDefaults.PreferHostingUrlsKey, "true");
                builder.UseSetting(WebHostDefaults.ServerUrlsKey, $"http://127.0.0.1:{Port}");
                builder.UseSetting(ConsulDiscoveryComposition.AdvertisementAddressKey, "127.0.0.1");
                builder.UseSetting(ConsulDiscoveryComposition.AdvertisementPortKey, Port.ToString());
                builder.ConfigureTestServices(services =>
                {
                    services.AddSingleton<IServiceReadinessContributor>(Readiness);
                    services.RemoveAll<IConsulClientFactory>();
                    services.AddSingleton<IConsulClientFactory>(Clients);
                    services.RemoveAll<ILoggerFactory>();
                    services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
                        logging.AddProvider(logs).SetMinimumLevel(LogLevel.Information)));
                });
            });
            factory.UseKestrel(Port);
        }
        public void Start() => http = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = new Uri($"http://127.0.0.1:{Port}") });
        public async Task AssertReadyAsync(bool ready)
        {
            using var response = await http.GetAsync("/health/ready", TestContext.Current.CancellationToken);
            Assert.Equal(ready ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable, response.StatusCode);
            using var anonymous = await http.GetAsync("/metrics", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
            using var scrape = new HttpRequestMessage(HttpMethod.Get, "/metrics");
            scrape.Headers.Add("X-Admin-AppId", AgentFixture.ScraperId);
            scrape.Headers.Add("X-Admin-AppSecret", AgentFixture.ScraperSecret);
            using var metrics = await http.SendAsync(scrape, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, metrics.StatusCode);
            ScanToken(await metrics.Content.ReadAsStringAsync(), "metrics");
        }
        public async Task UpdateAsync(Dictionary<string, string> changes)
        {
            using var login = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
                { Content = JsonContent.Create(new { username = "consul_real_admin", password = "ConsulReal1234" }) };
            login.Headers.Add("X-ServiceMantle-Request", "1");
            using var response = await http.SendAsync(login, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            var cookie = response.Headers.GetValues("Set-Cookie").Single(x => x.StartsWith("__Host-ServiceMantle.Management=", StringComparison.Ordinal)).Split(';')[0];
            http.DefaultRequestHeaders.Remove("Cookie");
            http.DefaultRequestHeaders.Add("Cookie", cookie);
            var settings = await http.GetFromJsonAsync<JsonElement>("/management/v1/settings", TestContext.Current.CancellationToken);
            using var update = await http.PostAsJsonAsync("/management/v1/settings", new
            {
                expectedVersion = settings.GetProperty("version").GetInt64(),
                changes = changes.Select(x => new { key = x.Key, value = x.Value })
            }, TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, update.StatusCode);
            ScanToken(await update.Content.ReadAsStringAsync(), "management update");
            var current = await http.GetStringAsync("/management/v1/settings", TestContext.Current.CancellationToken);
            ScanToken(current, "management settings");
            Assert.Equal(settings.GetProperty("version").GetInt64() + 1,
                JsonSerializer.Deserialize<JsonElement>(current).GetProperty("version").GetInt64());
        }
        public Task StopLifecycleAsync(CancellationToken cancellationToken) => factory.Services
            .GetServices<IHostedService>().Single(x => x.GetType().Name == "ConsulRegistrationLifecycle").StopAsync(cancellationToken);
        public async Task StopAsync()
        {
            await DisposeAsync();
            Assert.Equal(Clients.Created, Clients.Disposed);
        }
        public async ValueTask DisposeAsync()
        {
            if (disposed) return;
            disposed = true;
            http?.Dispose();
            try { await factory.DisposeAsync(); }
            catch (OperationCanceledException)
            {
                // WebApplicationFactory stops before disposing its host. A previously cancelled
                // lifecycle stop is replayed, so release the actual host even on that exit.
                if (factory.Host is IAsyncDisposable asyncHost) await asyncHost.DisposeAsync();
                else factory.Host?.Dispose();
            }
        }
    }

    private sealed class OwnedFactory(Action<IWebHostBuilder> configure) : WebApplicationFactory<Program>
    {
        public IHost? Host { get; private set; }
        protected override void ConfigureWebHost(IWebHostBuilder builder) => configure(builder);
        protected override IHost CreateHost(IHostBuilder builder)
        {
            Host = builder.Build();
            Host.Start();
            return Host;
        }
    }

    private sealed class ToggleReadiness : IServiceReadinessContributor
    {
        public volatile bool Ready;
        public int Samples;
        public int Order => 200;
        public ValueTask<ServiceReadinessContributorResult> EvaluateAsync(ServiceHealthSnapshot snapshot, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref Samples);
            return ValueTask.FromResult(Ready ? ServiceReadinessContributorResult.Ready() : ServiceReadinessContributorResult.NotReady("health.contributor_failed"));
        }
    }
    // Decorates the actual shared HTTP factory; no successful operation is synthesized.
    private sealed class CountingClientFactory : IConsulClientFactory
    {
        public int Created;
        public int Disposed;
        public int SuccessfulRegisters;
        public ConcurrentQueue<ConsulClientResult> Results { get; } = new();
        public IConsulClient Create(ConsulClientConfiguration configuration)
        {
            Interlocked.Increment(ref Created);
            return new CountingClient(new ConsulHttpClientFactory().Create(configuration), this);
        }
        private sealed class CountingClient(IConsulClient inner, CountingClientFactory owner) : IConsulClient
        {
            public async ValueTask<ConsulClientResult> RegisterAsync(ConsulServiceRegistration registration, CancellationToken cancellationToken = default)
            {
                try
                {
                    var result = await inner.RegisterAsync(registration, cancellationToken);
                    owner.Results.Enqueue(result);
                    if (result == ConsulClientResult.Success) Interlocked.Increment(ref owner.SuccessfulRegisters);
                    return result;
                }
                catch
                {
                    owner.Results.Enqueue(ConsulClientResult.Unavailable);
                    throw;
                }
            }
            public ValueTask<ConsulClientResult> DeregisterAsync(string registrationId, CancellationToken cancellationToken = default) => inner.DeregisterAsync(registrationId, cancellationToken);
            public void Dispose() { Interlocked.Increment(ref owner.Disposed); inner.Dispose(); }
        }
    }
    private sealed class CaptureLogs : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();
        public ILogger CreateLogger(string categoryName) => new Logger(Messages);
        public void Dispose() { }
        private sealed class Logger(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            {
                messages.Enqueue(state.ToString() ?? "");
                if (state is IEnumerable<KeyValuePair<string, object?>> properties)
                    foreach (var property in properties) messages.Enqueue(property.Key + "=" + property.Value);
                return null;
            }
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                messages.Enqueue(formatter(state, exception));
                if (state is IEnumerable<KeyValuePair<string, object?>> properties)
                    foreach (var property in properties) messages.Enqueue(property.Key + "=" + property.Value);
                if (exception is not null) messages.Enqueue(exception.ToString());
            }
        }
    }
    private static readonly HashSet<int> AllocatedPorts = [];
    private static int FreePort()
    {
        lock (AllocatedPorts)
        {
            for (var attempt = 0; attempt < 100; attempt++)
            {
                using var socket = new TcpListener(IPAddress.Loopback, 0);
                socket.Start();
                var port = ((IPEndPoint)socket.LocalEndpoint).Port;
                if (!AllocatedPorts.Add(port)) continue;
                try
                {
                    // Consul's serf ports use both transports. Also prevent immediate reuse
                    // between the agent, proxy and hosts before their listeners are started.
                    using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
                    return port;
                }
                catch (SocketException) { }
            }
        }
        throw new InvalidOperationException("Could not allocate distinct acceptance ports.");
    }

    private sealed class RecordingProxy : IAsyncDisposable
    {
        private readonly HttpListener listener = new();
        private readonly HttpClient upstream;
        private readonly CancellationTokenSource lifetime = new();
        private readonly List<Task> requests = [];
        private readonly Task loop;
        public int Port { get; } = FreePort();
        public ConcurrentQueue<Request> Requests { get; } = new();
        public volatile bool DropNextRegisterResponse;
        public volatile bool HoldDeregisterResponse;
        public bool SensitiveTransportObserved;
        public TaskCompletionSource DeregisterForwarded { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseDeregister { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public RecordingProxy(int agentPort)
        {
            upstream = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{agentPort}"), Timeout = TimeSpan.FromSeconds(3) };
            listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
            listener.Start();
            loop = RunAsync();
        }
        private async Task RunAsync()
        {
            try
            {
                while (!lifetime.IsCancellationRequested)
                {
                    var context = await listener.GetContextAsync().WaitAsync(lifetime.Token);
                    requests.Add(ForwardAsync(context));
                }
            }
            catch (Exception e) when (e is OperationCanceledException or HttpListenerException or ObjectDisposedException) { }
        }
        private async Task ForwardAsync(HttpListenerContext context)
        {
            var forwarded = false;
            var dropped = false;
            var request = context.Request;
            var path = request.RawUrl!;
            var kind = path.Contains("/deregister/", StringComparison.Ordinal) ? "deregister" : "register";
            var body = await new StreamReader(request.InputStream, Encoding.UTF8).ReadToEndAsync();
            if ((path + body).Contains(AgentFixture.Token, StringComparison.Ordinal)) SensitiveTransportObserved = true;
            var tokenCorrect = request.Headers["X-Consul-Token"] == AgentFixture.Token;
            var payload = kind == "register" ? JsonSerializer.Deserialize<JsonElement>(body) : default;
            var id = kind == "register" ? payload.GetProperty("ID").GetString()! : Uri.UnescapeDataString(path.Split('/')[^1]);
            var healthUri = kind == "register" ? payload.GetProperty("Check").GetProperty("HTTP").GetString() : null;
            try
            {
                using var message = new HttpRequestMessage(new HttpMethod(request.HttpMethod), path);
                message.Headers.TryAddWithoutValidation("X-Consul-Token", request.Headers["X-Consul-Token"]);
                if (body.Length > 0) message.Content = JsonContent.Create(payload, options: JsonSerializerOptions.Default);
                using var response = await upstream.SendAsync(message, lifetime.Token);
                forwarded = response.IsSuccessStatusCode;
                if (kind == "register" && forwarded && DropNextRegisterResponse)
                {
                    DropNextRegisterResponse = false;
                    dropped = true;
                    // Withhold headers beyond the real client operation budget, then drop the
                    // response. Truncating only the body would not fail ResponseHeadersRead.
                    await Task.Delay(TimeSpan.FromSeconds(12), lifetime.Token);
                    context.Response.Abort();
                    return;
                }
                if (kind == "deregister" && forwarded && HoldDeregisterResponse)
                {
                    DeregisterForwarded.TrySetResult();
                    await ReleaseDeregister.Task.WaitAsync(lifetime.Token);
                }
                context.Response.StatusCode = (int)response.StatusCode;
                // The production adapter consumes only the real agent's status. Never reflect
                // arbitrary upstream text into an HTTP response owned by this test listener.
                context.Response.ContentType = "application/json";
                context.Response.ContentLength64 = 0;
                context.Response.Close();
            }
            catch (Exception e) when (e is HttpRequestException or OperationCanceledException or HttpListenerException or IOException or ObjectDisposedException)
            {
                try { context.Response.StatusCode = 503; context.Response.Close(); } catch (ObjectDisposedException) { }
            }
            finally { Requests.Enqueue(new Request(request.HttpMethod, kind, id, tokenCorrect, forwarded, dropped, healthUri)); }
        }
        public async ValueTask DisposeAsync()
        {
            await lifetime.CancelAsync();
            listener.Close();
            await loop;
            await Task.WhenAll(requests);
            upstream.Dispose();
            lifetime.Dispose();
        }
        public sealed record Request(string Method, string Kind, string Id, bool TokenCorrect, bool Forwarded, bool Dropped, string? HealthUri);
    }
}
