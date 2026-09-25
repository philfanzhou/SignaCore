using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using ServiceMantle.Consul;
using ServiceMantle.Health;
using SignaCore.Database;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Characterization of the shared snapshot-driven Consul registration lifecycle (ServiceMantle
/// #104) against an in-process fake agent — the post-switch state. The fake agent is a local HTTP
/// listener: no Docker and no real Consul are involved. The completed installation is seeded
/// through the shared setup fixture with the <c>consul.*</c> settings pointing at the listener and
/// the explicit per-instance advertisement supplied through <c>ServiceDiscovery:*</c>.
/// <para>
/// Pinned behaviors: registration only after the shared readiness decision is Ready, the explicit
/// advertisement address/port and readiness health check in the payload, the ACL token as a
/// request header only, shutdown deregistration of the same id under the shared owner, the
/// refused <c>register=true + deregister=false</c> combination, the query-only and disabled
/// combinations never touching the agent, retry instead of fail-fast when the agent is
/// unreachable, restart-bound configuration changes, and two same-version hosts with distinct
/// advertisements never deregistering each other.
/// </para>
/// <para>
/// Differences from the retired Steeltoe wiring are deliberate and documented in
/// <c>docs/development/ConsulIntegration.md</c>: the instance id is the host identity's
/// (<c>signacore:signacore-{guid}</c>), the health check is an HTTP readiness probe instead of a
/// TTL heartbeat, the address and port are explicit per-instance configuration instead of
/// auto-detection, and an unreachable agent retries instead of failing host startup. Product
/// catalog defaults remain pinned by <c>ProductSettingDefinitionTableTests</c>.
/// </para>
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class ConsulDiscoveryRegistrationTests : IAsyncLifetime
{
    private const string Root = "/management/v1";
    private const string RootSecret = "consul-characterization-root-secret";
    private const string AdminUsername = "consul_admin";
    private const string AdminPassword = "ConsulAdmin123";
    private const string ConsulToken = "consul-acl-token-for-characterization";
    private const string ManagementCookieName = "__Host-ServiceMantle.Management";
    private const string AdvertisementAddress = "10.9.8.7";
    private const int AdvertisementPort = 41234;

    private string _workingDirectory = string.Empty;
    private string _connectionString = string.Empty;
    private FakeConsulAgent _agent = null!;
    private readonly List<WebApplicationFactory<Program>> _factories = [];

    public ValueTask InitializeAsync()
    {
        _workingDirectory = Path.Combine(Path.GetTempPath(), $"signacore-consul-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_workingDirectory);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(_workingDirectory, "signacore.db")
        }.ConnectionString;
        _agent = new FakeConsulAgent();
        _agent.Start();
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var factory in _factories)
        {
            factory.Dispose();
        }

        _agent.Dispose();
        for (var attempt = 0; attempt < 5; attempt++)
        {
            TestSqlitePools.ClearAll();
            try
            {
                if (Directory.Exists(_workingDirectory))
                {
                    Directory.Delete(_workingDirectory, recursive: true);
                }

                return;
            }
            catch (IOException) when (attempt < 4)
            {
                await Task.Delay(200);
            }
        }
    }

    [Fact]
    public async Task EnabledWithRegister_RegistersAfterReady_WithTheExplicitAdvertisement()
    {
        var logs = new CapturingLoggerProvider();
        using var http = await StartHostAsync(
            logs,
            Enabled: "true", Register: "true", Deregister: "true",
            AdvertisementAddress: AdvertisementAddress, AdvertisementPort: AdvertisementPort.ToString());

        var registration = await _agent.WaitForRegistrationAsync(TestContext.Current.CancellationToken);
        Assert.Equal("PUT", registration.Method);
        Assert.Equal("/v1/agent/service/register", registration.Path);
        Assert.Equal(ConsulToken, registration.TokenHeader);

        // The payload comes from the derived discovery view: the fixed service name, the host
        // identity's per-build instance id, and the explicit per-instance advertisement. The
        // registered check is the shared readiness probe on the advertised endpoint.
        Assert.Equal("SignaCore", registration.Body.Name);
        Assert.Matches("^signacore:signacore-[0-9a-f]{32}$", registration.Body.Id);
        Assert.Equal(AdvertisementAddress, registration.Body.Address);
        Assert.Equal(AdvertisementPort, registration.Body.Port);
        Assert.NotNull(registration.Body.Check);
        Assert.Equal(
            $"http://{AdvertisementAddress}:{AdvertisementPort}/health/ready",
            registration.Body.Check!.Http);
        Assert.Equal("10s", registration.Body.Check.Interval);
        Assert.Equal("2s", registration.Body.Check.Timeout);

        // The ACL token reaches the agent as a request header only: it never appears in a URL, a
        // payload field, or any log line the host emitted.
        Assert.DoesNotContain(ConsulToken, registration.RawBody, StringComparison.Ordinal);
        Assert.All(logs.Messages, message =>
            Assert.DoesNotContain(ConsulToken, message, StringComparison.Ordinal));

        // The shared lifecycle is the sole registration owner; the retired client and its
        // package have been removed from the host.
    }

    [Fact]
    public async Task Shutdown_DeregistersTheSameInstanceId()
    {
        using var http = await StartHostAsync(
            logs: null,
            Enabled: "true", Register: "true", Deregister: "true",
            AdvertisementAddress: AdvertisementAddress, AdvertisementPort: AdvertisementPort.ToString());

        var registration = await _agent.WaitForRegistrationAsync(TestContext.Current.CancellationToken);

        // The hosted stop performs the cleanup deregistration of the very same registration id
        // within its shutdown budget, before the factory teardown.
        _factories[^1].Dispose();
        http.Dispose();

        var deregistration = await _agent.WaitForDeregistrationAsync(TestContext.Current.CancellationToken);
        Assert.Equal("PUT", deregistration.Method);
        // The transport URI-escapes the registration id; the semantic id itself is unchanged.
        Assert.Equal(registration.Body.Id, ExtractId(deregistration.Path));
        Assert.Equal(ConsulToken, deregistration.TokenHeader);
    }

    [Fact]
    public async Task ReadinessTransitions_RegisterOnlyWhileReady_AndDeregisterOnReadinessLoss()
    {
        var toggle = new ToggleReadinessContributor();
        using var http = await StartHostAsync(
            logs: null,
            Enabled: "true", Register: "true", Deregister: "true",
            AdvertisementAddress: AdvertisementAddress, AdvertisementPort: AdvertisementPort.ToString(),
            configureTestServices: services => services.AddSingleton<IServiceReadinessContributor>(toggle));

        // While the shared readiness decision is NotReady the lifecycle performs no registration
        // at all, exactly like the /health/ready route it shares its decision source with.
        using var ready = await http.GetAsync("/health/ready", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, ready.StatusCode);
        await Assert.ThrowsAsync<TimeoutException>(() =>
            _agent.WaitForRegistrationAsync(CancellationToken.None, grace: TimeSpan.FromSeconds(3)));
        Assert.Empty(_agent.Registrations);

        toggle.SetReady();
        var registration = await _agent.WaitForRegistrationAsync(TestContext.Current.CancellationToken);
        Assert.Equal(AdvertisementAddress, registration.Body.Address);

        toggle.SetNotReady();
        var deregistration = await _agent.WaitForDeregistrationAsync(TestContext.Current.CancellationToken);
        Assert.Equal(registration.Body.Id, ExtractId(deregistration.Path));
    }

    [Fact]
    public async Task RegisterWithoutDeregister_RefusesHostStartup()
    {
        // The shared owner always deregisters; a deployment that kept the legacy
        // deregister=false switch is refused with the fixed configuration code instead of
        // silently ignoring the switch.
        var exception = await Assert.ThrowsAnyAsync<Exception>(() => Task.Run(() =>
            StartHostAsync(
                logs: null,
                Enabled: "true", Register: "true", Deregister: "false",
                AdvertisementAddress: AdvertisementAddress, AdvertisementPort: AdvertisementPort.ToString())));
        var actual = Unwrap(exception);
        Assert.IsType<ConsulDiscoveryConfigurationException>(actual);
        Assert.Equal(
            ConsulDiscoveryConfigurationException.DeregisterRequired,
            ((ConsulDiscoveryConfigurationException)actual).ErrorCode);
    }

    [Fact]
    public async Task RegisterWithoutTheExplicitAdvertisement_RefusesHostStartup()
    {
        var exception = await Assert.ThrowsAnyAsync<Exception>(() => Task.Run(() =>
            StartHostAsync(
                logs: null,
                Enabled: "true", Register: "true", Deregister: "true",
                AdvertisementAddress: null, AdvertisementPort: null)));
        var actual = Unwrap(exception);
        Assert.IsType<ConsulDiscoveryConfigurationException>(actual);
        Assert.Equal(
            ConsulDiscoveryConfigurationException.AdvertisementRequired,
            ((ConsulDiscoveryConfigurationException)actual).ErrorCode);
    }

    [Fact]
    public async Task QueryOnlyCombination_NeverTouchesTheAgent()
    {
        using var http = await StartHostAsync(
            logs: null,
            Enabled: "true", Register: "false", Deregister: "false",
            AdvertisementAddress: null, AdvertisementPort: null);

        // The query-only combination the catalog defaults produce is a disabled lifecycle: the
        // host starts, reports readiness on the completed installation, and no agent call is ever
        // made — not on startup and not on shutdown.
        using var ready = await http.GetAsync("/health/ready", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);

        _factories[^1].Dispose();
        http.Dispose();

        Assert.Empty(_agent.Requests);
    }

    [Fact]
    public async Task UnreachableAgent_DoesNotFailStartup_AndRegistersWhenTheAgentReturns()
    {
        // A port that is free now: connection attempts are refused immediately, so every
        // registration attempt fails while the agent is absent. Unlike the retired fail-fast
        // Steeltoe wiring the host starts and the shared lifecycle keeps retrying.
        var lateAgent = new FakeConsulAgent();
        var agentPort = FreePort();
        var bootstrapFilePath = await PrepareInstallationAsync(
            Enabled: "true", Register: "true", Deregister: "true", agentPortOverride: agentPort);
        using var http = await StartHostAsync(
            logs: null,
            bootstrapFilePath,
            AdvertisementAddress: AdvertisementAddress, AdvertisementPort: AdvertisementPort.ToString());

        using var ready = await http.GetAsync("/health/ready", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);

        // The agent appears at the configured address; the next retry registers. The late agent
        // stays alive through disposal so the host's cleanup deregistration settles quickly.
        lateAgent.Start(agentPort);
        var registration = await lateAgent.WaitForRegistrationAsync(TestContext.Current.CancellationToken);
        Assert.Equal(AdvertisementAddress, registration.Body.Address);

        _factories[^1].Dispose();
        http.Dispose();
        await lateAgent.WaitForDeregistrationAsync(TestContext.Current.CancellationToken);
        lateAgent.Dispose();
    }

    [Fact]
    public async Task ConfigurationChange_TakesEffectAfterRestart_IncludingDisable()
    {
        using var first = await StartHostAsync(
            logs: null,
            Enabled: "true", Register: "true", Deregister: "true",
            AdvertisementAddress: AdvertisementAddress, AdvertisementPort: AdvertisementPort.ToString());
        var firstRegistration = await _agent.WaitForRegistrationAsync(TestContext.Current.CancellationToken);

        // The authenticated management update commits version 2 with discovery disabled.
        using var admin = await CreateAdminClientAsync(_factories[^1]);
        var version = await ReadConfigurationVersionAsync(admin);
        using var update = await admin.PostAsJsonAsync(
            Root + "/settings",
            new { expectedVersion = version, changes = new[] { new { key = "consul.discovery.enabled", value = "false" } } },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, update.StatusCode);
        Assert.Equal(version + 1, await ReadConfigurationVersionAsync(admin));

        // The running host keeps its captured version-1 session: it does not re-bind, and its
        // stored token never appears in the management projection.
        using var current = await admin.GetAsync(Root + "/settings", TestContext.Current.CancellationToken);
        var body = await current.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain(ConsulToken, body, StringComparison.Ordinal);

        _factories[^1].Dispose();
        first.Dispose();
        var firstDeregistration = await _agent.WaitForDeregistrationAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal(firstRegistration.Body.Id, ExtractId(firstDeregistration.Path));

        // The restarted host captures version 2: disabled means no client, no sampler, and no
        // agent request at all, while the host itself still starts and reports ready.
        var bootstrapFilePath = await CurrentBootstrapPathAsync();
        using var second = await StartHostAsync(
            logs: null, bootstrapFilePath,
            AdvertisementAddress: AdvertisementAddress, AdvertisementPort: AdvertisementPort.ToString());
        using var ready = await second.GetAsync("/health/ready", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);

        _factories[^1].Dispose();
        second.Dispose();
        Assert.Single(_agent.Registrations);
        Assert.Single(_agent.Deregistrations);
    }



    [Fact]
    public async Task TwoHosts_SameSnapshotVersion_DistinctAdvertisements_DoNotDeregisterEachOther()
    {
        var bootstrapFilePath = await PrepareInstallationAsync(
            Enabled: "true", Register: "true", Deregister: "true");

        using var first = await StartHostAsync(
            logs: null, bootstrapFilePath,
            AdvertisementAddress: "10.0.0.1", AdvertisementPort: "11111");
        var firstRegistration = await _agent.WaitForRegistrationAsync(TestContext.Current.CancellationToken);

        using var second = await StartHostAsync(
            logs: null, bootstrapFilePath,
            AdvertisementAddress: "10.0.0.2", AdvertisementPort: "22222");
        var secondRegistration = await _agent.WaitForRegistrationAsync(
            1, TestContext.Current.CancellationToken);

        // Two per-build instance identities over one product version: distinct registration ids
        // and distinct explicit advertisements; neither overwrites the other.
        Assert.NotEqual(firstRegistration.Body.Id, secondRegistration.Body.Id);
        Assert.Equal("10.0.0.1", firstRegistration.Body.Address);
        Assert.Equal("10.0.0.2", secondRegistration.Body.Address);
        Assert.Equal(2, _agent.Registrations.Count);

        // Stopping one host cleans up exactly its own registration; the other's stays.
        _factories[0].Dispose();
        first.Dispose();
        var deregistration = await _agent.WaitForDeregistrationAsync(TestContext.Current.CancellationToken);
        Assert.Equal(firstRegistration.Body.Id, ExtractId(deregistration.Path));
        Assert.All(_agent.Deregistrations, request =>
            Assert.Equal(firstRegistration.Body.Id, ExtractId(request.Path)));
        Assert.Equal(2, _agent.Registrations.Count);
    }

    private static string? ExtractId(string path) =>
        path.StartsWith("/v1/agent/service/deregister/", StringComparison.Ordinal)
            ? Uri.UnescapeDataString(path["/v1/agent/service/deregister/".Length..])
            : null;

    private static Exception Unwrap(Exception exception)
    {
        var current = exception;
        while (current is not ConsulDiscoveryConfigurationException &&
               current.InnerException is not null)
        {
            current = current.InnerException;
        }

        return current;
    }

    private async Task<string> CurrentBootstrapPathAsync() =>
        Path.Combine(_workingDirectory, "current", "signacore.bootstrap.json");

    private async Task<string> PrepareInstallationAsync(
        string Enabled,
        string Register,
        string Deregister,
        int? agentPortOverride = null,
        string directory = "current")
    {
        var bootstrapFilePath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
            Path.Combine(_workingDirectory, directory),
            new DatabaseOptions { Provider = "SQLite", ConnectionString = _connectionString },
            RootSecret,
            AdminUsername,
            AdminPassword,
            new Dictionary<string, string>
            {
                [SystemSettingKeys.ConsulHost] = "127.0.0.1",
                [SystemSettingKeys.ConsulPort] = (agentPortOverride ?? _agent.Port)
                    .ToString(CultureInfo.InvariantCulture),
                [SystemSettingKeys.ConsulToken] = ConsulToken,
                [SystemSettingKeys.ConsulDiscoveryEnabled] = Enabled,
                [SystemSettingKeys.ConsulDiscoveryRegister] = Register,
                [SystemSettingKeys.ConsulDiscoveryDeregister] = Deregister
            });
        return bootstrapFilePath;
    }

    private async Task<HttpClient> StartHostAsync(
        CapturingLoggerProvider? logs,
        string Enabled,
        string Register,
        string Deregister,
        string? AdvertisementAddress,
        string? AdvertisementPort,
        Action<IServiceCollection>? configureTestServices = null)
    {
        var bootstrapFilePath = await PrepareInstallationAsync(Enabled, Register, Deregister);
        return await StartHostAsync(
            logs, bootstrapFilePath, AdvertisementAddress, AdvertisementPort, configureTestServices);
    }

    private async Task<HttpClient> StartHostAsync(
        CapturingLoggerProvider? logs,
        string bootstrapFilePath,
        string? AdvertisementAddress,
        string? AdvertisementPort,
        Action<IServiceCollection>? configureTestServices = null)
    {
        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath);
                if (AdvertisementAddress is not null)
                {
                    builder.UseSetting(ConsulDiscoveryComposition.AdvertisementAddressKey, AdvertisementAddress);
                    builder.UseSetting(ConsulDiscoveryComposition.AdvertisementPortKey, AdvertisementPort);
                }

                builder.ConfigureTestServices(services =>
                {
                    configureTestServices?.Invoke(services);
                    if (logs is not null)
                    {
                        // Replace Serilog with an in-memory factory, the same way the existing
                        // sensitive-value scan tests do, so the Consul wiring's log lines are captured.
                        services.RemoveAll<ILoggerFactory>();
                        services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
                        {
                            logging.AddProvider(logs);
                            logging.SetMinimumLevel(LogLevel.Information);
                        }));
                    }
                });
            });

        _factories.Add(factory);
        return factory.CreateClient();
    }

    private static async Task<HttpClient> CreateAdminClientAsync(WebApplicationFactory<Program> factory)
    {
        var client = factory.CreateClient();
        var request = new HttpRequestMessage(HttpMethod.Post, Root + "/session/login")
        {
            Content = new StringContent(
                JsonSerializer.Serialize(new { username = AdminUsername, password = AdminPassword }),
                Encoding.UTF8,
                "application/json")
        };
        request.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(response.Headers.NonValidated.TryGetValues("Set-Cookie", out var cookies));
        var cookie = cookies
            .Single(value => value.StartsWith($"{ManagementCookieName}=", StringComparison.Ordinal))
            .Split(';')[0];
        client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", cookie);
        return client;
    }

    private static async Task<long> ReadConfigurationVersionAsync(HttpClient admin)
    {
        using var response = await admin.GetAsync(Root + "/settings", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken))
            .GetProperty("version").GetInt64();
    }

    private static int FreePort()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    /// <summary>
    /// A controllable readiness contributor: NotReady until the test flips it, so the shared
    /// readiness decision — and through it the Consul lifecycle — observes a real flip.
    /// </summary>
    private sealed class ToggleReadinessContributor : IServiceReadinessContributor
    {
        private volatile bool _ready;

        public int Order => 200;

        public void SetReady() => _ready = true;

        public void SetNotReady() => _ready = false;

        public ValueTask<ServiceReadinessContributorResult> EvaluateAsync(
            ServiceHealthSnapshot snapshot, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(
                _ready
                    ? ServiceReadinessContributorResult.Ready()
                    : ServiceReadinessContributorResult.NotReady("health.contributor_failed"));
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<string> _messages = new();

        public IReadOnlyCollection<string> Messages => _messages;

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, _messages);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(
            string categoryName,
            ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                messages.Enqueue($"{categoryName}: {formatter(state, exception)}");
                if (exception is not null)
                {
                    messages.Enqueue($"{categoryName}: {exception}");
                }
            }
        }
    }

    /// <summary>
    /// A minimal in-process Consul agent: it accepts the registration and deregistration PUTs the
    /// shared lifecycle issues and records their method, path, ACL token header, and payload.
    /// </summary>
    private sealed class FakeConsulAgent : IDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly ConcurrentQueue<AgentRequest> _registrations = new();
        private readonly ConcurrentQueue<AgentRequest> _deregistrations = new();
        private readonly ConcurrentQueue<AgentRequest> _requests = new();
        private int _port;

        public IReadOnlyCollection<AgentRequest> Registrations => _registrations;

        public IReadOnlyCollection<AgentRequest> Deregistrations => _deregistrations;

        public IReadOnlyCollection<AgentRequest> Requests => _requests;

        public int Port => _port;

        public void Start(int? port = null)
        {
            _port = port ?? FreePort();
            _listener.Prefixes.Add($"http://127.0.0.1:{_port}/");
            _listener.Start();
            _ = Task.Run(AcceptLoopAsync);
        }

        public async Task<AgentRequest> WaitForRegistrationAsync(
            CancellationToken cancellationToken, TimeSpan? grace = null)
        {
            var deadline = DateTimeOffset.UtcNow + (grace ?? TimeSpan.FromSeconds(30));
            while (DateTimeOffset.UtcNow < deadline)
            {
                if (!_registrations.IsEmpty)
                {
                    return _registrations.First();
                }

                await Task.Delay(50, cancellationToken);
            }

            throw new TimeoutException("No registration PUT reached the agent.");
        }

        public async Task<AgentRequest> WaitForRegistrationAsync(
            int occurrence, CancellationToken cancellationToken)
        {
            var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
            while (DateTimeOffset.UtcNow < deadline)
            {
                if (_registrations.Count > occurrence)
                {
                    return _registrations.ElementAt(occurrence);
                }

                await Task.Delay(50, cancellationToken);
            }

            throw new TimeoutException($"Registration PUT #{occurrence + 1} never reached the agent.");
        }

        public async Task<AgentRequest> WaitForDeregistrationAsync(
            CancellationToken cancellationToken, TimeSpan? grace = null)
        {
            var deadline = DateTimeOffset.UtcNow + (grace ?? TimeSpan.FromSeconds(30));
            while (DateTimeOffset.UtcNow < deadline)
            {
                if (!_deregistrations.IsEmpty)
                {
                    return _deregistrations.First();
                }

                await Task.Delay(50, cancellationToken);
            }

            throw new TimeoutException("No deregistration PUT reached the agent.");
        }

        private async Task AcceptLoopAsync()
        {
            while (_listener.IsListening)
            {
                HttpListenerContext context;
                try
                {
                    context = await _listener.GetContextAsync();
                }
                catch (Exception exception) when (exception is HttpListenerException or ObjectDisposedException)
                {
                    return;
                }

                _ = Task.Run(() => HandleAsync(context));
            }
        }

        private async Task HandleAsync(HttpListenerContext context)
        {
            var request = context.Request;
            using var reader = new StreamReader(request.InputStream, Encoding.UTF8);
            var body = await reader.ReadToEndAsync();

            RegistrationPayload? payload = null;
            if (body.Length > 0)
            {
                try
                {
                    payload = JsonSerializer.Deserialize<RegistrationPayload>(body);
                }
                catch (JsonException)
                {
                    payload = null;
                }
            }

            var path = request.Url?.AbsolutePath ?? request.RawUrl ?? string.Empty;
            var recorded = new AgentRequest(
                request.HttpMethod,
                path,
                request.Headers["X-Consul-Token"],
                payload ?? new RegistrationPayload(),
                body);
            _requests.Enqueue(recorded);
            if (path.StartsWith("/v1/agent/service/register", StringComparison.Ordinal))
            {
                _registrations.Enqueue(recorded);
            }
            else if (path.StartsWith("/v1/agent/service/deregister", StringComparison.Ordinal))
            {
                _deregistrations.Enqueue(recorded);
            }

            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            var buffer = "{}"u8.ToArray();
            context.Response.ContentLength64 = buffer.Length;
            await context.Response.OutputStream.WriteAsync(buffer);
            context.Response.Close();
        }

        public void Dispose()
        {
            if (_listener.IsListening)
            {
                _listener.Stop();
            }

            _listener.Close();
        }

        public sealed record AgentRequest(
            string Method,
            string Path,
            string? TokenHeader,
            RegistrationPayload Body,
            string RawBody);
    }

    private sealed class RegistrationPayload
    {
        // The Consul agent API wire names, which the Consul client serializes verbatim.
        [JsonPropertyName("ID")]
        public string? Id { get; set; }

        [JsonPropertyName("Name")]
        public string? Name { get; set; }

        [JsonPropertyName("Address")]
        public string? Address { get; set; }

        [JsonPropertyName("Port")]
        public int? Port { get; set; }

        [JsonPropertyName("Check")]
        public RegistrationCheck? Check { get; set; }
    }

    private sealed class RegistrationCheck
    {
        [JsonPropertyName("HTTP")]
        public string? Http { get; set; }

        [JsonPropertyName("Interval")]
        public string? Interval { get; set; }

        [JsonPropertyName("Timeout")]
        public string? Timeout { get; set; }

        [JsonPropertyName("Status")]
        public string? Status { get; set; }
    }
}
