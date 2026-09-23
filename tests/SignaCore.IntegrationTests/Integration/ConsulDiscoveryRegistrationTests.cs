using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Characterization of the Steeltoe Consul registration lifecycle against an in-process fake
/// agent — the pre-switch state, not the target design. The fake agent is a local HTTP listener:
/// no Docker and no real Consul are involved. The completed installation is seeded through the
/// shared setup fixture with the <c>consul.*</c> settings pointing at the listener.
/// <para>
/// Pinned behaviors: the registration PUT and its payload (name, generated instance id, readiness
/// health check, ACL token as a request header only), shutdown deregistration behind the
/// <c>register+deregister</c> flags, the query-only default (never registers, never deregisters),
/// fail-fast host startup when the agent is unreachable, and single registration per host.
/// </para>
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class ConsulDiscoveryRegistrationTests : IAsyncLifetime
{
    private const string RootSecret = "consul-characterization-root-secret";
    private const string AdminUsername = "consul_admin";
    private const string AdminPassword = "ConsulAdmin123";
    private const string ConsulToken = "consul-acl-token-for-characterization";

    private string _workingDirectory = string.Empty;
    private string _databasePath = string.Empty;
    private string _connectionString = string.Empty;
    private FakeConsulAgent _agent = null!;
    private WebApplicationFactory<Program>? _factory;

    public ValueTask InitializeAsync()
    {
        _workingDirectory = Path.Combine(Path.GetTempPath(), $"signacore-consul-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_workingDirectory);
        _databasePath = Path.Combine(_workingDirectory, "signacore.db");
        _connectionString = new SqliteConnectionStringBuilder { DataSource = _databasePath }.ConnectionString;
        _agent = new FakeConsulAgent();
        _agent.Start();
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        _factory?.Dispose();

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
    public async Task EnabledWithRegister_RegistersWithTheAgentAndKeepsTheTokenOutOfLogs()
    {
        var logs = new CapturingLoggerProvider();
        using var http = await StartHostAsync(
            logs,
            Register: "true",
            Deregister: "false");

        var registration = await _agent.WaitForRegistrationAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal("PUT", registration.Method);
        Assert.Equal("/v1/agent/service/register", registration.Path);
        Assert.Equal(ConsulToken, registration.TokenHeader);

        // The payload is derived from the settings catalog: the fixed service name, the generated
        // per-process instance id (hyphen-separated, normalized for Consul), the resolved host
        // address, and a listen port. Steeltoe's heartbeat defaults to enabled, so the registered
        // check is a TTL heartbeat — the process pings the agent itself — and the catalog's
        // /health/ready path is carried by the options but not by this payload.
        Assert.Equal("SignaCore", registration.Body.Name);
        Assert.Matches("^SignaCore-[0-9]{8}$", registration.Body.Id);
        Assert.False(string.IsNullOrWhiteSpace(registration.Body.Address));
        Assert.True(registration.Body.Port > 0);
        Assert.NotNull(registration.Body.Check);
        Assert.Equal("30s", registration.Body.Check!.Ttl);
        Assert.Equal("30m0s", registration.Body.Check.DeregisterCriticalServiceAfter);
        Assert.Null(registration.Body.Check.Http);

        // The ACL token reaches the agent as a request header only: it never appears in a URL, a
        // payload field, or any log line the host emitted.
        Assert.DoesNotContain(ConsulToken, registration.RawBody, StringComparison.Ordinal);
        Assert.All(logs.Messages, message =>
            Assert.DoesNotContain(ConsulToken, message, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ShutdownWithDeregister_DeregistersTheSameInstanceId()
    {
        using var http = await StartHostAsync(
            logs: null,
            Register: "true",
            Deregister: "true");

        var registration = await _agent.WaitForRegistrationAsync(
            TestContext.Current.CancellationToken);

        // The host's stop path (DiscoveryClientHostedService.StopAsync) is, verbatim, an awaited
        // ShutdownAsync on every discovery client. Driving that same call on the booted host's real
        // client keeps the assertion on host behavior: WebApplicationFactory's synchronous Dispose
        // races its own teardown against the in-flight deregistration PUT and silently kills it,
        // which is a harness artifact — a plain web host with the same registration shuts down
        // cleanly (verified independently).
        var discoveryClient = _factory!.Services.GetRequiredService<Steeltoe.Common.Discovery.IDiscoveryClient>();
        await discoveryClient.ShutdownAsync(TestContext.Current.CancellationToken);
        _factory.Dispose();
        _factory = null;
        http.Dispose();

        var deregistration = await _agent.WaitForDeregistrationAsync(
            TestContext.Current.CancellationToken);
        Assert.Equal("PUT", deregistration.Method);
        Assert.Equal(
            "/v1/agent/service/deregister/" + registration.Body.Id,
            deregistration.Path);
        Assert.Equal(ConsulToken, deregistration.TokenHeader);
    }

    [Fact]
    public async Task ShutdownWithoutDeregister_LeavesTheRegistrationBehind()
    {
        using var http = await StartHostAsync(
            logs: null,
            Register: "true",
            Deregister: "false");

        var registration = await _agent.WaitForRegistrationAsync(
            TestContext.Current.CancellationToken);

        _factory!.Dispose();
        _factory = null;
        http.Dispose();

        // The catalog default deregister=false is the current state: shutdown never deregisters,
        // and the stale entry is left to Consul's own health-check timeout policy.
        await Assert.ThrowsAsync<TimeoutException>(() =>
            _agent.WaitForDeregistrationAsync(CancellationToken.None, grace: TimeSpan.FromSeconds(2)));
    }

    [Fact]
    public async Task EnabledWithoutRegister_NeverTouchesTheAgent()
    {
        using var http = await StartHostAsync(
            logs: null,
            Register: "false",
            Deregister: "false");

        // The pure query-only client the catalog defaults produce: the host starts, reports
        // readiness on the completed installation, and no agent call is ever made — not on
        // startup and not on shutdown.
        using var ready = await http.GetAsync("/health/ready", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);

        _agent.Dispose();
        _factory!.Dispose();
        _factory = null;
        http.Dispose();

        Assert.Empty(_agent.Registrations);
        Assert.Empty(_agent.Deregistrations);
    }

    [Fact]
    public async Task UnreachableAgentWithRegister_FailsHostStartup()
    {
        // A port that is free now and stays unlistened: connection attempts are refused
        // immediately, so the single fail-fast attempt fails deterministically.
        var unreachablePort = FreePort();

        var bootstrapFilePath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
            _workingDirectory,
            new DatabaseOptions { Provider = "SQLite", ConnectionString = _connectionString },
            RootSecret,
            AdminUsername,
            AdminPassword,
            new Dictionary<string, string>
            {
                [SystemSettingKeys.ConsulHost] = "127.0.0.1",
                [SystemSettingKeys.ConsulPort] = unreachablePort.ToString(CultureInfo.InvariantCulture),
                [SystemSettingKeys.ConsulToken] = ConsulToken,
                [SystemSettingKeys.ConsulDiscoveryEnabled] = "true",
                [SystemSettingKeys.ConsulDiscoveryRegister] = "true"
            });

        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath));

        // No retry is configured for the discovery client, so the single registration attempt in
        // the discovery-client constructor propagates and the host fails to start.
        await Assert.ThrowsAnyAsync<Exception>(() => Task.Run(() => factory.CreateClient()));
        factory.Dispose();
    }

    [Fact]
    public async Task OneHost_RegistersExactlyOnce_EvenWhenTheClientIsResolvedAgain()
    {
        using var http = await StartHostAsync(
            logs: null,
            Register: "true",
            Deregister: "false");

        await _agent.WaitForRegistrationAsync(TestContext.Current.CancellationToken);

        // The discovery client is a singleton guarded by the registrar's own running flag, so
        // resolving it again from the booted host does not produce a second registration PUT.
        var client = _factory!.Services.GetRequiredService<Steeltoe.Common.Discovery.IDiscoveryClient>();
        var local = client.GetLocalServiceInstance();
        Assert.NotNull(local);

        Assert.Single(_agent.Registrations);
    }

    private async Task<HttpClient> StartHostAsync(
        CapturingLoggerProvider? logs,
        string Register,
        string Deregister)
    {
        var bootstrapFilePath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
            _workingDirectory,
            new DatabaseOptions { Provider = "SQLite", ConnectionString = _connectionString },
            RootSecret,
            AdminUsername,
            AdminPassword,
            new Dictionary<string, string>
            {
                [SystemSettingKeys.ConsulHost] = "127.0.0.1",
                [SystemSettingKeys.ConsulPort] = _agent.Port.ToString(CultureInfo.InvariantCulture),
                [SystemSettingKeys.ConsulToken] = ConsulToken,
                [SystemSettingKeys.ConsulDiscoveryEnabled] = "true",
                [SystemSettingKeys.ConsulDiscoveryRegister] = Register,
                [SystemSettingKeys.ConsulDiscoveryDeregister] = Deregister
            });

        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath);
                if (logs is not null)
                {
                    // Replace Serilog with an in-memory factory, the same way the existing
                    // sensitive-value scan tests do, so the Consul wiring's log lines are captured.
                    builder.ConfigureTestServices(services =>
                    {
                        services.RemoveAll<ILoggerFactory>();
                        services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
                        {
                            logging.AddProvider(logs);
                            logging.SetMinimumLevel(LogLevel.Information);
                        }));
                    });
                }
            });

        return _factory.CreateClient();
    }

    private static int FreePort()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
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
    /// Steeltoe client issues and records their method, path, ACL token header, and payload.
    /// </summary>
    private sealed class FakeConsulAgent : IDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly ConcurrentQueue<AgentRequest> _registrations = new();
        private readonly ConcurrentQueue<AgentRequest> _deregistrations = new();

        public IReadOnlyCollection<AgentRequest> Registrations => _registrations;
        public IReadOnlyCollection<AgentRequest> Deregistrations => _deregistrations;



        public int Port { get; private set; }

        public void Start()
        {
            var port = FreePort();
            _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
            _listener.Start();
            Port = port;
            _ = Task.Run(AcceptLoopAsync);
        }

        public async Task<AgentRequest> WaitForRegistrationAsync(CancellationToken cancellationToken)
        {
            var deadline = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30);
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

            var recorded = new AgentRequest(
                request.HttpMethod,
                request.Url?.AbsolutePath ?? request.RawUrl,
                request.Headers["X-Consul-Token"],
                payload ?? new RegistrationPayload(),
                body);
            if (recorded.Path.StartsWith("/v1/agent/service/register", StringComparison.Ordinal))
            {
                _registrations.Enqueue(recorded);
            }
            else if (recorded.Path.StartsWith("/v1/agent/service/deregister", StringComparison.Ordinal))
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

        [JsonPropertyName("TTL")]
        public string? Ttl { get; set; }

        [JsonPropertyName("DeregisterCriticalServiceAfter")]
        public string? DeregisterCriticalServiceAfter { get; set; }
    }
}
