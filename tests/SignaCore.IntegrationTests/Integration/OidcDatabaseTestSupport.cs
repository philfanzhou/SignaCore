using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.RateLimiting;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Security;
using SignaCore.Host.Startup;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

internal static class OidcDatabaseTestSupport
{
    internal const string RootSecret = "oidc-distributed-rate-limit-root-secret";
    internal const string AdminUsername = "shared_budget_admin";
    internal const string AdminPassword = "SharedBudget-123!";
    internal const string ClientId = "rl-canary-client-7f3a";
    internal const string ClientSecret = "rl-canary-secret-7f3a";
    internal const string RedirectUri = "https://bff.shared-budget.test/callback";
    internal const string RemoteIp = "198.51.100.23";
    internal const string CodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    internal const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    internal const int Budget = IdentityConstants.OidcTokenRateLimitPerMinute;
    internal const int GlobalBudget = 100;
    internal static CancellationToken Ct => TestContext.Current.CancellationToken;

    // ---- Helpers ----

    internal static async Task<List<HttpStatusCode>> AlternateTokenRequestsAsync(
        TestHost a,
        TestHost b,
        string partition,
        int count)
    {
        var outcomes = new List<HttpStatusCode>(count);
        for (var i = 0; i < count; i++)
        {
            using var response = await (i % 2 == 0 ? a : b).Client.SendAsync(TokenRequest(partition), Ct);
            outcomes.Add(response.StatusCode);
        }

        return outcomes;
    }

    internal static async Task<List<HttpStatusCode>> SendTokenRequestsAsync(TestHost host, int count)
    {
        var outcomes = new List<HttpStatusCode>(count);
        for (var i = 0; i < count; i++)
        {
            using var response = await host.Client.SendAsync(TokenRequest("ip"), Ct);
            outcomes.Add(response.StatusCode);
        }

        return outcomes;
    }

    /// <summary>
    /// A token request that fails client authentication: the registered client with a wrong
    /// secret lands in its client partition, an unknown client in the source-network partition.
    /// </summary>
    internal static HttpRequestMessage TokenRequest(string partition)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials"
            })
        };
        request.Headers.Authorization = partition == "client"
            ? BasicHeader(ClientId, "wrong-secret")
            : BasicHeader("unknown-client", "wrong-secret");
        return request;
    }

    internal sealed record InteractiveEndpoint(string Policy, string PartitionKey, Func<HttpRequestMessage> Create);

    internal static IEnumerable<InteractiveEndpoint> InteractiveEndpoints()
    {
        yield return new(OidcRateLimitPolicies.Authorize, "client:" + ClientId, () => new HttpRequestMessage(
            HttpMethod.Get,
            "/oauth2/authorize?" + string.Join('&',
                $"client_id={ClientId}",
                $"redirect_uri={Uri.EscapeDataString(RedirectUri)}",
                "response_type=code",
                "scope=openid",
                $"state=state-{Guid.NewGuid():N}",
                $"nonce=nonce-{Guid.NewGuid():N}",
                $"code_challenge={CodeChallenge}",
                "code_challenge_method=S256")));
        yield return new(OidcRateLimitPolicies.Login, "ip:" + RemoteIp, () => new HttpRequestMessage(HttpMethod.Post, "/oauth2/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["login_handle"] = "unknown-handle",
                ["username"] = "nobody",
                ["password"] = "wrong-password"
            })
        });
        yield return new(OidcRateLimitPolicies.Token, "ip:" + RemoteIp, () => TokenRequest("ip"));
        yield return new(OidcRateLimitPolicies.UserInfo, "ip:" + RemoteIp, () => new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", "not-a-real-token") }
        });
        yield return new(OidcRateLimitPolicies.Logout, "ip:" + RemoteIp, () => new HttpRequestMessage(HttpMethod.Get, "/oauth2/logout"));
        yield return new(OidcRateLimitPolicies.Logout, "ip:" + RemoteIp, () => new HttpRequestMessage(HttpMethod.Post, "/oauth2/logout/requests")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["id_token_hint"] = "x" })
        });
        yield return new(OidcRateLimitPolicies.Revoke, "ip:" + RemoteIp, () =>
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/revoke")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = "opaque" })
            };
            request.Headers.Authorization = BasicHeader("unknown-client", "wrong-secret");
            return request;
        });
    }

    internal static async Task AssertFixedRejectionAsync(HttpResponseMessage response, HttpStatusCode status)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.ToString() == "no-store", "The rejection was cacheable.");
        Assert.True(response.Headers.Location is null, "The rejection included a redirect.");
        Assert.True(OidcRateLimitPolicies.RejectionBody == await response.Content.ReadAsStringAsync(Ct),
            "The rejection body differed from the fixed contract.");
    }

    internal static AuthenticationHeaderValue BasicHeader(string id, string secret) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}")));

    internal static void AssertNoCanary(IReadOnlyCollection<string> values, params string[] canaries)
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

    /// <summary>A per-instance budget: what a disconnected shared store would amount to.</summary>
    internal sealed class PerInstanceBudgetStore : IOidcRateLimitStore
    {
        private readonly ConcurrentDictionary<(string, string), int> _counts = new();

        public Task<OidcRateLimitAcquireResult> AcquireAsync(
            string policy,
            string partitionDigest,
            CancellationToken cancellationToken)
        {
            var count = _counts.AddOrUpdate((policy, partitionDigest), 1, (_, current) => current + 1);
            return Task.FromResult(count <= Budget ? OidcRateLimitAcquireResult.Granted : OidcRateLimitAcquireResult.Rejected);
        }

        public Task<int?> DeleteExpiredAsync(CancellationToken cancellationToken) => Task.FromResult<int?>(0);
    }

    /// <summary>What one host did: handler invocations, rejection callbacks, and its log lines.</summary>
    internal sealed class HostProbe
    {
        private int _handlerInvocations;
        private int _rejections;
        private int _inFlight;
        private readonly ConcurrentQueue<string> _logs = new();

        public int HandlerInvocations => Volatile.Read(ref _handlerInvocations);

        public int Rejections => Volatile.Read(ref _rejections);

        public IReadOnlyCollection<string> Logs => _logs.ToArray();

        public void Handled() => Interlocked.Increment(ref _handlerInvocations);

        public void Rejected() => Interlocked.Increment(ref _rejections);

        public void Log(string line) => _logs.Enqueue(line);

        public void ClearLogs() => _logs.Clear();

        public IDisposable Request()
        {
            Interlocked.Increment(ref _inFlight);
            return new Exit(this);
        }

        public async Task WaitForRequestsToDrainAsync()
        {
            var started = TimeProvider.System.GetTimestamp();
            while (Volatile.Read(ref _inFlight) > 0 && TimeProvider.System.GetElapsedTime(started) < TimeSpan.FromSeconds(10))
            {
                await Task.Delay(20, Ct);
            }

            Assert.Equal(0, Volatile.Read(ref _inFlight));
        }

        private sealed class Exit(HostProbe probe) : IDisposable
        {
            public void Dispose() => Interlocked.Decrement(ref probe._inFlight);
        }
    }

    /// <summary>Counts every controller action that started executing.</summary>
    internal sealed class HandlerProbeFilter(HostProbe probe) : IResourceFilter
    {
        public void OnResourceExecuting(ResourceExecutingContext context) => probe.Handled();

        public void OnResourceExecuted(ResourceExecutedContext context)
        {
        }
    }

    /// <summary>
    /// Pins the source address of every request, ahead of the whole pipeline, and tracks requests
    /// still in flight so a canceled request is observed to its end.
    /// </summary>
    internal sealed class RemoteAddressStartupFilter(HostProbe probe) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, following) =>
            {
                using var _ = probe.Request();
                context.Connection.RemoteIpAddress = IPAddress.Parse(RemoteIp);
                await following(context);
            });
            next(app);
        };
    }

    internal sealed class CaptureLoggerProvider(HostProbe probe) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new CaptureLogger(probe, categoryName);

        public void Dispose()
        {
        }

        private sealed class CaptureLogger(HostProbe probe, string category) : ILogger
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
                probe.Log($"{category} {formatter(state, exception)} {properties} {exception}");
            }
        }
    }

    /// <summary>Captures every tag of the ASP.NET Core rate-limiting instruments.</summary>
    internal sealed class RateLimitMetricsCapture : IDisposable
    {
        private static readonly HashSet<string> AllowedTagKeys = new(StringComparer.Ordinal)
        {
            "aspnetcore.rate_limiting.policy",
            "aspnetcore.rate_limiting.result"
        };

        private readonly MeterListener _listener = new();
        private readonly ConcurrentQueue<KeyValuePair<string, object?>> _tags = new();

        public RateLimitMetricsCapture(TestHost host)
        {
            // Only this host's meters: other hosts in the process keep their own measurements.
            var scope = host.Factory.Services.GetRequiredService<IMeterFactory>();
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "Microsoft.AspNetCore.RateLimiting"
                    && ReferenceEquals(instrument.Meter.Scope, scope))
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<long>((_, _, tags, _) => Record(tags));
            _listener.SetMeasurementEventCallback<double>((_, _, tags, _) => Record(tags));
            _listener.Start();
        }

        public IReadOnlyCollection<string> TagValues =>
            _tags.Select(tag => Convert.ToString(tag.Value, CultureInfo.InvariantCulture) ?? string.Empty).ToArray();

        public void AssertOnlyPolicyTags()
        {
            Assert.NotEmpty(_tags);
            Assert.All(_tags, tag =>
            {
                Assert.Contains(tag.Key, AllowedTagKeys);
                if (tag.Key == "aspnetcore.rate_limiting.policy")
                {
                    Assert.Contains((string)tag.Value!, OidcRateLimitPolicies.All);
                }
            });
        }

        public void Dispose() => _listener.Dispose();

        private void Record(ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            foreach (var tag in tags)
            {
                _tags.Enqueue(tag);
            }
        }
    }

    internal sealed class TestHost(WebApplicationFactory<Program> factory, HttpClient client, HostProbe probe) : IDisposable
    {
        public WebApplicationFactory<Program> Factory => factory;

        public HttpClient Client => client;

        public HostProbe Probe => probe;

        public string Digest(string partitionKey) =>
            factory.Services.GetRequiredService<OidcRateLimitPartitioner>().Digest(partitionKey);

        public void Dispose()
        {
            client.Dispose();
            factory.Dispose();
        }
    }

    internal sealed record SeededCode(string Code, Guid Id);

    internal sealed class Harness(DatabaseOptions database, string bootstrapDirectory, string bootstrapFilePath, PostgreSqlContainer container) : IAsyncDisposable
    {
        public string ConnectionString => database.ConnectionString;

        public static async Task<Harness> CreateAsync(IReadOnlyDictionary<string, string>? settings = null)
        {
            Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true", "Enable the PostgreSQL database contract matrix.");
            var container = new PostgreSqlBuilder(Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") ?? "postgres:15-alpine").Build();
            var directory = Path.Combine(Path.GetTempPath(), $"signacore-shared-budget-{Guid.NewGuid():N}");
            try
            {
                await container.StartAsync(Ct);
                var database = new DatabaseOptions
                {
                    Provider = "PostgreSQL",
                    ServerVersion = "15",
                    ConnectionString = container.GetConnectionString()
                };
                var bootstrapFilePath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
                    directory, database, RootSecret, AdminUsername, AdminPassword, settings, cancellationToken: Ct);
                var harness = new Harness(database, directory, bootstrapFilePath, container);
                await harness.SeedClientAsync();
                return harness;
            }
            catch
            {
                await container.DisposeAsync();
                throw;
            }
        }

        /// <summary>One more replica: its own process state, the shared database and root key.</summary>
        public TestHost CreateHost(Action<IServiceCollection>? configure = null, bool captureLogs = true)
        {
            var probe = new HostProbe();
            var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath);
                builder.UseSetting("Endpoints:Http", "0");
                builder.ConfigureTestServices(services =>
                {
                    services.AddSingleton<IStartupFilter>(new RemoteAddressStartupFilter(probe));
                    services.Configure<MvcOptions>(options => options.Filters.Add(new HandlerProbeFilter(probe)));
                    if (captureLogs)
                    {
                        services.RemoveAll<ILoggerFactory>();
                        services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
                            logging.SetMinimumLevel(LogLevel.Trace).AddProvider(new CaptureLoggerProvider(probe))));
                    }
                    services.PostConfigure<RateLimiterOptions>(options =>
                    {
                        var inner = options.OnRejected;
                        options.OnRejected = async (context, cancellationToken) =>
                        {
                            probe.Rejected();
                            if (inner is not null)
                            {
                                await inner(context, cancellationToken);
                            }
                        };
                    });
                    configure?.Invoke(services);
                });
            });
            var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                HandleCookies = false
            });
            return new TestHost(factory, client, probe);
        }

        public IdentityDbContext Context()
        {
            var builder = new DbContextOptionsBuilder<IdentityDbContext>();
            builder.UseIdentityDatabase(database, enableRetryOnFailure: false);
            return new IdentityDbContext(builder.Options);
        }

        public async Task ExecuteAsync(string sql)
        {
            await using var connection = await OpenAsync();
            await using var command = new NpgsqlCommand(sql, connection);
            await command.ExecuteNonQueryAsync(Ct);
        }

        public async Task<int> CountAsync()
        {
            await using var connection = await OpenAsync();
            await using var command = new NpgsqlCommand("SELECT count(*) FROM oidc_rate_limit_buckets", connection);
            return Convert.ToInt32(await command.ExecuteScalarAsync(Ct), CultureInfo.InvariantCulture);
        }

        public async Task<int?> PermitCountAsync(string policy, string digest)
        {
            await using var connection = await OpenAsync();
            await using var command = new NpgsqlCommand(
                "SELECT permit_count FROM oidc_rate_limit_buckets WHERE policy = @p AND partition_digest = @d",
                connection);
            command.Parameters.AddWithValue("p", policy);
            command.Parameters.AddWithValue("d", digest);
            var value = await command.ExecuteScalarAsync(Ct);
            return value is null ? null : Convert.ToInt32(value, CultureInfo.InvariantCulture);
        }

        public async Task<List<string>> DumpAsync()
        {
            await using var connection = await OpenAsync();
            await using var command = new NpgsqlCommand(
                "SELECT policy, partition_digest, window_expires_at::text, permit_count::text FROM oidc_rate_limit_buckets",
                connection);
            await using var reader = await command.ExecuteReaderAsync(Ct);
            var rows = new List<string>();
            while (await reader.ReadAsync(Ct))
            {
                rows.Add(string.Join('|', reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3)));
            }

            return rows;
        }

        /// <summary>Holds the row lock of one bucket in an open transaction until disposed.</summary>
        public async Task<IAsyncDisposable> LockRowAsync(string policy, string digest)
        {
            var connection = await OpenAsync();
            var transaction = await connection.BeginTransactionAsync(Ct);
            await using (var command = new NpgsqlCommand(
                "SELECT 1 FROM oidc_rate_limit_buckets WHERE policy = @p AND partition_digest = @d FOR UPDATE",
                connection,
                transaction))
            {
                command.Parameters.AddWithValue("p", policy);
                command.Parameters.AddWithValue("d", digest);
                Assert.NotNull(await command.ExecuteScalarAsync(Ct));
            }

            return new RowLock(connection, transaction);
        }

        public Task WaitForLockWaitAsync() => WaitForLockWaitersAsync(expectWaiting: true);

        public Task WaitForNoLockWaitAsync() => WaitForLockWaitersAsync(expectWaiting: false);

        public async Task<SeededCode> SeedAuthorizationCodeAsync()
        {
            await using var context = Context();
            var application = await context.AppRegistrations.AsNoTracking().SingleAsync(x => x.AppId == ClientId, Ct);
            var accountId = Guid.NewGuid();
            var credentialId = Guid.NewGuid();
            context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
            context.PasswordCredentials.Add(new PasswordCredentialEntity
            {
                Id = credentialId,
                AccountId = accountId,
                Username = $"shared_budget_user_{Guid.NewGuid():N}",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("Shared-Budget-123!", 4),
                CreatedAt = DateTimeOffset.UtcNow
            });
            await context.SaveChangesAsync(Ct);
            context.ChangeTracker.Clear();

            var session = await new IdentitySessionStore(
                    new Database.Repositories.IdentitySessionRepository(context),
                    new Database.Repositories.EfCoreUnitOfWork(context))
                .CreateAsync(accountId, credentialId, DateTimeOffset.UtcNow, Ct);
            var creation = await new AuthorizationCodeStore(
                    new Database.Repositories.AuthorizationCodeRepository(context),
                    new Database.Repositories.EfCoreUnitOfWork(context))
                .CreateAsync(
                    session,
                    new AuthorizationCodeBinding(application.Id, RedirectUri, "openid", "shared-budget-nonce", CodeChallenge),
                    DateTimeOffset.UtcNow,
                    Ct);
            return new SeededCode(creation.Code, creation.Id);
        }

        public async ValueTask DisposeAsync()
        {
            await container.DisposeAsync();
            if (Directory.Exists(bootstrapDirectory))
            {
                Directory.Delete(bootstrapDirectory, recursive: true);
            }
        }

        private async Task SeedClientAsync()
        {
            await using var context = Context();
            var application = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = ClientId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword(ClientSecret, 4),
                AppName = "Shared Budget App",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.PerApplication,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = "openid profile",
                AllowRefreshToken = false
            };
            context.AppRegistrations.Add(application);
            context.AppRedirectUris.Add(new AppRedirectUriEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = application.Id,
                Kind = RedirectUriKind.Redirect,
                CanonicalUri = RedirectUri
            });
            await context.SaveChangesAsync(Ct);
        }

        internal async Task<NpgsqlConnection> OpenAsync()
        {
            var connection = new NpgsqlConnection(
                new NpgsqlConnectionStringBuilder(database.ConnectionString) { Pooling = false }.ConnectionString);
            await connection.OpenAsync(Ct);
            return connection;
        }

        private async Task WaitForLockWaitersAsync(bool expectWaiting)
        {
            var started = TimeProvider.System.GetTimestamp();
            while (TimeProvider.System.GetElapsedTime(started) < TimeSpan.FromSeconds(10))
            {
                await using var connection = await OpenAsync();
                await using var command = new NpgsqlCommand(
                    "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()",
                    connection);
                var waiting = Convert.ToInt32(await command.ExecuteScalarAsync(Ct), CultureInfo.InvariantCulture) > 0;
                if (waiting == expectWaiting)
                {
                    return;
                }

                await Task.Delay(20, Ct);
            }

            Assert.Fail(expectWaiting
                ? "No session started waiting for the row lock."
                : "A session kept waiting for the row lock.");
        }

        private sealed class RowLock(NpgsqlConnection connection, NpgsqlTransaction transaction) : IAsyncDisposable
        {
            private bool _disposed;

            public async ValueTask DisposeAsync()
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                await transaction.DisposeAsync();
                await connection.DisposeAsync();
            }
        }
    }
}
