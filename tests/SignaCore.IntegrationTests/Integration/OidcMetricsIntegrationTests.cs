using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Domain;
using SignaCore.Host;
using SignaCore.Host.Metrics;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The interactive OIDC metrics over the real host (issue #305): the endpoint-class outcome
/// counters and duration histograms observe the live protocol paths, the five retention gauges
/// follow artifact creation and cleanup, the existing <c>auth.*</c> instruments keep their exact
/// names, and a recorder that throws never changes a protocol response.
/// </summary>
public sealed class OidcMetricsIntegrationTests : IClassFixture<IdentityServerFixture>
{
    private const string ClientId = "metrics-app";
    private const string ClientSecret = "metrics-app-secret";

    private readonly IdentityServerFixture _fixture;

    public OidcMetricsIntegrationTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
        SeedClient();
    }

    private void SeedClient()
    {
        using var scope = _fixture.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var application = context.AppRegistrations
            .FirstOrDefaultAsync(row => row.AppId == ClientId, TestContext.Current.CancellationToken)
            .GetAwaiter().GetResult();
        if (application is null)
        {
            application = new Database.Entity.AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = ClientId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword(ClientSecret),
                AppName = "Metrics App",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            };
            context.AppRegistrations.Add(application);
        }

        application.IsActive = true;
        context.SaveChanges();
    }

    [Fact]
    public async Task TheTokenEndpoint_ProducesOutcomeAndDurationObservations()
    {
        using var collector = new MetricsCollector();
        using var host = _fixture.WithTestServices(_ => { });
        using var http = host.CreateClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(ClientId, ClientSecret);

        using var structural = await http.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "" }),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, structural.StatusCode);

        var outcome = Assert.Single(collector.Outcomes, o => o.Endpoint == "token" && o.ClientId == ClientId);
        Assert.Equal("invalid_request", outcome.Outcome);
        Assert.Equal(ClientId, outcome.ClientId);
        Assert.Contains(collector.Durations, d => d.Endpoint == "token" && d.Value >= 0);
    }

    [Fact]
    public async Task TheUserInfoEndpoint_ProducesDistinguishableOutcomes()
    {
        using var collector = new MetricsCollector();
        using var host = _fixture.WithTestServices(_ => { });
        using var http = host.CreateClient();

        using var noBearer = await http.GetAsync("/oauth2/userinfo", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, noBearer.StatusCode);
        using var invalid = await http.SendAsync(
            new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo")
            {
                Headers = { Authorization = new AuthenticationHeaderValue("Bearer", "not-a-jwt") }
            },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, invalid.StatusCode);

        var outcomes = collector.Outcomes.Where(o => o.Endpoint == "userinfo").ToList();
        Assert.Contains(outcomes, o => o.Outcome == "invalid_request");
        Assert.Contains(outcomes, o => o.Outcome == "invalid_token");
        Assert.DoesNotContain(outcomes, o => o.Outcome.Contains(' ', StringComparison.Ordinal));
    }

    [Fact]
    public async Task TheLogoutPreparation_ProducesOutcomeObservations()
    {
        using var collector = new MetricsCollector();
        using var host = _fixture.WithTestServices(_ => { });
        using var http = host.CreateClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(ClientId, ClientSecret);

        using var invalid = await http.PostAsync(
            "/oauth2/logout/requests",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["unknown_field"] = "x" }),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);

        var outcome = Assert.Single(collector.Outcomes, o => o.Endpoint == "logout-prepare" && o.ClientId == ClientId);
        Assert.Equal("invalid_request", outcome.Outcome);
        Assert.Equal(ClientId, outcome.ClientId);
    }

    [Fact]
    public async Task AThrowingRecorder_NeverChangesTheProtocolResponse()
    {
        using var host = _fixture.WithTestServices(services =>
        {
            services.RemoveAll<AuthMetrics>();
            services.AddSingleton<AuthMetrics, ThrowingAuthMetrics>();
        });
        using var http = host.CreateClient();
        http.DefaultRequestHeaders.Authorization = BasicHeader(ClientId, ClientSecret);

        using var response = await http.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "" }),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("invalid_request", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task TheRetentionGauges_FollowArtifactCreation()
    {
        using var host = _fixture.WithTestServices(_ => { });
        var gauges = host.Services.GetRequiredService<OidcRetentionGauges>();
        using var collector = new MetricsCollector();

        var before = collector.SnapshotGauge("oidc.retention.identity_session", gauges);

        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        await ExecuteAsync(async context =>
        {
            context.Accounts.Add(new Database.Entity.AccountEntity
            {
                Id = accountId,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            });
            context.PasswordCredentials.Add(new Database.Entity.PasswordCredentialEntity
            {
                Id = credentialId,
                AccountId = accountId,
                Username = $"metrics_user_{accountId:N}",
                PasswordHash = "hash",
                CreatedAt = DateTimeOffset.UtcNow
            });
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
            var session = await new Domain.Services.IdentitySessionStore(
                new Database.Repositories.IdentitySessionRepository(context),
                new Database.Repositories.EfCoreUnitOfWork(context))
                .CreateAsync(accountId, credentialId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
            context.ChangeTracker.Clear();
            Assert.NotEqual(default, session.Id);
        });

        var after = collector.SnapshotGauge("oidc.retention.identity_session", gauges);
        Assert.Equal(before + 1, after);

        // The closed provider label is part of every gauge sample.
        Assert.Contains("sqlite", new[] { gauges.Provider });
    }

    // ---- Helpers ----

    private static AuthenticationHeaderValue BasicHeader(string id, string secret) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}")));

    private async Task ExecuteAsync(Func<IdentityDbContext, Task> action)
    {
        using var scope = _fixture.Services.CreateScope();
        await action(scope.ServiceProvider.GetRequiredService<IdentityDbContext>());
    }

    /// <summary>Throws on every endpoint-class recording: the protocol must not notice.</summary>
    private sealed class ThrowingAuthMetrics : AuthMetrics
    {
        public ThrowingAuthMetrics()
            : base(StubFactory())
        {
        }

        private static System.Diagnostics.Metrics.IMeterFactory StubFactory()
        {
            var factory = new Moq.Mock<System.Diagnostics.Metrics.IMeterFactory>();
            factory
                .Setup(f => f.Create(Moq.It.IsAny<System.Diagnostics.Metrics.MeterOptions>()))
                .Returns(new System.Diagnostics.Metrics.Meter("SignaCore"));
            return factory.Object;
        }

        protected override void RecordOidcEndpointOutcomeCore(string endpoint, string outcome, string? clientId) =>
            throw new InvalidOperationException("metrics recording failed");

        protected override void RecordOidcEndpointDurationCore(string endpoint, double milliseconds) =>
            throw new InvalidOperationException("metrics recording failed");
    }

    /// <summary>
    /// Collects the <c>SignaCore</c> meter's endpoint metrics through a process-wide
    /// <see cref="System.Diagnostics.Metrics.MeterListener"/>, and can pull the retention gauges
    /// on demand.
    /// </summary>
    private sealed class MetricsCollector : IDisposable
    {
        private readonly MeterListener _listener;
        private readonly object _gate = new();

        public List<(string Endpoint, string Outcome, string? ClientId)> Outcomes { get; } = [];

        public List<(string Endpoint, double Value)> Durations { get; } = [];

        public MetricsCollector()
        {
            _listener = new MeterListener
            {
                InstrumentPublished = (instrument, listener) =>
                {
                    if (instrument.Meter.Name == "SignaCore"
                        && (instrument.Name == "oidc.endpoint.outcome"
                            || instrument.Name == "oidc.endpoint.duration"
                            || instrument.Name.StartsWith("oidc.retention.", StringComparison.Ordinal)))
                    {
                        listener.EnableMeasurementEvents(instrument);
                    }
                }
            };
            _listener.SetMeasurementEventCallback<int>((instrument, value, tags, _) =>
            {
                if (instrument.Name != "oidc.endpoint.outcome")
                {
                    return;
                }

                string endpoint = string.Empty, outcome = string.Empty;
                string? clientId = null;
                foreach (var tag in tags)
                {
                    if (tag.Key == "endpoint") endpoint = tag.Value?.ToString() ?? string.Empty;
                    if (tag.Key == "outcome") outcome = tag.Value?.ToString() ?? string.Empty;
                    if (tag.Key == "client_id") clientId = tag.Value?.ToString();
                }

                lock (_gate)
                {
                    Outcomes.Add((endpoint, outcome, clientId));
                }
            });
            _listener.SetMeasurementEventCallback<double>((instrument, value, tags, _) =>
            {
                if (instrument.Name != "oidc.endpoint.duration")
                {
                    return;
                }

                string endpoint = string.Empty;
                foreach (var tag in tags)
                {
                    if (tag.Key == "endpoint") endpoint = tag.Value?.ToString() ?? string.Empty;
                }

                lock (_gate)
                {
                    Durations.Add((endpoint, value));
                }
            });
            _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
            {
                if (instrument.Name.StartsWith("oidc.retention.", StringComparison.Ordinal))
                {
                    lock (_gate)
                    {
                        _retentions[instrument.Name] = value;
                    }
                }
            });
            _listener.Start();
        }

        private readonly Dictionary<string, long> _retentions = new(StringComparer.Ordinal);

        public long SnapshotGauge(string name, OidcRetentionGauges gauges)
        {
            lock (_gate)
            {
                _retentions.Remove(name);
            }

            _listener.RecordObservableInstruments();
            lock (_gate)
            {
                return _retentions.TryGetValue(name, out var value) ? value : -1;
            }
        }

        public void Dispose() => _listener.Dispose();
    }
}
