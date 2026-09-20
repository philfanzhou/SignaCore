using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using SignaCore.Database;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// End-to-end correlation propagation through the shared ServiceMantle correlation middleware in
/// the real hosts. Every production branch — Bootstrap Configuration Mode, Setup Mode, and the
/// normal host — must return the accepted caller value verbatim, or a generated 32-character
/// lowercase hex id when the header is missing, invalid, or repeated. On the normal business path
/// one Token audit case proves that the response header, the Serilog request scope, the accessor,
/// and the persisted audit row all carry the same id.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed partial class CorrelationPropagationTests : IClassFixture<IdentityServerFixture>
{
    private const string HeaderName = "x-correlation-id";
    private const string ValidValue = "e2e-correlation-0123456789abcdef";

    private readonly IdentityServerFixture _fixture;

    public CorrelationPropagationTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    [GeneratedRegex("^[0-9a-f]{32}$")]
    private static partial Regex GeneratedIdPattern();

    // ---- Normal host ----

    [Fact]
    public async Task NormalHost_TokenAudit_CarriesOneIdAcrossResponseScopeAccessorAndAudit()
    {
        var capture = new RequestScopeCapture();
        using var factory = _fixture.WithTestServices(services =>
        {
            // Serilog routes ILogger.BeginScope through one process-wide static logger, which the
            // parallel test hosts keep reconfiguring; a per-factory Serilog sink is therefore not
            // deterministic here. Swapping in a plain logger factory records the library's request
            // scope state directly — the same scope surface the Serilog pipeline consumes.
            services.RemoveAll<ILoggerFactory>();
            services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
                logging.AddProvider(capture)));
        });
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Admin-AppId", IdentityServerFixture.GatewayAppId);
        client.DefaultRequestHeaders.Add("X-Admin-AppSecret", IdentityServerFixture.GatewayAppSecret);
        client.DefaultRequestHeaders.Add(HeaderName, ValidValue);

        using var response = await client.PostAsJsonAsync(
            "/api/auth/token",
            new { grantType = "no_such_grant" },
            TestContext.Current.CancellationToken);

        // The JSON contract of the endpoint is unchanged by the correlation middleware.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("unsupported_grant_type", body, StringComparison.Ordinal);

        // 1. The response header echoes the accepted value.
        Assert.Equal(ValidValue, response.Headers.GetValues(HeaderName).Single());

        // 2. The request scope opened by the middleware during this business request carries the
        //    same value, alongside the ServiceMantle identity fields.
        var scope = capture.Scopes.Single(fields =>
            Field(fields, "CorrelationId") == ValidValue);
        Assert.Equal("signacore", Field(scope, "ServiceName"));

        // 3. The persisted audit row received the same value through the accessor.
        using var scope2 = _fixture.Services.CreateScope();
        var database = scope2.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var history = await database.LoginHistories
            .AsNoTracking()
            .Where(entry => entry.CorrelationId == ValidValue)
            .ToListAsync(TestContext.Current.CancellationToken);
        Assert.Single(history);
    }

    [Fact]
    public async Task NormalHost_MissingHeader_GeneratesCorrelationId()
    {
        using var client = _fixture.CreateHttpClient();

        using var response = await client.GetAsync("/health/live", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Matches(GeneratedIdPattern(), response.Headers.GetValues(HeaderName).Single());
    }

    [Theory]
    [InlineData(" ")]        // whitespace-only is rejected whole
    [InlineData("a b")]      // illegal character
    [InlineData("a,b")]      // comma-joined value
    public async Task NormalHost_RejectedValue_IsReplacedByGeneratedId(string value)
    {
        using var client = _fixture.CreateHttpClient();
        client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderName, value);

        using var response = await client.GetAsync("/health/live", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Matches(GeneratedIdPattern(), response.Headers.GetValues(HeaderName).Single());
    }

    [Fact]
    public async Task NormalHost_RepeatedHeader_IsDiscardedWhole()
    {
        using var client = _fixture.CreateHttpClient();
        client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderName, "first-value");
        client.DefaultRequestHeaders.TryAddWithoutValidation(HeaderName, "second-value");

        using var response = await client.GetAsync("/health/live", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var correlationId = response.Headers.GetValues(HeaderName).Single();
        Assert.Matches(GeneratedIdPattern(), correlationId);
        Assert.NotEqual("first-value", correlationId);
    }

    // ---- Bootstrap Configuration Mode ----

    [Theory]
    [InlineData(ValidValue)]
    [InlineData(null)]
    public async Task BootstrapHost_RoundTripsCorrelation(string? headerValue)
    {
        var directory = Path.Combine(Path.GetTempPath(), $"signacore-correlation-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.UseSetting("environment", Environments.Production);
                builder.UseSetting(
                    SignaCoreBootstrapStore.FilePathConfigurationKey,
                    Path.Combine(directory, "signacore.bootstrap.json"));
            });
            using var client = factory.CreateClient();
            if (headerValue is not null)
            {
                client.DefaultRequestHeaders.Add(HeaderName, headerValue);
            }

            using var response = await client.GetAsync("/health/live", TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var correlationId = response.Headers.GetValues(HeaderName).Single();
            if (headerValue is null)
            {
                Assert.Matches(GeneratedIdPattern(), correlationId);
            }
            else
            {
                Assert.Equal(headerValue, correlationId);
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    // ---- Setup Mode ----

    [Theory]
    [InlineData(ValidValue)]
    [InlineData(null)]
    public async Task SetupHost_RoundTripsCorrelation(string? headerValue)
    {
        var workingDirectory = Path.Combine(Path.GetTempPath(), $"signacore-correlation-{Guid.NewGuid():N}");
        Directory.CreateDirectory(workingDirectory);
        var databasePath = Path.Combine(workingDirectory, "identity.db");
        try
        {
            var bootstrapFilePath = await InstallationTestSupport.PrepareUninstalledBootstrapAsync(
                workingDirectory,
                new DatabaseOptions
                {
                    Provider = "SQLite",
                    ConnectionString = $"Data Source={databasePath}"
                },
                IdentityServerFixture.RootSecret);

            using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.UseSetting("environment", Environments.Production);
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath);
            });
            using var client = factory.CreateClient();
            if (headerValue is not null)
            {
                client.DefaultRequestHeaders.Add(HeaderName, headerValue);
            }

            using var response = await client.GetAsync("/health/live", TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var correlationId = response.Headers.GetValues(HeaderName).Single();
            if (headerValue is null)
            {
                Assert.Matches(GeneratedIdPattern(), correlationId);
            }
            else
            {
                Assert.Equal(headerValue, correlationId);
            }
        }
        finally
        {
            Directory.Delete(workingDirectory, recursive: true);
        }
    }

    /// <summary>
    /// Records the ILogger scopes opened during the request — the ServiceMantle request scope is an
    /// <c>IReadOnlyList&lt;KeyValuePair&lt;string, object?&gt;&gt;</c> of named fields.
    /// </summary>
    private sealed class RequestScopeCapture : ILoggerProvider
    {
        private readonly object _gate = new();
        public List<IReadOnlyList<KeyValuePair<string, object?>>> Scopes { get; } = [];

        public ILogger CreateLogger(string categoryName) => new CaptureLogger(this);

        public void Dispose()
        {
        }

        private sealed class CaptureLogger(RequestScopeCapture owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            {
                if (state is IReadOnlyList<KeyValuePair<string, object?>> fields)
                {
                    lock (owner._gate)
                    {
                        owner.Scopes.Add(fields);
                    }
                }

                return NullScope.Instance;
            }

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
            }
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();

            public void Dispose()
            {
            }
        }
    }

    private static string? Field(IReadOnlyList<KeyValuePair<string, object?>> fields, string name)
    {
        foreach (var field in fields)
        {
            if (string.Equals(field.Key, name, StringComparison.Ordinal))
            {
                return field.Value?.ToString();
            }
        }

        return null;
    }
}
