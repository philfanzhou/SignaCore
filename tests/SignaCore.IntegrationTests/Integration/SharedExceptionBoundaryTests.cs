using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ServiceMantle.Web.Health;
using ServiceMantle.Web.Http;
using ServiceMantle.Health;
using ServiceMantle.Installation;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Integration;

public sealed class SharedExceptionBoundaryTests
{
    private const string Canary = "synthetic-private-exception-canary";
    public static TheoryData<ServiceStartupPhase, string, bool> Cases => new(
        from phase in new[] { ServiceStartupPhase.BootstrapConfiguration, ServiceStartupPhase.PendingSetup, ServiceStartupPhase.Completed }
        from kind in new[] { "argument", "state", "unknown" }
        from prefix in new[] { false, true }
        select (phase, kind, prefix));

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task EachHostPhase_HasOneSafeBoundary(ServiceStartupPhase phase, string kind, bool prefix)
    {
        var logs = new CapturedLogs();
        await using var app = await StartAsync(phase, logs);
        using var client = app.GetTestClient();
        using var response = await client.GetAsync($"/{(prefix ? "prefix" : "endpoint")}/{kind}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal(prefix ? "application/json" : "application/problem+json", response.Content.Headers.ContentType!.MediaType);
        var content = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain(Canary, content);
        using var json = JsonDocument.Parse(content);
        if (prefix)
        {
            Assert.Equal(new[] { "Detail", "Status", "Title" }, json.RootElement.EnumerateObject().Select(p => p.Name).Order().ToArray());
            Assert.Equal(500, json.RootElement.GetProperty("Status").GetInt32());
        }
        else
        {
            Assert.Equal(new[] { "correlationId", "errorCode", "status", "title", "type" }, json.RootElement.EnumerateObject().Select(p => p.Name).Order().ToArray());
            Assert.Equal(500, json.RootElement.GetProperty("status").GetInt32());
            Assert.Equal(response.Headers.GetValues("x-correlation-id").Single(), json.RootElement.GetProperty("correlationId").GetString());
        }
        var error = Assert.Single(logs.Entries.Where(e => e.Level == LogLevel.Error));
        Assert.Equal(prefix ? typeof(ExceptionHandlingMiddleware).FullName : "ServiceMantle.Http.ProblemDetails", error.Category);
        Assert.All(logs.Entries, e => { Assert.Null(e.Exception); Assert.DoesNotContain(Canary, e.Message); });
    }

    [Theory]
    [InlineData(ServiceStartupPhase.BootstrapConfiguration)]
    [InlineData(ServiceStartupPhase.PendingSetup)]
    [InlineData(ServiceStartupPhase.Completed)]
    public async Task StartedResponse_IsNotRewrittenOrLoggedTwice(ServiceStartupPhase phase)
    {
        var logs = new CapturedLogs();
        await using var app = await StartAsync(phase, logs);
        using var client = app.GetTestClient();
        using var response = await client.GetAsync("/started", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.Equal("already-sent", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal("ServiceMantle.Http.ProblemDetails", Assert.Single(logs.Entries.Where(e => e.Level == LogLevel.Error)).Category);
    }

    [Theory]
    [InlineData(ServiceStartupPhase.BootstrapConfiguration)]
    [InlineData(ServiceStartupPhase.PendingSetup)]
    [InlineData(ServiceStartupPhase.Completed)]
    public async Task SharedErrorWriteFailure_PropagatesWithoutOuterFallback(ServiceStartupPhase phase)
    {
        var logs = new CapturedLogs();
        await using var app = await StartAsync(phase, logs);
        using var client = app.GetTestClient();
        var error = await Record.ExceptionAsync(() => client.GetAsync("/failed-write", TestContext.Current.CancellationToken));
        Assert.NotNull(error);
        Assert.Equal("ServiceMantle.Http.ProblemDetails", Assert.Single(logs.Entries.Where(e => e.Level == LogLevel.Error)).Category);
        Assert.DoesNotContain(logs.Entries, e => e.Category == typeof(ExceptionHandlingMiddleware).FullName);
    }

    [Theory]
    [InlineData(ServiceStartupPhase.BootstrapConfiguration)]
    [InlineData(ServiceStartupPhase.PendingSetup)]
    [InlineData(ServiceStartupPhase.Completed)]
    public async Task CallerCancellation_PropagatesWithoutErrorResponseOrErrorLog(ServiceStartupPhase phase)
    {
        var logs = new CapturedLogs();
        await using var app = await StartAsync(phase, logs);
        using var client = app.GetTestClient();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.GetAsync("/cancel", TestContext.Current.CancellationToken));
        Assert.Empty(logs.Entries.Where(e => e.Level == LogLevel.Error));
    }

    private static Exception Failure(string kind) => kind switch
    {
        "argument" => new ArgumentException(Canary),
        "state" => new InvalidOperationException(Canary),
        _ => new Exception(Canary)
    };

    private static async Task<WebApplication> StartAsync(ServiceStartupPhase phase, CapturedLogs logs)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Logging.AddProvider(logs);
        builder.Services.AddSignaCoreServiceMantle()
            .AddManagementCookieAuthentication().AddServiceMantleManagementApiV1()
            .AddSensitiveHeaders().AddSecurityResponseHeaders().AddRateLimiting();
        builder.Services.AddSingleton<IServiceHealthSnapshotSource>(new Snapshot(phase));
        var app = builder.Build();
        app.UseMiddleware<ExceptionHandlingMiddleware>();
        app.Use((http, next) => http.Request.Path.StartsWithSegments("/prefix")
            ? throw Failure(http.Request.Path.Value!.Split('/').Last()) : next(http));
        app.UseSignaCoreSharedHttpPipeline();
        app.MapGet("/endpoint/{kind}", (string kind) => Task.FromException(Failure(kind)))
            .WithServiceMantlePhaseAdmission(phase);
        app.MapGet("/started", async (HttpContext http) =>
        {
            http.Response.StatusCode = 202;
            await http.Response.WriteAsync("already-sent", http.RequestAborted);
            await http.Response.Body.FlushAsync(http.RequestAborted);
            throw Failure("unknown");
        }).WithServiceMantlePhaseAdmission(phase);
        app.MapGet("/failed-write", (HttpContext http) =>
        {
            http.Response.Body = new FailedWriteStream();
            return Task.FromException(Failure("unknown"));
        }).WithServiceMantlePhaseAdmission(phase);
        app.MapGet("/cancel", (HttpContext http) =>
        {
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();
            http.RequestAborted = cancellation.Token;
            return Task.FromException(new OperationCanceledException(cancellation.Token));
        }).WithServiceMantlePhaseAdmission(phase);
        try { await app.StartAsync(TestContext.Current.CancellationToken); return app; }
        catch { await app.DisposeAsync(); throw; }
    }

    private sealed class Snapshot(ServiceStartupPhase phase) : IServiceHealthSnapshotSource
    {
        public ValueTask<ServiceHealthSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new ServiceHealthSnapshot(phase, ServiceMigrationReadinessState.Succeeded, ServiceDatabaseReadinessState.Reachable));
    }
    private sealed class FailedWriteStream : MemoryStream
    {
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromException(new IOException("Synthetic write failure."));
    }
    private sealed class CapturedLogs : ILoggerProvider
    {
        public List<Entry> Entries { get; } = [];
        public ILogger CreateLogger(string categoryName) => new Logger(categoryName, this);
        public void Dispose() { }
        public sealed record Entry(string Category, LogLevel Level, string Message, Exception? Exception);
        private sealed class Logger(string category, CapturedLogs owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            { lock(owner.Entries) owner.Entries.Add(new(category, level, formatter(state, exception), exception)); }
        }
    }
}
