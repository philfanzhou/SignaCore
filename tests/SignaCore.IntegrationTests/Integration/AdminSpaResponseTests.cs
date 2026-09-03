using System.Collections.Concurrent;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using SignaCore.Database;
using SignaCore.Host;
using SignaCore.Host.Startup;
using SignaCore.Tests.Integration;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

public sealed class AdminSpaResponseTests
{
    private const string Template = "<html><head><title>__APP_TITLE__</title></head><body>Console</body></html>";
    private const string Title = "SPA Contract Test";

    [Theory]
    [InlineData("bootstrap")]
    [InlineData("setup")]
    [InlineData("normal")]
    public async Task HostModes_ServeInjectedIndexAndPreserveHistoryFallback(string mode)
    {
        using var files = new SpaFiles();
        var database = new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = new SqliteConnectionStringBuilder { DataSource = Path.Combine(files.Directory, "identity.db") }.ConnectionString
        };
        var bootstrapPath = mode switch
        {
            "normal" => await InstallationTestSupport.PrepareCompletedInstallationAsync(
                files.Directory, database, IdentityServerFixture.RootSecret,
                IdentityServerFixture.AdminUsername, IdentityServerFixture.AdminPassword,
                cancellationToken: TestContext.Current.CancellationToken),
            "setup" => await InstallationTestSupport.PrepareUninstalledBootstrapAsync(
                files.Directory, database, IdentityServerFixture.RootSecret, TestContext.Current.CancellationToken),
            _ => Path.Combine(files.Directory, "missing-bootstrap.json")
        };
        await using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseWebRoot(files.WebRoot);
            builder.UseSetting("Bootstrap:FilePath", bootstrapPath);
            // TestServer's local port is zero; the real SPA port predicate must run in this test.
            builder.UseSetting("Endpoints:Http", "0");
            builder.UseSetting("APP_TITLE", Title);
        });
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using var index = await client.GetAsync("/index.html", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, index.StatusCode);
        Assert.Equal("text/html; charset=utf-8", index.Content.Headers.ContentType?.ToString());
        Assert.Equal(AdminSpaTitleInjector.Inject(Template, Title),
            await index.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        var route = mode switch { "bootstrap" => "/bootstrap/route", "setup" => "/setup/route", _ => "/admin/accounts" };
        using var fallback = await client.GetAsync(route, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, fallback.StatusCode);
        Assert.Equal("text/html", fallback.Content.Headers.ContentType?.MediaType);
        // The existing history fallback uses static files directly, without title injection.
        Assert.Equal(Template, await fallback.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ClientCancellation_StopsIndexReadOrResponseWrite(bool beforeRead)
    {
        using var files = new SpaFiles();
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var aborted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var completed = new TaskCompletionSource<(bool Cancelled, string? ContentType, long Bytes, CancellationToken RequestToken)>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var logs = new LevelLoggerProvider();
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ContentRootPath = files.Directory,
            WebRootPath = files.WebRoot
        });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders().AddProvider(logs);
        await using var app = builder.Build();
        await using var body = new GatedResponseStream(reached, release);
        app.Use(async (context, next) =>
        {
            using var registration = context.RequestAborted.Register(() => aborted.TrySetResult());
            var originalBody = context.Response.Body;
            context.Response.Body = body;
            var observedCancellation = false;
            try
            {
                if (beforeRead)
                {
                    reached.TrySetResult();
                    await release.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
                }
                await next(context);
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
            {
                // Observe only this branch's cancellation. The global mapping is tracked by #197;
                // this isolated boundary also lets the file-read and write tokens be tested separately.
                observedCancellation = true;
            }
            finally
            {
                completed.TrySetResult((observedCancellation, context.Response.ContentType, body.Length, context.RequestAborted));
                context.Response.Body = originalBody;
            }
        });
        AdminSpaBranch.Map(app, 0);
        await app.StartAsync(TestContext.Current.CancellationToken);
        using var client = app.GetTestClient();
        var response = client.GetAsync("/index.html", cancellation.Token);
        try
        {
            await reached.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            cancellation.Cancel();
            await aborted.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            release.TrySetResult();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => response);
            var observed = await completed.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

            Assert.True(observed.Cancelled);
            Assert.Equal(0, observed.Bytes);
            if (beforeRead)
                Assert.Null(observed.ContentType);
            else
            {
                Assert.Equal("text/html; charset=utf-8", observed.ContentType);
                Assert.Equal(observed.RequestToken, body.ObservedToken);
            }
            Assert.DoesNotContain(LogLevel.Error, logs.Levels);
            Assert.DoesNotContain(LogLevel.Critical, logs.Levels);
        }
        finally
        {
            cancellation.Cancel();
            release.TrySetResult();
        }
    }

    private sealed class GatedResponseStream(TaskCompletionSource reached, TaskCompletionSource release) : MemoryStream
    {
        public CancellationToken ObservedToken { get; private set; }
        public override async Task FlushAsync(CancellationToken cancellationToken)
        {
            ObservedToken = cancellationToken;
            reached.TrySetResult();
            await release.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    private sealed class SpaFiles : IDisposable
    {
        public string Directory { get; } = Path.Combine(Path.GetTempPath(), $"signacore-spa-{Guid.NewGuid():N}");
        public string WebRoot => Path.Combine(Directory, "wwwroot");
        public SpaFiles()
        {
            System.IO.Directory.CreateDirectory(WebRoot);
            File.WriteAllText(Path.Combine(WebRoot, "index.html"), Template);
        }
        public void Dispose()
        {
            SqliteConnection.ClearAllPools();
            System.IO.Directory.Delete(Directory, recursive: true);
        }
    }

    private sealed class LevelLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<LogLevel> Levels { get; } = new();
        public ILogger CreateLogger(string categoryName) => new LevelLogger(Levels);
        public void Dispose() { }
        private sealed class LevelLogger(ConcurrentQueue<LogLevel> levels) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) => levels.Enqueue(logLevel);
        }
    }
}
