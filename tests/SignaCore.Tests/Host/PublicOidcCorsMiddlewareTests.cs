using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host.Http;
using SignaCore.Host.Middleware;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Host;

/// <summary>
/// The actual-response read condition of the Public token endpoint CORS middleware. Code redemption
/// and refresh rotation share one rule: a single parsed grant_type of either value, a validated
/// active Public application, an exact registered Origin, and a request that was not cancelled
/// before the response started.
/// </summary>
public sealed class PublicOidcCorsMiddlewareTests
{
    private const string Origin = "https://spa.example.test";

    [Theory]
    [InlineData("authorization_code")]
    [InlineData("refresh_token")]
    public async Task RegisteredOriginOfValidatedPublicApp_ReadsTheTokenResponse(string grantType)
    {
        await using var database = await TestDatabase.CreateAsync();
        var app = await database.SeedAppAsync(Origin);

        var context = await InvokeAsync(database, app, Form(("grant_type", grantType)));

        Assert.Equal(Origin, context.Response.Headers.AccessControlAllowOrigin.ToString());
        Assert.False(context.Response.Headers.ContainsKey("Access-Control-Allow-Credentials"));
        Assert.Contains("Origin", context.Response.Headers.Vary.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("authorization_code")]
    [InlineData("refresh_token")]
    public async Task CancellationBeforeTheResponseStarts_AddsNoReadPermission(string grantType)
    {
        await using var database = await TestDatabase.CreateAsync();
        var app = await database.SeedAppAsync(Origin);
        using var aborted = new CancellationTokenSource();

        var context = await InvokeAsync(database, app, Form(("grant_type", grantType)),
            abort: aborted, cancelDownstream: true);

        Assert.True(context.RequestAborted.IsCancellationRequested);
        Assert.False(context.Response.Headers.ContainsKey("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task OtherOrRepeatedGrantTypes_AreNotReadable()
    {
        await using var database = await TestDatabase.CreateAsync();
        var app = await database.SeedAppAsync(Origin);

        foreach (var form in new[]
                 {
                     Form(("grant_type", "client_credentials")),
                     Form(("grant_type", "password")),
                     Form(("grant_type", "REFRESH_TOKEN")),
                     Form(("grant_type", "refresh_token"), ("grant_type", "refresh_token")),
                     Form(("grant_type", "authorization_code"), ("grant_type", "refresh_token")),
                     Form()
                 })
        {
            var context = await InvokeAsync(database, app, form);
            Assert.False(context.Response.Headers.ContainsKey("Access-Control-Allow-Origin"));
        }
    }

    [Theory]
    [InlineData(OidcBoundedFormStatus.Malformed)]
    [InlineData(OidcBoundedFormStatus.Unavailable)]
    [InlineData(null)]
    public async Task UnparsedForm_IsNotReadable(OidcBoundedFormStatus? status)
    {
        await using var database = await TestDatabase.CreateAsync();
        var app = await database.SeedAppAsync(Origin);

        var context = await InvokeAsync(database, app, Form(("grant_type", "refresh_token")), formStatus: status);

        Assert.False(context.Response.Headers.ContainsKey("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task MissingCrossAppInactiveOrConfidentialValidatedApp_IsNotReadable()
    {
        await using var database = await TestDatabase.CreateAsync();
        var app = await database.SeedAppAsync(Origin);
        var inactive = await database.SeedAppAsync("https://inactive.example.test", active: false);
        var confidential = await database.SeedAppAsync("https://confidential.example.test",
            clientType: OidcClientType.Confidential);
        var other = await database.SeedAppAsync("https://other.example.test");

        var missing = await InvokeAsync(database, null, Form(("grant_type", "refresh_token")));
        var crossApp = await InvokeAsync(database, app, Form(("grant_type", "refresh_token")),
            origin: "https://other.example.test");
        var disabled = await InvokeAsync(database, inactive, Form(("grant_type", "refresh_token")),
            origin: "https://inactive.example.test");
        var nonPublic = await InvokeAsync(database, confidential, Form(("grant_type", "refresh_token")),
            origin: "https://confidential.example.test");
        var control = await InvokeAsync(database, other, Form(("grant_type", "refresh_token")),
            origin: "https://other.example.test");

        foreach (var context in new[] { missing, crossApp, disabled, nonPublic })
        {
            Assert.False(context.Response.Headers.ContainsKey("Access-Control-Allow-Origin"));
        }

        Assert.Equal("https://other.example.test", control.Response.Headers.AccessControlAllowOrigin.ToString());
    }

    private static FormCollection Form(params (string Name, string Value)[] fields) =>
        new(fields.GroupBy(field => field.Name).ToDictionary(
            group => group.Key,
            group => new StringValues(group.Select(field => field.Value).ToArray())));

    private static async Task<HttpContext> InvokeAsync(
        TestDatabase database,
        AppRegistrationEntity? validatedApp,
        FormCollection form,
        string origin = Origin,
        OidcBoundedFormStatus? formStatus = OidcBoundedFormStatus.Parsed,
        CancellationTokenSource? abort = null,
        bool cancelDownstream = false)
    {
        var context = new DefaultHttpContext();
        var responseStart = new ResponseStartFeature(context.Features.Get<IHttpResponseFeature>()!);
        context.Features.Set<IHttpResponseFeature>(responseStart);
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = "/oauth2/token";
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Headers.Origin = origin;
        context.Features.Set<IFormFeature>(new FormFeature(form));
        if (abort is not null)
        {
            context.RequestAborted = abort.Token;
        }

        if (formStatus is not null)
        {
            context.Items[BoundedOidcFormReadingMiddleware.StatusItemKey] = formStatus.Value;
        }

        var middleware = new PublicOidcCorsMiddleware(downstream =>
        {
            if (validatedApp is not null)
            {
                downstream.Items[IdentityHeaders.ValidatedApp] = validatedApp;
            }

            if (cancelDownstream)
            {
                abort!.Cancel();
            }

            return Task.CompletedTask;
        });
        await using var db = database.CreateContext();
        await middleware.InvokeAsync(context, db, new ProductionEnvironment());
        await responseStart.StartResponseAsync();
        return context;
    }

    /// <summary>Replays the registered OnStarting callbacks the way a real server starts a response.</summary>
    private sealed class ResponseStartFeature(IHttpResponseFeature inner) : IHttpResponseFeature
    {
        private readonly List<(Func<object, Task> Callback, object State)> onStarting = [];

        public Stream Body { get => inner.Body; set => inner.Body = value; }
        public IHeaderDictionary Headers { get => inner.Headers; set => inner.Headers = value; }
        public bool HasStarted => inner.HasStarted;
        public string? ReasonPhrase { get => inner.ReasonPhrase; set => inner.ReasonPhrase = value; }
        public int StatusCode { get => inner.StatusCode; set => inner.StatusCode = value; }

        public void OnStarting(Func<object, Task> callback, object state) => onStarting.Add((callback, state));

        public void OnCompleted(Func<object, Task> callback, object state) => inner.OnCompleted(callback, state);

        public async Task StartResponseAsync()
        {
            foreach (var (callback, state) in onStarting)
            {
                await callback(state);
            }
        }
    }

    private sealed class ProductionEnvironment : IWebHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Production";
        public string ApplicationName { get; set; } = "SignaCore.Tests";
        public string WebRootPath { get; set; } = string.Empty;
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public string ContentRootPath { get; set; } = string.Empty;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private sealed class TestDatabase : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly DbContextOptions<IdentityDbContext> _options;

        private TestDatabase(SqliteConnection connection, DbContextOptions<IdentityDbContext> options)
        {
            _connection = connection;
            _options = options;
        }

        public IdentityDbContext CreateContext() => new(_options);

        public static async Task<TestDatabase> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);
            var options = new DbContextOptionsBuilder<IdentityDbContext>().UseSqlite(connection).Options;
            await using var context = new IdentityDbContext(options);
            await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
            return new TestDatabase(connection, options);
        }

        public async Task<AppRegistrationEntity> SeedAppAsync(
            string origin,
            bool active = true,
            OidcClientType clientType = OidcClientType.Public)
        {
            var appId = $"cors-{Guid.NewGuid():N}";
            var app = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = appId,
                AppIdNormalized = appId.ToUpperInvariant(),
                AppName = "Cors Test Application",
                IsActive = active,
                ClientType = clientType,
                CreatedAt = DateTimeOffset.UtcNow
            };
            await using var context = CreateContext();
            context.AppRegistrations.Add(app);
            context.AppAllowedOrigins.Add(new AppAllowedOriginEntity
            {
                Id = Guid.NewGuid(), AppRegistrationId = app.Id, CanonicalOrigin = origin
            });
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
            return app;
        }

        public async ValueTask DisposeAsync() => await _connection.DisposeAsync();
    }
}
