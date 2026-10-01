extern alias ConsumerApp;

using System.Collections.Concurrent;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SignaCore.Client.AspNetCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The SignaCore side of the client-package contract tests: one installed SQLite host (the same
/// installation composition production uses), one interactive Confidential client registration
/// whose redirect URI routes to the consumer test server, and one seeded end user.
/// </summary>
public sealed partial class SignaCoreHostFixture : IAsyncLifetime
{
    public const string ClientId = "client-pack-app";
    public const string ClientSecret = "client-pack-test-secret";
    public const string RedirectUri = "https://bff.localhost/auth/callback";
    public const string Username = "client_pack_user";
    public const string Password = "Client-Pack-123!";
    public const string Authority = "https://localhost";

    private WebApplicationFactory<Program>? _factory;
    private string? _bootstrapDirectory;
    private string? _databasePath;

    public WebApplicationFactory<Program> Host =>
        _factory ?? throw new InvalidOperationException("The fixture is not initialized.");

    public async ValueTask InitializeAsync()
    {
        // The shared SQLite target preparation rejects symlinked path components, and macOS
        // exposes the per-user temp directory under /var, a symlink to /private/var: use the
        // physical location so the tests exercise the contract instead of the platform's symlink.
        var temp = Path.GetTempPath();
        if (temp.StartsWith("/var/", StringComparison.Ordinal) && Directory.Exists("/private" + temp))
        {
            temp = "/private" + temp;
        }

        _bootstrapDirectory = Path.Combine(temp, $"signacore-client-pack-{Guid.NewGuid():N}");
        _databasePath = Path.Combine(temp, $"signacore-client-pack-{Guid.NewGuid():N}.db");
        var connectionString = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder
        {
            DataSource = _databasePath
        }.ConnectionString;

        var bootstrapFilePath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
            _bootstrapDirectory,
            new DatabaseOptions
            {
                Provider = "SQLite",
                ConnectionString = connectionString
            },
            "test-master-key-for-client-pack-tests-only",
            "client_pack_admin",
            "ClientPackAdmin-123!",
            // The package resolves every endpoint from Discovery and enforces HTTPS addresses, so
            // the installed settings carry an HTTPS public origin; the in-memory TestServer
            // serves both schemes identically.
            new Dictionary<string, string>
            {
                [SystemSettingKeys.PublicBaseUrl] = Authority,
                [SystemSettingKeys.JwtIssuer] = Authority
            });

        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath);
                builder.UseSetting("Endpoints:Http", "0");
            });
        _factory.CreateClient();
        await SeedAsync();
    }

    public async ValueTask DisposeAsync()
    {
        if (_factory is not null)
        {
            await _factory.DisposeAsync();
        }

        if (File.Exists(_databasePath))
        {
            File.Delete(_databasePath);
        }

        if (Directory.Exists(_bootstrapDirectory))
        {
            Directory.Delete(_bootstrapDirectory, recursive: true);
        }
    }

    private async Task SeedAsync()
    {
        using var scope = _factory!.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var application = await dbContext.AppRegistrations
            .FirstOrDefaultAsync(app => app.AppId == ClientId, TestContext.Current.CancellationToken);
        if (application is null)
        {
            application = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = ClientId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword(ClientSecret),
                AppName = "Client Package App",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.PerApplication,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = "openid profile",
                AllowRefreshToken = false
            };
            dbContext.AppRegistrations.Add(application);
            dbContext.AppRedirectUris.Add(new AppRedirectUriEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = application.Id,
                Kind = RedirectUriKind.Redirect,
                CanonicalUri = RedirectUri
            });
        }

        var credential = await dbContext.PasswordCredentials
            .FirstOrDefaultAsync(row => row.Username == Username, TestContext.Current.CancellationToken);
        if (credential is null)
        {
            var accountId = Guid.NewGuid();
            dbContext.Accounts.Add(new AccountEntity
            {
                Id = accountId,
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                Nickname = "client-pack-nickname"
            });
            dbContext.PasswordCredentials.Add(new PasswordCredentialEntity
            {
                Id = Guid.NewGuid(),
                AccountId = accountId,
                Username = Username,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(Password),
                CreatedAt = DateTimeOffset.UtcNow
            });
        }

        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        dbContext.ChangeTracker.Clear();
    }
}

/// <summary>
/// A browser over two servers: one host name routes to SignaCore (or the fake authority), the
/// other to the consumer application under test. Both clients share one cookie container, so the
/// SignaCore identity cookie and the package's session cookie replay exactly where they were set.
/// Redirects are followed manually, hop by hop, so a test always sees every intermediate response.
/// </summary>
public sealed class CrossServerBrowser(
    HttpClient identityServer,
    HttpClient consumer,
    Uri identityBase,
    Uri consumerBase,
    CookieContainer cookies) : IDisposable
{
    public const int MaxHops = 12;

    public HttpClient IdentityServer => identityServer;
    public HttpClient Consumer => consumer;
    public Uri IdentityBase => identityBase;
    public Uri ConsumerBase => consumerBase;
    public CookieContainer Cookies => cookies;

    public List<(HttpRequestMessage Request, string Body)> IdentityServerRequests { get; } = [];
    public List<(HttpRequestMessage Request, string Body)> ConsumerRequests { get; } = [];

    public async Task<(HttpResponseMessage Response, Uri FinalUri)> FollowAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken = default)
    {
        HttpResponseMessage response;
        Uri current;
        var hop = 0;
        do
        {
            var client = ClientFor(request.RequestUri!);
            var record = client == consumer ? ConsumerRequests : IdentityServerRequests;
            var body = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);
            record.Add((request, body));
            response = await client.SendAsync(request, cancellationToken);
            hop++;
            if (hop > MaxHops)
            {
                throw new InvalidOperationException("The redirect chain exceeded the hop budget.");
            }

            if (response.StatusCode is HttpStatusCode.Found
                or HttpStatusCode.RedirectKeepVerb
                or HttpStatusCode.SeeOther
                or HttpStatusCode.TemporaryRedirect)
            {
                current = new Uri(request.RequestUri!, response.Headers.Location!);
                request.Dispose();
                request = new HttpRequestMessage(HttpMethod.Get, current);
            }
            else
            {
                current = request.RequestUri!;
                break;
            }
        }
        while (true);

        return (response, current);
    }

    public async Task<HttpResponseMessage> SendOnIdentityServerAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken = default)
    {
        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(cancellationToken);
        IdentityServerRequests.Add((request, body));
        return await identityServer.SendAsync(request, cancellationToken);
    }

    public async Task<HttpResponseMessage> SendOnConsumerAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken = default)
    {
        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(cancellationToken);
        ConsumerRequests.Add((request, body));
        return await consumer.SendAsync(request, cancellationToken);
    }

    private HttpClient ClientFor(Uri uri) =>
        string.Equals(uri.Host, ConsumerBase.Host, StringComparison.Ordinal) ? consumer : identityServer;

    public void Dispose()
    {
        identityServer.Dispose();
        consumer.Dispose();
    }
}

/// <summary>
/// The consumer test server: the real consumer application with its package configuration
/// pointed at the test SignaCore host (or a fake authority), with the package's backchannel
/// routed to the in-memory server instead of the network.
/// </summary>
public static class ConsumerAppTestServer
{
    public static WebApplicationFactory<ConsumerApp.Program> Create(
        string authority,
        string clientId,
        string clientSecret,
        string redirectUri,
        HttpMessageHandler backchannelHandler,
        TimeProvider? timeProvider = null,
        Action<IServiceCollection>? configureTestServices = null,
        string? environment = null,
        ILoggerProvider? loggerProvider = null) =>
        new WebApplicationFactory<ConsumerApp.Program>().WithWebHostBuilder(builder =>
        {
            if (environment is not null)
            {
                builder.UseEnvironment(environment);
            }

            if (loggerProvider is not null)
            {
                builder.ConfigureLogging(logging => logging.AddProvider(loggerProvider));
            }

            builder.UseSetting("ClientApp:Authority", authority);
            builder.UseSetting("ClientApp:ClientId", clientId);
            builder.UseSetting("ClientApp:ClientSecret", clientSecret);
            builder.UseSetting("ClientApp:RedirectUri", redirectUri);

            builder.ConfigureTestServices(services =>
            {
                // Route the package's Discovery/JWKS/token backchannel to the in-memory server.
                services.AddHttpClient(SignaCoreHostedLoginDefaults.HttpClientName)
                    .ConfigurePrimaryHttpMessageHandler(() => backchannelHandler);

                // A test-controlled clock replaces the system one for the ticket store's expiry
                // decisions (the last registration wins).
                if (timeProvider is not null)
                {
                    services.AddSingleton(timeProvider);
                }

                configureTestServices?.Invoke(services);
            });
        });

    /// <summary>One browser over the SignaCore host and the consumer, sharing one cookie container.</summary>
    public static CrossServerBrowser CreateBrowser(
        WebApplicationFactory<Program> identity,
        WebApplicationFactory<ConsumerApp.Program> consumer)
    {
        var container = new CookieContainer();
        var identityClient = CreateClientWithCookies(
            identity.Server.CreateHandler(), new Uri(SignaCoreHostFixture.Authority), container);
        var consumerClient = CreateClientWithCookies(
            consumer.Server.CreateHandler(), new Uri("https://bff.localhost"), container);
        return new CrossServerBrowser(
            identityClient,
            consumerClient,
            new Uri(SignaCoreHostFixture.Authority),
            new Uri("https://bff.localhost"),
            container);

        static HttpClient CreateClientWithCookies(
            HttpMessageHandler handler, Uri baseAddress, CookieContainer container) =>
            new(new SharedCookieHandler(handler, container)) { BaseAddress = baseAddress };
    }

    /// <summary>A browser whose identity role is served by any HTTP handler (the fake authority).</summary>
    public static CrossServerBrowser CreateBrowserOverAuthority(
        WebApplicationFactory<ConsumerApp.Program> consumer,
        HttpMessageHandler authorityHandler,
        Uri authorityBase)
    {
        var container = new CookieContainer();
        var identityClient = new HttpClient(new SharedCookieHandler(authorityHandler, container))
        {
            BaseAddress = authorityBase
        };
        var consumerClient = new HttpClient(new SharedCookieHandler(consumer.Server.CreateHandler(), container))
        {
            BaseAddress = new Uri("https://bff.localhost")
        };
        return new CrossServerBrowser(
            identityClient, consumerClient, authorityBase, new Uri("https://bff.localhost"), container);
    }

    /// <summary>A delegating handler that shares one cookie container across both servers.</summary>
    public sealed class SharedCookieHandler(HttpMessageHandler inner, CookieContainer container)
        : DelegatingHandler(inner)
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            request.Headers.TryAddWithoutValidation(
                "Cookie", container.GetCookieHeader(request.RequestUri!));
            var response = await base.SendAsync(request, cancellationToken);
            if (response.Headers.NonValidated.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var cookie in cookies)
                {
                    try
                    {
                        container.SetCookies(request.RequestUri!, cookie);
                    }
                    catch (CookieException)
                    {
                        // A cookie the container refuses is not this harness's concern.
                    }
                }
            }

            return response;
        }
    }
}

/// <summary>
/// Drives SignaCore's real login form: the authorize redirect, the antiforgery pair, and the
/// credential POST — exactly the browser half of the flow the package is contracted to serve.
/// </summary>
public static partial class SignaCoreLoginDriver
{
    [GeneratedRegex("name=\"__RequestVerificationToken\" value=\"([^\"]*)\"")]
    private static partial Regex TokenPattern();

    public static async Task<HttpResponseMessage> DriveToCallbackUrlAsync(
        CrossServerBrowser browser,
        string authorizeUrl,
        string username,
        string password,
        CancellationToken cancellationToken = default)
    {
        using var authorize = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.IdentityBase, authorizeUrl));
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(authorize, cancellationToken);
        if (authorizeResponse.StatusCode != HttpStatusCode.Found)
        {
            throw new InvalidOperationException(
                $"The authorize endpoint answered {authorizeResponse.StatusCode} instead of a login redirect.");
        }

        var loginHandlePath = authorizeResponse.Headers.Location!.ToString();
        using var form = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.IdentityBase, loginHandlePath));
        using var formResponse = await browser.SendOnIdentityServerAsync(form, cancellationToken);
        var html = await formResponse.Content.ReadAsStringAsync(cancellationToken);
        var token = TokenPattern().Match(html).Groups[1].Value;
        if (string.IsNullOrEmpty(token))
        {
            throw new InvalidOperationException("The login form carried no antiforgery token.");
        }

        var post = new HttpRequestMessage(
            HttpMethod.Post, new Uri(browser.IdentityBase, "/oauth2/login"))
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["login_handle"] = loginHandlePath.Split('=')[1],
                ["username"] = username,
                ["password"] = password,
                ["__RequestVerificationToken"] = token,
                ["action"] = "login"
            })
        };
        return await browser.SendOnIdentityServerAsync(post, cancellationToken);
    }
}

/// <summary>
/// A test-controlled clock: the package's ticket store and pending-sign-in store read it for
/// every expiry decision, so a test can advance the session past the access token's expiry
/// without waiting.
/// </summary>
public sealed class ManualTimeProvider : TimeProvider
{
    private DateTimeOffset _utcNow;

    /// <summary>
    /// Starts at the real current instant: the shared cookie container judges a cookie's expiry
    /// by the system clock, so a synthetic past start would stop the session cookie from
    /// replaying before the package's own clock was ever advanced.
    /// </summary>
    public ManualTimeProvider() => _utcNow = DateTimeOffset.UtcNow;

    public ManualTimeProvider(DateTimeOffset initial) => _utcNow = initial;

    public override DateTimeOffset GetUtcNow() => _utcNow;

    public void Advance(TimeSpan duration) => _utcNow += duration;
}

/// <summary>
/// Captures every formatted log line the consumer host writes, so a test can assert that no
/// code, state, nonce, verifier, token, secret, or full query string ever appears in the output.
/// </summary>
public sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<string> _lines = new();

    public IReadOnlyList<string> Lines => _lines.ToArray();

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, _lines);

    public void Dispose()
    {
    }

    private sealed class CapturingLogger(
        string categoryName, ConcurrentQueue<string> lines) : ILogger
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
            lines.Enqueue($"[{categoryName}] {formatter(state, exception)} {exception}");
        }
    }
}
