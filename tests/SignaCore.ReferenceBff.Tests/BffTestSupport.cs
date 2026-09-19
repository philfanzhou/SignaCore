extern alias BffSample;

using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Xunit;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;

namespace SignaCore.ReferenceBff.Tests;

/// <summary>
/// The SignaCore side of the reference-BFF contract tests: one installed SQLite host (the same
/// installation composition production uses), one interactive client registration whose redirect
/// URI routes to the BFF test server, and one seeded end user.
/// </summary>
public sealed partial class SignaCoreHostFixture : IAsyncLifetime
{
    public const string ClientId = "reference-bff";
    public const string ClientSecret = "reference-bff-test-secret";
    public const string RedirectUri = "https://bff.localhost/signin-oidc";
    public const string Username = "reference_bff_user";
    public const string Password = "Reference-Bff-123!";
    public const string Authority = "https://localhost";

    private WebApplicationFactory<Program>? _factory;
    private string? _bootstrapDirectory;
    private string? _databasePath;

    public WebApplicationFactory<Program> Host =>
        _factory ?? throw new InvalidOperationException("The fixture is not initialized.");

    public async ValueTask InitializeAsync()
    {
        _bootstrapDirectory = Path.Combine(
            Path.GetTempPath(),
            $"signacore-bff-{Guid.NewGuid():N}");
        _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-bff-{Guid.NewGuid():N}.db");
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
            "test-master-key-for-bff-tests-only",
            "bff_admin",
            "BffAdmin-123!",
            // The BFF's OIDC client resolves every endpoint from Discovery and enforces HTTPS
            // metadata addresses, so the installed settings carry an HTTPS public origin; the
            // in-memory TestServer serves both schemes identically.
            new Dictionary<string, string>
            {
                [SystemSettingKeys.PublicBaseUrl] = "https://localhost",
                [SystemSettingKeys.JwtIssuer] = "https://localhost"
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
                AppName = "Reference BFF",
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

        application.IsActive = true;
        application.AllowAuthorizationCode = true;
        application.AllowedScopes = "openid profile";

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
                Nickname = "reference-bff-nickname"
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
/// A browser over two TestServers: one host name routes to SignaCore, the other to the BFF. Both
/// clients share one cookie container, so the identity cookie, the antiforgery pair, the BFF
/// correlation cookie, and the BFF session cookie all replay exactly where they were set.
/// Redirects are followed manually, hop by hop, so a test always sees every intermediate
/// response.
/// </summary>
public sealed partial class CrossServerBrowser(
    HttpClient identityServer,
    HttpClient bff,
    Uri identityBase,
    Uri bffBase,
    CookieContainer cookies) : IDisposable
{
    public const int MaxHops = 12;

    public HttpClient IdentityServer => identityServer;
    public HttpClient Bff => bff;
    public Uri IdentityBase => identityBase;
    public Uri BffBase => bffBase;
    public CookieContainer Cookies => cookies;

    public List<(HttpRequestMessage Request, string Body)> IdentityServerRequests { get; } = [];
    public List<(HttpRequestMessage Request, string Body)> BffRequests { get; } = [];

    /// <summary>Drops every cookie of the BFF host — the "correlation cookie missing" attempt.</summary>
    public void DropAllBffCookies()
    {
        foreach (Cookie cookie in cookies.GetCookies(BffBase))
        {
            cookies.Add(BffBase, new Cookie(cookie.Name, "deleted")
            {
                Path = cookie.Path,
                Expires = DateTime.UnixEpoch,
                Secure = cookie.Secure,
                HttpOnly = cookie.HttpOnly
            });
        }
    }

    public async Task<(HttpResponseMessage Response, Uri FinalUri)> FollowFromBffAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        using var first = new HttpRequestMessage(HttpMethod.Get, new Uri(BffBase, path));
        return await FollowAsync(first, cancellationToken);
    }

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
            var record = client == bff ? BffRequests : IdentityServerRequests;
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

    /// <summary>Follows only SignaCore-local redirects of the login form; used to drive the
    /// credential POST manually rather than through the automatic chain.</summary>
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

    public async Task<HttpResponseMessage> SendOnBffAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken = default)
    {
        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(cancellationToken);
        BffRequests.Add((request, body));
        return await bff.SendAsync(request, cancellationToken);
    }

    private HttpClient ClientFor(Uri uri) =>
        string.Equals(uri.Host, BffBase.Host, StringComparison.Ordinal) ? bff : identityServer;

    public void Dispose()
    {
        identityServer.Dispose();
        bff.Dispose();
    }
}

/// <summary>
/// The BFF test server: the real sample application with its configuration pointed at the test
/// SignaCore host (or a fake authority), with the OIDC backchannel routed to the in-memory
/// TestServer client instead of the network.
/// </summary>
public static class BffTestServer
{
    public static WebApplicationFactory<BffSample.Program> Create(
        string authority,
        string clientId,
        string clientSecret,
        string redirectUri,
        HttpClient backchannel,
        HttpMessageHandler? userInfoHandler = null,
        TimeProvider? timeProvider = null) =>
        new WebApplicationFactory<BffSample.Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ReferenceBff:Authority", authority);
            builder.UseSetting("ReferenceBff:ClientId", clientId);
            builder.UseSetting("ReferenceBff:ClientSecret", clientSecret);
            builder.UseSetting("ReferenceBff:RedirectUri", redirectUri);
            builder.UseSetting("ReferenceBff:Scope", "openid profile");
            // Configure (not PostConfigure): the OIDC handler's own post-configuration builds the
            // ConfigurationManager over whatever backchannel is already set, so the test client
            // has to be in place before it runs.
            builder.ConfigureTestServices(services =>
            {
                services.ConfigureAll<OpenIdConnectOptions>(options =>
                {
                    options.Backchannel = backchannel;
                });

                // Route the BFF's UserInfo backchannel (the named "signacore" client) to the
                // in-memory SignaCore TestServer instead of the network.
                if (userInfoHandler is not null)
                {
                    services.AddHttpClient("signacore")
                        .ConfigurePrimaryHttpMessageHandler(() => userInfoHandler);
                }

                // A test-controlled clock replaces the system one for the ticket store's expiry
                // decisions (the last registration wins).
                if (timeProvider is not null)
                {
                    services.AddSingleton(timeProvider);
                }
            });
        });

    /// <summary>
    /// One browser over the SignaCore host and the BFF, with cookies enabled on both clients.
    /// </summary>
    public static CrossServerBrowser CreateBrowser(
        WebApplicationFactory<Program> identity,
        WebApplicationFactory<BffSample.Program> bff)
    {
        var container = new CookieContainer();
        var identityClient = CreateClientWithCookies(
            identity.Server.CreateHandler(), new Uri(SignaCoreHostFixture.Authority), container);
        var bffClient = CreateClientWithCookies(
            bff.Server.CreateHandler(), new Uri("https://bff.localhost"), container);
        return new CrossServerBrowser(
            identityClient,
            bffClient,
            new Uri(SignaCoreHostFixture.Authority),
            new Uri("https://bff.localhost"),
            container);

        static HttpClient CreateClientWithCookies(
            HttpMessageHandler handler,
            Uri baseAddress,
            CookieContainer container) =>
            new(new SharedCookieHandler(handler, container))
            {
                BaseAddress = baseAddress
            };
    }

    /// <summary>
    /// Builds a browser whose identity role is served by any HTTP client (the fake authority).
    /// </summary>
    public static CrossServerBrowser CreateBrowserOverAuthority(
        WebApplicationFactory<BffSample.Program> bff,
        HttpMessageHandler authorityHandler,
        Uri authorityBase)
    {
        var container = new CookieContainer();
        var identityClient = new HttpClient(new SharedCookieHandler(authorityHandler, container))
        {
            BaseAddress = authorityBase
        };
        var bffClient = new HttpClient(new SharedCookieHandler(bff.Server.CreateHandler(), container))
        {
            BaseAddress = new Uri("https://bff.localhost")
        };
        return new CrossServerBrowser(
            identityClient,
            bffClient,
            authorityBase,
            new Uri("https://bff.localhost"),
            container);
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
                "Cookie",
                container.GetCookieHeader(request.RequestUri!));
            var response = await base.SendAsync(request, cancellationToken);

            // Store every Set-Cookie against the requesting host, honoring the Secure flag by
            // only replaying over the HTTPS base addresses these tests use.
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
/// credential POST — exactly the browser half of the flow the sample is contracted to serve.
/// </summary>
public static partial class SignaCoreLoginDriver
{
    [GeneratedRegex("name=\"__RequestVerificationToken\" value=\"([^\"]*)\"")]
    private static partial Regex TokenPattern();

    public static async Task<string> GetLoginHandleAndCookieAsync(
        CrossServerBrowser browser,
        string authorizeUrl,
        CancellationToken cancellationToken = default)
    {
        using var authorize = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.IdentityBase, authorizeUrl));
        using var response = await browser.SendOnIdentityServerAsync(authorize, cancellationToken);
        if (response.StatusCode != HttpStatusCode.Found)
        {
            throw new InvalidOperationException(
                $"The authorize endpoint answered {response.StatusCode} instead of a login redirect.");
        }

        return response.Headers.Location!.ToString();
    }

    public static async Task<HttpResponseMessage> PostCredentialsAsync(
        CrossServerBrowser browser,
        string loginHandlePath,
        string username,
        string password,
        CancellationToken cancellationToken = default)
    {
        using var form = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(browser.IdentityBase, loginHandlePath));
        using var formResponse = await browser.SendOnIdentityServerAsync(form, cancellationToken);
        var html = await formResponse.Content.ReadAsStringAsync(cancellationToken);
        var token = TokenPattern().Match(html).Groups[1].Value;
        if (string.IsNullOrEmpty(token))
        {
            throw new InvalidOperationException("The login form carried no antiforgery token.");
        }

        var post = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(browser.IdentityBase, "/oauth2/login"))
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
