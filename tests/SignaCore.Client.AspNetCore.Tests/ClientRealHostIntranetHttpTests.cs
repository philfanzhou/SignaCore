extern alias ConsumerApp;

using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host;
using SignaCore.Host.Configuration;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The intranet HTTP deployment against the real SignaCore host, in memory: the host serves its
/// hosted login over its own explicit HTTP-origin allowlist (the Testing-environment carrier),
/// while the consumer runs in Production with the package's
/// <c>IntranetHttpOrigins</c> list — proving the package's opt-in is honored under a Production
/// environment name exactly as under any other. The full password sign-in, callback, session,
/// CSRF boundary, and prepared logout complete over the two intranet origins, and every package
/// cookie is written without the Secure attribute.
/// </summary>
public sealed class ClientRealHostIntranetHttpTests : IAsyncLifetime
{
    private const string Authority = "http://192.168.55.10:5002";
    private const string ConsumerOrigin = "http://192.168.55.10:5020";
    private const string RedirectUri = ConsumerOrigin + "/auth/callback";
    private const string PostLogoutRedirectUri = ConsumerOrigin + "/auth/logout/return";
    private const string SessionName = SignaCoreHostedLoginDefaults.SessionCookieName;

    private string? _bootstrapDirectory;
    private string? _databasePath;
    private WebApplicationFactory<Program>? _host;

    public async ValueTask InitializeAsync()
    {
        var temp = Path.GetTempPath();
        if (temp.StartsWith("/var/", StringComparison.Ordinal) && Directory.Exists("/private" + temp))
        {
            temp = "/private" + temp;
        }

        _bootstrapDirectory = Path.Combine(temp, $"signacore-intranet-{Guid.NewGuid():N}");
        _databasePath = Path.Combine(temp, $"signacore-intranet-{Guid.NewGuid():N}.db");
        var connectionString = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder
        {
            DataSource = _databasePath
        }.ConnectionString;

        // The host side of the intranet deployment: an HTTP public origin carried by the shared
        // hosted-login HTTP origin allowlist, exactly as the Testing carrier contract requires.
        var bootstrapFilePath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
            _bootstrapDirectory,
            new DatabaseOptions
            {
                Provider = "SQLite",
                ConnectionString = connectionString
            },
            "test-master-key-for-intranet-tests-only",
            "intranet_admin",
            "IntranetAdmin-123!",
            new Dictionary<string, string>
            {
                [SystemSettingKeys.PublicBaseUrl] = Authority,
                [SystemSettingKeys.JwtIssuer] = Authority,
                [SystemSettingKeys.SecurityHostedLoginHttpTestOrigins] =
                    $$"""["{{Authority}}","{{ConsumerOrigin}}"]"""
            });

        _host = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Testing");
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath);
                builder.UseSetting("Endpoints:Http", "0");
            });
        _host.CreateClient();
        await SeedAsync();
    }

    public async ValueTask DisposeAsync()
    {
        if (_host is not null)
        {
            await _host.DisposeAsync();
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
        using var scope = _host!.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var application = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = SignaCoreHostFixture.ClientId,
            AppSecretHash = BCrypt.Net.BCrypt.HashPassword(SignaCoreHostFixture.ClientSecret),
            AppName = "Intranet Client App",
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
        dbContext.AppRedirectUris.Add(new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = application.Id,
            Kind = RedirectUriKind.PostLogout,
            CanonicalUri = PostLogoutRedirectUri
        });

        var accountId = Guid.NewGuid();
        dbContext.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            Nickname = "intranet-nickname"
        });
        dbContext.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = SignaCoreHostFixture.Username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(SignaCoreHostFixture.Password),
            CreatedAt = DateTimeOffset.UtcNow
        });
        await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task TheProductionConsumer_CompletesHostedLoginOverTheIntranetHttpHost()
    {
        Assert.NotNull(_host);
        var consumer = ConsumerAppTestServer.Create(
            Authority,
            SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret,
            RedirectUri,
            _host.Server.CreateHandler(),
            postLogoutRedirectUri: PostLogoutRedirectUri,
            environment: "Production",
            configureTestServices: services => services.PostConfigure<SignaCoreHostedLoginOptions>(
                options => options.IntranetHttpOrigins = [Authority, ConsumerOrigin]));
        await using var _ = consumer;
        var browser = ConsumerAppTestServer.CreateBrowser(
            _host, consumer, new Uri(Authority), new Uri(ConsumerOrigin));
        using var __ = browser;

        // 1. The start resolves Discovery over the intranet HTTP origin and redirects to the
        //    real authorize endpoint; the binding cookie carries no Secure attribute.
        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start?returnUrl=/dashboard"));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, startResponse.StatusCode);
        Assert.StartsWith(
            Authority + "/oauth2/authorize",
            startResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.True(startResponse.Headers.TryGetValues("Set-Cookie", out var startCookies));
        var binding = Assert.Single(
            startCookies, cookie => cookie.Contains("-login-binding.", StringComparison.Ordinal));
        Assert.DoesNotContain("secure", binding, StringComparison.OrdinalIgnoreCase);

        // 2. The real hosted login page signs the browser in over the host's own HTTP carrier.
        using var login = await SignaCoreLoginDriver.DriveToCallbackUrlAsync(
            browser,
            startResponse.Headers.Location!.ToString(),
            SignaCoreHostFixture.Username,
            SignaCoreHostFixture.Password,
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, login.StatusCode);
        Assert.StartsWith(RedirectUri, login.Headers.Location!.ToString(), StringComparison.Ordinal);

        // 3. The callback redeems the code and writes the unsecured session cookie.
        using var callback = new HttpRequestMessage(HttpMethod.Get, login.Headers.Location!);
        using var callbackResponse = await browser.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal("/dashboard", callbackResponse.Headers.Location!.ToString());
        Assert.True(callbackResponse.Headers.TryGetValues("Set-Cookie", out var callbackCookies));
        var session = Assert.Single(
            callbackCookies, cookie => cookie.StartsWith(SessionName + "=", StringComparison.Ordinal));
        Assert.DoesNotContain("secure", session, StringComparison.OrdinalIgnoreCase);

        // 4. The protected route and the session endpoint answer from the server-side session.
        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var dashboardResponse = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, dashboardResponse.StatusCode);
        using var sessionRead = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/session"));
        using var sessionResponse = await browser.SendOnConsumerAsync(
            sessionRead, TestContext.Current.CancellationToken);
        var sessionBody = await sessionResponse.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken);
        Assert.Contains("\"authenticated\":true", sessionBody, StringComparison.Ordinal);
        Assert.Contains(SignaCoreHostFixture.Username, sessionBody, StringComparison.Ordinal);

        // 5. The prepared logout and its return complete over the intranet origins.
        using var csrf = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/csrf"));
        using var csrfResponse = await browser.SendOnConsumerAsync(
            csrf, TestContext.Current.CancellationToken);
        var csrfBody = await csrfResponse.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken);
        var token = System.Text.Json.JsonSerializer
            .Deserialize<System.Text.Json.JsonElement>(csrfBody).GetProperty("token").GetString()!;
        using var logout = new HttpRequestMessage(
            HttpMethod.Post, new Uri(browser.ConsumerBase, "/auth/logout"));
        logout.Headers.TryAddWithoutValidation(
            SignaCoreHostedLoginDefaults.AntiforgeryHeaderName, token);
        using var logoutResponse = await browser.SendOnConsumerAsync(
            logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, logoutResponse.StatusCode);

        using var completion = new HttpRequestMessage(
            HttpMethod.Get, logoutResponse.Headers.Location!);
        using var completionResponse = await browser.SendOnIdentityServerAsync(
            completion, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, completionResponse.StatusCode);
        using var landing = new HttpRequestMessage(
            HttpMethod.Get, completionResponse.Headers.Location!);
        using var landingResponse = await browser.SendOnConsumerAsync(
            landing, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, landingResponse.StatusCode);
        Assert.Equal("/signed-out", landingResponse.Headers.Location!.ToString());
    }
}
