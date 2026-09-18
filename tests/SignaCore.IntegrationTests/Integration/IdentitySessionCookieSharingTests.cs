using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ServiceMantle.AspNetCore.Management;
using SignaCore.Database;
using SignaCore.Host;
using SignaCore.Host.Security;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The identity cookie across instances (canonical PS-18): two hosts over one ServiceMantle key
/// ring read the same cookie, the cookie cannot reach the AdminSession API, an instance with its
/// own key ring rejects it, and the identity and management payloads never unprotect under each
/// other's purpose. The identity state stays internal: a handleless login GET is a local error
/// and no Discovery capability is activated (AC-02).
/// </summary>
public sealed class IdentitySessionCookieSharingTests : IAsyncLifetime
{
    private const string IdentityCookieName = "__Host-signacore_identity";
    private const string ManagementCookieName = "__Host-ServiceMantle.Management";
    private const string AdminUsername = "identity_cookie_admin";
    private const string AdminPassword = "IdentityCookie123!";

    private readonly List<WebApplicationFactory<Program>> _factories = [];
    private readonly List<string> _databasePaths = [];
    private readonly List<string> _bootstrapDirectories = [];
    private string? _sharedBootstrapFilePath;
    private string? _isolatedBootstrapFilePath;

    public async ValueTask InitializeAsync()
    {
        _sharedBootstrapFilePath = await PrepareInstallationAsync("shared");
        _isolatedBootstrapFilePath = await PrepareInstallationAsync("isolated");
    }

    private async Task<string> PrepareInstallationAsync(string label)
    {
        var bootstrapDirectory = Path.Combine(
            Path.GetTempPath(), $"signacore-identity-cookie-{label}-{Guid.NewGuid():N}");
        var databasePath = Path.Combine(
            Path.GetTempPath(), $"signacore-identity-cookie-{label}-{Guid.NewGuid():N}.db");
        _bootstrapDirectories.Add(bootstrapDirectory);
        _databasePaths.Add(databasePath);
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath
        }.ConnectionString;

        return await InstallationTestSupport.PrepareCompletedInstallationAsync(
            bootstrapDirectory,
            new DatabaseOptions { Provider = "SQLite", ConnectionString = connectionString },
            IdentityServerFixture.RootSecret,
            AdminUsername,
            AdminPassword);
    }

    private WebApplicationFactory<Program> CreateInstance(string bootstrapFilePath)
    {
        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath));
        _factories.Add(factory);
        // Materialize the host so its startup validators have run.
        factory.CreateClient();
        return factory;
    }

    /// <summary>
    /// Issues an identity cookie through the real cookie handler of the given instance, exactly as
    /// a future sign-in path would, and returns the raw cookie header plus the Set-Cookie value.
    /// </summary>
    private static async Task<(string CookieHeader, string SetCookie)> IssueIdentityCookieAsync(
        WebApplicationFactory<Program> factory,
        Guid sessionId)
    {
        using var scope = factory.Services.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        await context.SignInAsync(
            IdentitySessionDefaults.AuthenticationScheme,
            IdentitySessionPrincipal.Create(sessionId));

        var setCookie = Assert.Single(context.Response.Headers["Set-Cookie"].ToArray());
        Assert.StartsWith($"{IdentityCookieName}=", setCookie, StringComparison.Ordinal);
        var cookieHeader = setCookie.Split(';')[0];
        return (cookieHeader, setCookie);
    }

    private static async Task<AuthenticateResult> AuthenticateIdentityCookieAsync(
        WebApplicationFactory<Program> factory,
        string cookieHeader)
    {
        using var scope = factory.Services.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        context.Request.Headers.Cookie = cookieHeader;
        return await context.AuthenticateAsync(IdentitySessionDefaults.AuthenticationScheme);
    }

    private static async Task<string> LoginManagementAsync(WebApplicationFactory<Program> factory)
    {
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
        {
            Content = JsonContent.Create(new
            {
                username = AdminUsername,
                password = AdminPassword
            })
        };
        request.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(response.Headers.NonValidated.TryGetValues("Set-Cookie", out var cookieValues));
        return cookieValues
            .Single(value => value.StartsWith($"{ManagementCookieName}=", StringComparison.Ordinal))
            .Split(';')[0];
    }

    [Fact]
    public async Task TheSameIdentityCookie_IsAcceptedByBothInstances()
    {
        using var first = CreateInstance(_sharedBootstrapFilePath!);
        using var second = CreateInstance(_sharedBootstrapFilePath!);
        var sessionId = Guid.NewGuid();

        var (cookieHeader, setCookie) = await IssueIdentityCookieAsync(first, sessionId);

        // The wire attributes follow PS-18: host-only, secure, lax, root path, no domain.
        Assert.Contains("; path=/", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("; secure", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("; samesite=lax", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("; httponly", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("; domain", setCookie, StringComparison.OrdinalIgnoreCase);

        var firstResult = await AuthenticateIdentityCookieAsync(first, cookieHeader);
        Assert.True(firstResult.Succeeded);

        // The second instance reads the same cookie through the shared encrypted key ring, and
        // the payload that survives the real handler round trip is still only the opaque id.
        var secondResult = await AuthenticateIdentityCookieAsync(second, cookieHeader);
        Assert.True(secondResult.Succeeded);
        var identity = Assert.Single(secondResult.Principal!.Identities);
        Assert.Equal(IdentitySessionDefaults.AuthenticationScheme, identity.AuthenticationType);
        var claim = Assert.Single(identity.Claims);
        Assert.Equal(IdentitySessionDefaults.SessionIdClaim, claim.Type);
        Assert.Equal(sessionId.ToString(), claim.Value);
    }

    [Fact]
    public async Task AnIdentityCookie_CannotReachTheAdminSessionApi()
    {
        using var instance = CreateInstance(_sharedBootstrapFilePath!);
        var (cookieHeader, _) = await IssueIdentityCookieAsync(instance, Guid.NewGuid());

        // The identity cookie is Secure, so the client addresses the in-memory host over https.
        using var client = instance.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
        client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", cookieHeader);
        using var response = await client.GetAsync(
            "/api/admin/session/me", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AnInstanceWithItsOwnKeyRing_RejectsTheSharedIdentityCookie()
    {
        using var shared = CreateInstance(_sharedBootstrapFilePath!);
        using var isolated = CreateInstance(_isolatedBootstrapFilePath!);
        var (cookieHeader, _) = await IssueIdentityCookieAsync(shared, Guid.NewGuid());

        // Without the shared key ring the cross-instance read fails as designed; the payload of
        // another deployment is never an identity result here.
        var result = await AuthenticateIdentityCookieAsync(isolated, cookieHeader);
        Assert.False(result.Succeeded);
        Assert.Null(result.Principal);
    }

    [Fact]
    public async Task TheIdentityAndManagementCookies_DoNotUnprotectUnderEachOthersPurpose()
    {
        using var instance = CreateInstance(_sharedBootstrapFilePath!);
        var (identityCookieHeader, _) = await IssueIdentityCookieAsync(instance, Guid.NewGuid());
        var managementCookieHeader = await LoginManagementAsync(instance);
        var identityValue = identityCookieHeader[(IdentityCookieName.Length + 1)..];
        var managementValue = managementCookieHeader[(ManagementCookieName.Length + 1)..];

        using var scope = instance.Services.CreateScope();
        var monitor = scope.ServiceProvider
            .GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>();
        var identityFormat =
            monitor.Get(IdentitySessionDefaults.AuthenticationScheme).TicketDataFormat!;
        var managementFormat =
            monitor.Get(ManagementSessionDefaults.AuthenticationScheme).TicketDataFormat!;

        // Both cookies ride the same fixed application discriminator and the same shared key
        // ring, so the rejection can only come from the distinct purposes: each format refuses
        // the other's payload instead of deserializing it.
        Assert.Null(managementFormat.Unprotect(identityValue));
        Assert.Null(identityFormat.Unprotect(managementValue));

        // The management cookie never satisfies the identity scheme, and the identity cookie
        // never satisfies the management scheme.
        var identityOnManagement = await AuthenticateIdentityCookieAsync(
            instance, managementCookieHeader);
        Assert.False(identityOnManagement.Succeeded);
        var managementOnIdentity = await AuthenticateManagementAsync(instance, identityCookieHeader);
        Assert.False(managementOnIdentity.Succeeded);
    }

    [Fact]
    public async Task AHandlelessLoginGetIsALocalErrorAndDiscoveryStaysInactive()
    {
        using var instance = CreateInstance(_sharedBootstrapFilePath!);
        using var client = instance.CreateClient();

        // The login route exists but a GET without a login_handle shares the single local 400 of
        // EV-03; the interactive core is advertised by capability (AC-07), never by login state,
        // and the not-yet-delivered logout route stays unadvertised (AC-10).
        using var login = await client.GetAsync("/oauth2/login", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, login.StatusCode);
        Assert.Null(login.Headers.Location);

        using var discovery = await client.GetAsync(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, discovery.StatusCode);
        using var document = JsonDocument.Parse(
            await discovery.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.True(document.RootElement.TryGetProperty("authorization_endpoint", out _));
        Assert.False(document.RootElement.TryGetProperty("end_session_endpoint", out _));
    }

    private static async Task<AuthenticateResult> AuthenticateManagementAsync(
        WebApplicationFactory<Program> factory,
        string cookieHeader)
    {
        using var scope = factory.Services.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        context.Request.Headers.Cookie = cookieHeader;
        return await context.AuthenticateAsync(ManagementSessionDefaults.AuthenticationScheme);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var factory in _factories)
        {
            factory.Dispose();
        }

        SqliteConnection.ClearAllPools();
        foreach (var databasePath in _databasePaths)
        {
            if (File.Exists(databasePath))
            {
                File.Delete(databasePath);
            }
        }

        foreach (var bootstrapDirectory in _bootstrapDirectories)
        {
            if (Directory.Exists(bootstrapDirectory))
            {
                Directory.Delete(bootstrapDirectory, recursive: true);
            }
        }

        await ValueTask.CompletedTask;
    }
}
