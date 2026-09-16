using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle.AspNetCore.Management;
using SignaCore.Database;
using SignaCore.Host;
using SignaCore.Host.Security;
using SignaCore.Host.Startup;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The antiforgery pair's independence from every session layer (canonical <c>PS-19</c>): the
/// validation never touches the default-populated <c>HttpContext.User</c>, so a form rendered
/// anonymously survives a POST carrying a management or identity cookie and vice versa, and one
/// shared key ring lets instance B validate a pair instance A rendered. In the other direction the
/// antiforgery cookie satisfies no session policy, and no session cookie can stand in for it.
/// </summary>
public sealed class OAuthLoginAntiforgerySessionTests : IAsyncLifetime
{
    private const string ManagementCookieName = "__Host-ServiceMantle.Management";
    private const string AdminUsername = "login_antiforgery_admin";
    private const string AdminPassword = "LoginAntiforgery123!";

    private readonly List<WebApplicationFactory<Program>> _factories = [];
    private readonly List<string> _databasePaths = [];
    private readonly List<string> _bootstrapDirectories = [];
    private string? _sharedBootstrapFilePath;

    public async ValueTask InitializeAsync()
    {
        _sharedBootstrapFilePath = await PrepareInstallationAsync();
    }

    private async Task<string> PrepareInstallationAsync()
    {
        var bootstrapDirectory = Path.Combine(
            Path.GetTempPath(), $"signacore-login-antiforgery-{Guid.NewGuid():N}");
        var databasePath = Path.Combine(
            Path.GetTempPath(), $"signacore-login-antiforgery-{Guid.NewGuid():N}.db");
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

    private WebApplicationFactory<Program> CreateInstance()
    {
        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
                builder.UseSetting("Bootstrap:FilePath", _sharedBootstrapFilePath!));
        _factories.Add(factory);
        // Materialize the host so its startup validators have run.
        factory.CreateClient();
        return factory;
    }

    [Fact]
    public async Task AnAnonymousRender_SurvivesAManagementSessionPost_AndTheReverse()
    {
        using var instance = CreateInstance();
        using var client = instance.CreateClient();
        var managementCookieHeader = await LoginManagementAsync(instance);

        // Anonymous GET, management-session POST: the pair validates regardless of which session
        // state the browser happens to carry, because nothing binds it to a principal.
        var session = await BeginLoginAsync(instance.Services, client);
        using var postWithManagement = await client.SendAsync(CreateLoginPost(
            fields: CancelFields(session),
            cookieHeader: $"{managementCookieHeader}; {CookieHeaderFor(session)}"),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotImplemented, postWithManagement.StatusCode);

        // Management-session GET, anonymous POST.
        using var getRequest = new HttpRequestMessage(HttpMethod.Get, $"/oauth2/login?login_handle={session.Handle}");
        getRequest.Headers.TryAddWithoutValidation(
            "Cookie", $"{managementCookieHeader}; {CookieHeaderFor(session)}");
        using var getResponse = await client.SendAsync(getRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);
        var secondToken = ExtractToken(
            await getResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Null(GetSetCookieHeader(getResponse, CookieName));

        using var anonymousPost = await client.SendAsync(CreateLoginPost(
            fields: CancelFields(new LoginSession(session.Handle, session.CookieValue, secondToken)),
            cookieHeader: CookieHeaderFor(session)),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotImplemented, anonymousPost.StatusCode);
    }

    [Fact]
    public async Task AnIdentityCookieOnEitherSide_DoesNotDisturbTheAntiforgeryPair()
    {
        using var instance = CreateInstance();
        using var client = instance.CreateClient();
        var identityCookieHeader = await IssueIdentityCookieAsync(instance, Guid.NewGuid());

        var session = await BeginLoginAsync(instance.Services, client);
        using var postWithIdentity = await client.SendAsync(CreateLoginPost(
            fields: CancelFields(session),
            cookieHeader: $"{identityCookieHeader}; {CookieHeaderFor(session)}"),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotImplemented, postWithIdentity.StatusCode);

        using var getRequest = new HttpRequestMessage(HttpMethod.Get, $"/oauth2/login?login_handle={session.Handle}");
        getRequest.Headers.TryAddWithoutValidation("Cookie", identityCookieHeader);
        using var getResponse = await client.SendAsync(getRequest, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, getResponse.StatusCode);
    }

    [Fact]
    public async Task InstanceARenders_InstanceBValidates_OverTheSharedKeyRing()
    {
        using var first = CreateInstance();
        using var second = CreateInstance();

        using var firstClient = first.CreateClient();
        var session = await BeginLoginAsync(first.Services, firstClient);
        using var secondClient = second.CreateClient();
        using var post = await secondClient.SendAsync(CreateLoginPost(
            fields: CancelFields(session),
            cookieHeader: CookieHeaderFor(session)),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotImplemented, post.StatusCode);
    }

    [Fact]
    public async Task TheAntiforgeryCookie_SatisfiesNoSessionPolicy()
    {
        using var instance = CreateInstance();
        var session = await BeginLoginAsync(instance.Services, instance.CreateClient());
        var csrfCookieHeader = $"{CookieName}={session.CookieValue}";

        // End to end: the admin console rejects the antiforgery cookie.
        using var client = instance.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
        client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", csrfCookieHeader);
        using var response = await client.GetAsync(
            "/api/admin/session/me", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        // Scheme level: neither the management scheme (which both AdminSession and Ops ride) nor
        // the identity scheme authenticates the antiforgery cookie, so with an anonymous principal
        // all three policies reject.
        using var scope = instance.Services.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        context.Request.Headers.Cookie = csrfCookieHeader;

        var management = await context.AuthenticateAsync(ManagementSessionDefaults.AuthenticationScheme);
        Assert.False(management.Succeeded);
        var identity = await context.AuthenticateAsync(IdentitySessionDefaults.AuthenticationScheme);
        Assert.False(identity.Succeeded);

        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        foreach (var policyName in new[]
                 {
                     "AdminSession",
                     GatewayAppAuthenticationDefaults.OpsPolicy,
                     IdentitySessionDefaults.Policy,
                 })
        {
            var decision = await authorization.AuthorizeAsync(
                management.Principal ?? new System.Security.Claims.ClaimsPrincipal(
                    new System.Security.Claims.ClaimsIdentity()),
                policyName);
            Assert.False(decision.Succeeded);
        }
    }

    [Fact]
    public async Task SessionCookies_AreNotAntiforgeryCookies()
    {
        using var instance = CreateInstance();
        using var client = instance.CreateClient();
        var session = await BeginLoginAsync(instance.Services, client);
        var managementCookieHeader = await LoginManagementAsync(instance);
        var identityCookieHeader = await IssueIdentityCookieAsync(instance, Guid.NewGuid());
        var managementValue = managementCookieHeader[(ManagementCookieName.Length + 1)..];
        var identityValue = identityCookieHeader[(IdentitySessionDefaults.CookieName.Length + 1)..];

        // Each session cookie value presented under the antiforgery cookie name fails the pair
        // validation under the antiforgery purpose.
        foreach (var foreignValue in new[] { managementValue, identityValue })
        {
            using var response = await client.SendAsync(CreateLoginPost(
                fields: CancelFields(session),
                cookieHeader: $"{CookieName}={foreignValue}"),
                TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    private static string ExtractToken(string body)
    {
        var match = System.Text.RegularExpressions.Regex.Match(
            body, "name=\"__RequestVerificationToken\" value=\"([^\"]*)\"");
        Assert.True(match.Success);
        return match.Groups[1].Value;
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

    private static async Task<string> IssueIdentityCookieAsync(
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
        return setCookie.Split(';')[0];
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
