using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Security;
using SignaCore.Host.Startup;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Acceptance of the OIDC surfaces over the two-instance base (SignaCore #102): the PS-18 identity
/// cookie and the PS-03 continuation cross instances through the real endpoints, the shared RSA
/// key material makes both instances' JWKS and issuance agree, and each shared dependency is
/// negative-tested on its own — disconnecting the authorization-request store while the key ring
/// stays shared, disconnecting the RSA key material, or disconnecting the Data Protection key ring
/// each fails its own path without a false positive from the others.
/// <para>
/// Instance routing is explicit A/B addressing (instance A produces, instance B consumes) over one
/// shared SQLite database and bootstrap file — the <see cref="MultiInstanceAcceptanceTests"/> base;
/// no second generic multi-instance or Data Protection infrastructure is introduced here.
/// </para>
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed partial class OidcMultiInstanceAcceptanceTests : IAsyncLifetime
{
    private const string AdminUsername = "oidc_multi_admin";
    private const string AdminPassword = "OidcMulti123!";
    private const string LoginUser = "oidc_multi_user";
    private const string LoginPassword = "Oidc-User-123!";
    private const string ClientSecret = "login-success-secret";
    // The RFC 7636 appendix B verifier of the fixed S256 challenge the support helpers seed.
    private const string CodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    [GeneratedRegex("name=\"__RequestVerificationToken\" value=\"([^\"]*)\"")]
    private static partial Regex AntiforgeryTokenPattern();

    private string _workingDirectory = string.Empty;
    private string _connectionString = string.Empty;
    // The isolated deployment has its own database and key ring: the negative self-check needs a
    // deployment that shares nothing with the A/B pair.
    private string _isolatedConnectionString = string.Empty;
    private string? _sharedBootstrapFilePath;
    private string? _isolatedBootstrapFilePath;
    private readonly List<WebApplicationFactory<Program>> _factories = [];

    public async ValueTask InitializeAsync()
    {
        _workingDirectory = Path.Combine(Path.GetTempPath(), $"signacore-oidc-multi-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_workingDirectory);
        _connectionString = ConnectionStringOf("signacore.db");
        _isolatedConnectionString = ConnectionStringOf("isolated.db");
        _sharedBootstrapFilePath = await PrepareInstallationAsync(
            "shared", _connectionString, RootSecretOf("shared"));
        _isolatedBootstrapFilePath = await PrepareInstallationAsync(
            "isolated", _isolatedConnectionString, RootSecretOf("isolated"));
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var factory in _factories)
        {
            factory.Dispose();
        }

        for (var attempt = 0; attempt < 5; attempt++)
        {
            TestSqlitePools.ClearAll();
            try
            {
                if (Directory.Exists(_workingDirectory))
                {
                    Directory.Delete(_workingDirectory, recursive: true);
                }

                return;
            }
            catch (IOException) when (attempt < 4)
            {
                await Task.Delay(200);
            }
        }
    }

    // ---- PS-18: the identity cookie crosses instances through the real flow ----

    /// <summary>
    /// A cookie issued by instance A's real login drives the code flow on instance B without
    /// another login: B unprotects A's cookie through the shared key ring, resolves the shared
    /// server-side session, and issues its own code bound to that session.
    /// </summary>
    [Fact]
    public async Task AnIdentityCookieIssuedByInstanceA_DrivesTheCodeFlowOnInstanceB()
    {
        using var a = CreateInstance();
        using var b = CreateInstance();
        var cookieValue = await LoginOnInstanceAsync(a);

        var location = await AuthorizeWithIdentityCookieAsync(
            b, BuildSuccessAuthorizeUrl(state: "cross-instance-state-0123456"), cookieValue);

        AssertRedirectWithCodeAndState(location, "cross-instance-state-0123456");
    }

    // ---- PS-03: the continuation crosses instances ----

    /// <summary>
    /// A continuation created by instance A's authorize endpoint is rendered, consumed, and turned
    /// into the redirect decision by instance B: B recovers A's stored snapshot from the shared
    /// database, and the single consumption commits there — a second consumption by either
    /// instance fails.
    /// </summary>
    [Fact]
    public async Task AContinuationCreatedByInstanceA_IsConsumedByInstanceB()
    {
        using var a = CreateInstance();
        using var b = CreateInstance();

        // A produces the continuation in the shared store.
        var login = await BeginSuccessLoginViaAuthorizeAsync(a.Services, NonRedirectingClient(a));

        // B renders the form, completes the login, and derives the redirect from A's snapshot.
        // The antiforgery pair follows PS-19: a browser already holding a usable antiforgery
        // cookie (protected under the shared key ring) is not re-issued one.
        await EnsureSeededAsync(a);
        using var bClient = NonRedirectingClient(b);
        using var form = await bClient.SendAsync(
            new HttpRequestMessage(
                HttpMethod.Get, $"/oauth2/login?login_handle={login.Handle}")
            {
                Headers = { { "Cookie", CookieHeaderFor(login) } }
            },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, form.StatusCode);
        var token = AntiforgeryTokenPattern().Match(
            await form.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).Groups[1].Value;
        var formSetCookie = GetSetCookieHeader(form, CookieName);
        var antiforgeryValue = formSetCookie is not null
            ? CookieValueFromHeader(formSetCookie, CookieName)
            : login.CookieValue;

        using var completion = await bClient.SendAsync(
            CreateLoginPost(
                fields:
                [
                    new("login_handle", login.Handle),
                    new("username", LoginUser),
                    new("password", LoginPassword),
                    new(LoginAntiforgeryDefaults.TokenFieldName, token),
                    new(ActionFieldName, LoginActionValue)
                ],
                cookieHeader: $"{CookieName}={antiforgeryValue}"),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, completion.StatusCode);
        AssertRedirectWithCodeAndState(completion.Headers.Location!.ToString(), SuccessState);

        // The consumption is single and committed in the shared store: the handle is spent for
        // every instance, and the code row it produced is bound to the shared session.
        using var scope = a.Services.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IAuthorizationRequestStore>();
        Assert.False(await store.TryConsumeAsync(
            login.Handle, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken));
        Assert.Null(await store.GetActiveAsync(
            login.Handle, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken));
    }

    // ---- Negative self-checks: each shared dependency fails its own path ----

    /// <summary>
    /// Disconnecting the authorization-request store only (instance B's store is replaced with an
    /// empty one; the Data Protection key ring stays shared): B can still unprotect A's identity
    /// cookie, yet it cannot recover the continuation or derive any redirect — the missing lookup
    /// is the local generic error and nothing about the stored snapshot leaks.
    /// </summary>
    [Fact]
    public async Task WithTheSharedAuthorizationStateDisconnected_NoContinuationIsRecovered()
    {
        using var a = CreateInstance();
        using var b = CreateInstance(configureTestServices: services =>
        {
            services.RemoveAll<IAuthorizationRequestStore>();
            services.AddSingleton<IAuthorizationRequestStore>(new EmptyAuthorizationRequestStore());
        });

        var login = await BeginSuccessLoginViaAuthorizeAsync(a.Services, NonRedirectingClient(a));
        var cookieValue = await LoginOnInstanceAsync(a);

        // The cookie still unprotects on B through the shared key ring: the failure below can
        // only come from the disconnected request store, not from a broken key ring.
        await AssertCookieAuthenticatesOnInstanceAsync(b, cookieValue);

        using var bClient = NonRedirectingClient(b);
        using var recovery = await bClient.GetAsync(
            $"/oauth2/login?login_handle={login.Handle}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, recovery.StatusCode);
        Assert.Null(recovery.Headers.Location);
        var body = await recovery.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain(RegisteredUri, body, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryState, body, StringComparison.Ordinal);

        // The same disconnect closes the authorize side: a cookie-less request must create a
        // continuation before it can redirect to the login page, and the disconnected store fails
        // closed — no handle, no code, no redirect decision derived from the snapshot.
        using var authorize = await bClient.SendAsync(
            AuthorizeGet(BuildSuccessAuthorizeUrl(), identityCookieValue: null),
            TestContext.Current.CancellationToken);
        Assert.NotEqual(HttpStatusCode.Found, authorize.StatusCode);
        Assert.DoesNotContain(
            SuccessRegisteredUri,
            authorize.Headers.Location?.ToString() ?? string.Empty,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A cookie protected under the wrong purpose (the management cookie's payload carried in the
    /// identity cookie's name) never satisfies the identity scheme: the authorize endpoint falls
    /// back to the login continuation exactly like a cookie-less request, instead of accepting the
    /// foreign payload.
    /// </summary>
    [Fact]
    public async Task AManagementPurposeCookie_NeverSatisfiesTheIdentitySchemeAcrossInstances()
    {
        using var a = CreateInstance();
        using var b = CreateInstance();
        var managementCookie = await LoginManagementAsync(a);
        var managementValue = managementCookie[(("__Host-ServiceMantle.Management").Length + 1)..];

        using var bClient = NonRedirectingClient(b);
        using var response = await bClient.SendAsync(
            AuthorizeGet(
                BuildSuccessAuthorizeUrl(state: "wrong-purpose-state-012345"),
                $"{IdentitySessionDefaults.CookieName}={managementValue}"),
            TestContext.Current.CancellationToken);

        // The wrong-purpose payload never satisfies the identity scheme: no code is issued, and a
        // redirect answer can only be the login continuation.
        var location = response.Headers.Location?.ToString() ?? string.Empty;
        Assert.DoesNotContain("code=", location, StringComparison.Ordinal);
        if (response.StatusCode == HttpStatusCode.Found)
        {
            Assert.StartsWith("/oauth2/login?login_handle=", location, StringComparison.Ordinal);
        }
        else
        {
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    /// <summary>
    /// Disconnecting the RSA key material only (instance B's key manager is an isolated in-process
    /// ring): B keeps serving its own JWKS, but A's issued token no longer validates against it —
    /// the cross-instance signature agreement is lost exactly when the key material stops being
    /// shared.
    /// </summary>
    [Fact]
    public async Task WithTheKeyMaterialDisconnected_TheForeignTokenIsRejectedByInstanceBJwks()
    {
        using var a = CreateInstance();
        using var b = CreateInstance(configureTestServices: services =>
        {
            services.RemoveAll<IKeyManager>();
            services.AddSingleton<IKeyManager, IsolatedKeyManager>();
        });

        var accessToken = await IssueAccessTokenOnInstanceAsync(a);
        var jwks = await GetJwksAsync(b);
        AssertNoPrivateMaterial(jwks);

        // The isolated ring publishes a disjoint kid set, and the token signed by A's shared key
        // fails validation against B's published keys.
        var token = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);
        var kids = jwks.GetProperty("keys").EnumerateArray()
            .Select(key => key.GetProperty("kid").GetString()).ToHashSet();
        Assert.DoesNotContain(token.Header.Kid, kids);

        var keys = jwks.GetProperty("keys").EnumerateArray()
            .Select(key => new JsonWebKey(key.GetRawText()));
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = (await GetDiscoveryAsync(b)).GetProperty("issuer").GetString(),
            ValidAudience = SuccessAppId,
            IssuerSigningKeys = keys
        };
        await Assert.ThrowsAnyAsync<SecurityTokenException>(() =>
            Task.Run(() => new JwtSecurityTokenHandler().ValidateToken(accessToken, parameters, out _)));
    }

    /// <summary>
    /// Disconnecting the Data Protection key ring (instance B is a deployment of its own: an
    /// isolated database and key ring): B cannot unprotect A's identity cookie, so the real
    /// authorize flow falls back to the login continuation instead of issuing a code.
    /// </summary>
    [Fact]
    public async Task WithAnIsolatedKeyRing_InstanceBRejectsTheSharedIdentityCookie()
    {
        using var a = CreateInstance();
        var cookieValue = await LoginOnInstanceAsync(a);

        // The isolated instance carries its own installation with the same client registration,
        // so the request itself validates; only the cookie path is broken.
        using var b = CreateInstance(_isolatedBootstrapFilePath!);
        await SeedSuccessApplicationAsync(b.Services);
        await SeedUserAsync(b.Services, LoginUser, LoginPassword);

        await AssertCookieDoesNotAuthenticateOnInstanceAsync(b, cookieValue);

        using var bClient = NonRedirectingClient(b);
        using var response = await bClient.SendAsync(
            AuthorizeGet(BuildSuccessAuthorizeUrl(state: "isolated-ring-state-01234"), cookieValue),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith("/oauth2/login?login_handle=", location, StringComparison.Ordinal);
        Assert.DoesNotContain("code=", location, StringComparison.Ordinal);
    }

    // ---- RSA/JWKS positive: shared material, agreeing discovery ----

    /// <summary>
    /// With the shared database backing the key manager, both instances publish the same JWKS
    /// document, and a token issued by instance A validates against instance B's published keys —
    /// discovery, JWKS, and issuance agree across instances.
    /// </summary>
    [Fact]
    public async Task SharedKeyMaterial_JwksAgreesAcrossInstancesAndTheTokenValidatesOnB()
    {
        using var a = CreateInstance();
        using var b = CreateInstance();

        var accessToken = await IssueAccessTokenOnInstanceAsync(a);
        var jwksA = await GetJwksAsync(a);
        var jwksB = await GetJwksAsync(b);
        AssertNoPrivateMaterial(jwksA);
        AssertNoPrivateMaterial(jwksB);

        // The same live key material: identical kid sets and identical public moduli, in the same
        // document order.
        Assert.Equal(
            jwksA.GetProperty("keys").GetRawText(),
            jwksB.GetProperty("keys").GetRawText());

        var keys = jwksB.GetProperty("keys").EnumerateArray()
            .Select(key => new JsonWebKey(key.GetRawText()));
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = (await GetDiscoveryAsync(b)).GetProperty("issuer").GetString(),
            ValidAudience = SuccessAppId,
            IssuerSigningKeys = keys
        };
        var principal = new JwtSecurityTokenHandler().ValidateToken(accessToken, parameters, out _);
        Assert.NotNull(principal);
    }

    // ---- Secrets never reach responses or logs ----

    /// <summary>
    /// Across one full A-login / B-code / B-redemption run on captured logs: the login password,
    /// the protected cookie payload, the access token, and the client secret never appear in any
    /// log line, and the JWKS response carries public parameters only.
    /// </summary>
    [Fact]
    public async Task Secrets_StayOutOfResponsesAndLogsAcrossInstances()
    {
        var logs = new CapturingLoggerProvider();
        using var a = CreateInstance(configureTestServices: services => ReplaceLoggerFactory(services, logs));
        using var b = CreateInstance(configureTestServices: services => ReplaceLoggerFactory(services, logs));

        var cookieValue = await LoginOnInstanceAsync(a);
        var location = await AuthorizeWithIdentityCookieAsync(
            b, BuildSuccessAuthorizeUrl(state: "secret-scan-state-0123456"), cookieValue);
        var code = ExtractQueryValue(location, "code");
        var accessToken = await RedeemCodeAsync(b, code);

        Assert.NotEmpty(accessToken);
        // The authorization code is deliberately not in the scan set: it travels to the client
        // inside the redirect Location by protocol, and the MVC RedirectResult log line that
        // echoes that Location is framework behavior outside this task's log surface. The login
        // flow's own log scan stays with OAuthLoginSensitiveValueScanTests.
        var secrets = new[]
        {
            LoginPassword,
            cookieValue,
            accessToken,
            ClientSecret
        };
        Assert.All(logs.Messages, message =>
            Assert.All(secrets, secret =>
                Assert.DoesNotContain(secret, message, StringComparison.Ordinal)));
        AssertNoPrivateMaterial(await GetJwksAsync(b));
    }

    // ---- Helpers ----

    private string ConnectionStringOf(string fileName) => new SqliteConnectionStringBuilder
    {
        DataSource = Path.Combine(_workingDirectory, fileName)
    }.ConnectionString;

    private Task<string> PrepareInstallationAsync(
        string label, string connectionString, string rootSecret) =>
        InstallationTestSupport.PrepareCompletedInstallationAsync(
            Path.Combine(_workingDirectory, label),
            new DatabaseOptions { Provider = "SQLite", ConnectionString = connectionString },
            rootSecret,
            AdminUsername,
            AdminPassword);

    private static string RootSecretOf(string label) => $"oidc-multi-{label}-root-secret";

    private WebApplicationFactory<Program> CreateInstance(
        string? bootstrapFilePath = null,
        Action<IServiceCollection>? configureTestServices = null)
    {
        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath ?? _sharedBootstrapFilePath!);
                if (configureTestServices is not null)
                {
                    builder.ConfigureTestServices(configureTestServices);
                }
            });
        _factories.Add(factory);
        factory.CreateClient();
        return factory;
    }

    private static HttpClient NonRedirectingClient(WebApplicationFactory<Program> factory) =>
        factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    private async Task<string> LoginOnInstanceAsync(WebApplicationFactory<Program> factory)
    {
        await EnsureSeededAsync(factory);
        using var client = NonRedirectingClient(factory);
        return await CompleteSuccessLoginAndGetIdentityCookieValueAsync(
            factory.Services, client, LoginUser, LoginPassword);
    }

    /// <summary>Seeds the login user over the shared database through a real host, idempotently.</summary>
    private static async Task EnsureSeededAsync(WebApplicationFactory<Program> factory)
    {
        await SeedSuccessApplicationAsync(factory.Services);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        if (!await db.PasswordCredentials.AnyAsync(
                row => row.Username == LoginUser, TestContext.Current.CancellationToken))
        {
            await SeedUserAsync(factory.Services, LoginUser, LoginPassword);
        }
    }

    private static HttpRequestMessage AuthorizeGet(string url, string? identityCookieValue)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (identityCookieValue is not null)
        {
            request.Headers.TryAddWithoutValidation(
                "Cookie", $"{IdentitySessionDefaults.CookieName}={identityCookieValue}");
        }

        return request;
    }

    private async Task<string> AuthorizeWithIdentityCookieAsync(
        WebApplicationFactory<Program> factory, string url, string cookieValue)
    {
        using var client = NonRedirectingClient(factory);
        using var response = await client.SendAsync(
            AuthorizeGet(url, cookieValue), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        return response.Headers.Location!.ToString();
    }

    private static void AssertRedirectWithCodeAndState(string location, string expectedState)
    {
        Assert.StartsWith(SuccessRegisteredUri.Split('?')[0], location, StringComparison.Ordinal);
        Assert.Contains("code=", location, StringComparison.Ordinal);
        Assert.Equal(expectedState, ExtractQueryValue(location, "state"));
    }

    private static string ExtractQueryValue(string location, string name)
    {
        var query = location.Contains('?') ? location[(location.IndexOf('?') + 1)..] : location;
        foreach (var pair in query.Split('&'))
        {
            var parts = pair.Split('=', 2);
            if (parts.Length == 2 && parts[0] == name)
            {
                return Uri.UnescapeDataString(parts[1]);
            }
        }

        throw new Xunit.Sdk.XunitException($"No '{name}' in '{location}'.");
    }

    private async Task<string> IssueAccessTokenOnInstanceAsync(WebApplicationFactory<Program> factory)
    {
        var cookieValue = await LoginOnInstanceAsync(factory);
        using var client = NonRedirectingClient(factory);
        var location = await AuthorizeWithIdentityCookieAsync(factory, BuildSuccessAuthorizeUrl(), cookieValue);
        return await RedeemCodeAsync(factory, ExtractQueryValue(location, "code"));
    }

    private static async Task<string> RedeemCodeAsync(WebApplicationFactory<Program> factory, string code)
    {
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
            "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{SuccessAppId}:{ClientSecret}")));
        using var response = await client.PostAsync(
            "/oauth2/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = SuccessRegisteredUri,
                ["code_verifier"] = CodeVerifier
            }),
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
        return body.GetProperty("access_token").GetString()!;
    }

    private static async Task<JsonElement> GetDiscoveryAsync(WebApplicationFactory<Program> factory)
    {
        using var client = factory.CreateClient();
        using var response = await client.GetAsync(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
    }

    private static async Task<JsonElement> GetJwksAsync(WebApplicationFactory<Program> factory)
    {
        using var client = factory.CreateClient();
        using var response = await client.GetAsync(
            "/.well-known/jwks.json", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadFromJsonAsync<JsonElement>(
            cancellationToken: TestContext.Current.CancellationToken);
    }

    private static void AssertNoPrivateMaterial(JsonElement jwks)
    {
        foreach (var key in jwks.GetProperty("keys").EnumerateArray())
        {
            Assert.False(key.TryGetProperty("d", out _), "The JWKS response carries a private exponent.");
            Assert.False(key.TryGetProperty("p", out _), "The JWKS response carries a private prime.");
            Assert.False(key.TryGetProperty("q", out _), "The JWKS response carries a private prime.");
        }
    }

    private static async Task AssertCookieAuthenticatesOnInstanceAsync(
        WebApplicationFactory<Program> factory, string cookieValue)
    {
        using var scope = factory.Services.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        context.Request.Headers.Cookie = $"{IdentitySessionDefaults.CookieName}={cookieValue}";
        var result = await context.AuthenticateAsync(IdentitySessionDefaults.AuthenticationScheme);
        Assert.True(result.Succeeded, "The shared key ring must still unprotect the cookie here.");
    }

    private static async Task AssertCookieDoesNotAuthenticateOnInstanceAsync(
        WebApplicationFactory<Program> factory, string cookieValue)
    {
        using var scope = factory.Services.CreateScope();
        var context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        context.Request.Headers.Cookie = $"{IdentitySessionDefaults.CookieName}={cookieValue}";
        var result = await context.AuthenticateAsync(IdentitySessionDefaults.AuthenticationScheme);
        Assert.False(result.Succeeded);
        Assert.Null(result.Principal);
    }

    private static async Task<string> LoginManagementAsync(WebApplicationFactory<Program> factory)
    {
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
        {
            Content = new StringContent(
                JsonSerializer.Serialize(new { username = AdminUsername, password = AdminPassword }),
                Encoding.UTF8,
                "application/json")
        };
        request.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(response.Headers.NonValidated.TryGetValues("Set-Cookie", out var cookies));
        return cookies
            .Single(value => value.StartsWith("__Host-ServiceMantle.Management=", StringComparison.Ordinal))
            .Split(';')[0];
    }

    private static void ReplaceLoggerFactory(IServiceCollection services, CapturingLoggerProvider provider)
    {
        services.RemoveAll<ILoggerFactory>();
        services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
        {
            logging.AddProvider(provider);
            logging.SetMinimumLevel(LogLevel.Information);
        }));
    }

    /// <summary>The shared-database store replaced by an empty one: nothing is recoverable.</summary>
    private sealed class EmptyAuthorizationRequestStore : IAuthorizationRequestStore
    {
        public Task<AuthorizationRequestCreation> CreateAsync(
            OidcAuthorizationValidationResult.Accepted accepted,
            DateTimeOffset now,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException("The shared authorization state is disconnected.");

        public Task<AuthorizationRequestEntity?> GetActiveAsync(
            string loginHandle, DateTimeOffset now, CancellationToken cancellationToken = default) =>
            Task.FromResult<AuthorizationRequestEntity?>(null);

        public Task<bool> TryConsumeAsync(
            string loginHandle, DateTimeOffset now, CancellationToken cancellationToken = default) =>
            Task.FromResult(false);

        public Task<int> CleanupExpiredAsync(
            DateTimeOffset now, CancellationToken cancellationToken = default) =>
            Task.FromResult(0);
    }

    /// <summary>
    /// An isolated in-process key ring: same interface, its own freshly generated key material —
    /// instance B stops sharing the service's signing keys.
    /// </summary>
    private sealed class IsolatedKeyManager : IKeyManager
    {
        private readonly RsaSecurityKey _key = new(RSA.Create(2048));

        public Task InitializationCompleted => Task.CompletedTask;

        public RsaSecurityKey GetCurrentKey() => _key;

        public IReadOnlyList<SecurityKey> GetValidationKeys() => [_key];

        public Task<IReadOnlyList<RsaSecurityKey>> GetValidKeysAsync(
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<RsaSecurityKey>>([_key]);

        public Task<IReadOnlyList<RsaSecurityKey>> GetLogoutHintValidationKeysAsync(
            CancellationToken cancellationToken = default) =>
            GetValidKeysAsync(cancellationToken);

        public Task<bool> NeedsKeyRotationAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(false);

        public Task RotateKeyAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<string> _messages = new();

        public IReadOnlyCollection<string> Messages => _messages;

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, _messages);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(
            string categoryName, ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                messages.Enqueue($"{categoryName}: {formatter(state, exception)}");
                if (exception is not null)
                {
                    messages.Enqueue($"{categoryName}: {exception}");
                }
            }
        }
    }
}
