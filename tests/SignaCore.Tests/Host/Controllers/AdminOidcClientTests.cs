using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Host;
using SignaCore.Host.Controllers;
using SignaCore.Host.Models;
using SignaCore.Host.Provisioning;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

/// <summary>
/// Interactive OIDC client management through the administration API, and its agreement with the
/// <c>bootstrap-apps.json</c> pre-seed.
/// <para>
/// These tests use a real repository and unit of work rather than mocks, because the properties
/// under test are about what ends up in the database: that a rejected request writes nothing, and
/// that the two entry points cannot diverge.
/// </para>
/// </summary>
public class AdminOidcClientTests : IDisposable
{
    private const string AppId = "oidc-admin-test-app";
    private const string CallbackUrl = "https://claims.example.test/permissions";

    private static readonly Guid AdminId = Guid.NewGuid();

    private readonly IdentityDbContext _dbContext;
    private readonly AdminController _controller;
    private readonly IAppRegistrationRepository _repository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly Mock<IAuditService> _auditServiceMock = new();
    private readonly IPasswordHasher _passwordHasher = new BCryptPasswordHasher(
        new PasswordHasherOptions { WorkFactor = 4 });
    private readonly IWebHostEnvironment _environment = ProductionEnvironment();

    private static readonly JwtOptions TestJwtOptions = new()
    {
        Issuer = "TestIssuer",
        Audience = "TestAudience",
        TokenExpirationHours = 2
    };

    public AdminOidcClientTests()
    {
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _dbContext = new IdentityDbContext(options);
        _repository = new AppRegistrationRepository(_dbContext);
        _unitOfWork = new EfCoreUnitOfWork(_dbContext);

        _controller = new AdminController(NullLogger<AdminController>.Instance)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(new ClaimsIdentity(
                        [
                            new Claim(ClaimTypes.NameIdentifier, AdminId.ToString()),
                            new Claim(ClaimTypes.Name, "admin")
                        ],
                        "Cookies"))
                }
            }
        };
    }

    // ---- Reading ----

    /// <summary>
    /// An application registered before interactive configuration existed reports the fail-closed
    /// defaults, and every field it already had is unchanged.
    /// </summary>
    [Fact]
    public async Task GetApps_ForAnApplicationThatPredatesInteractiveConfiguration_ReportsSafeDefaults()
    {
        await SeedAsync();

        var result = await _controller.GetApps(
            _dbContext,
            TestJwtOptions,
            TestContext.Current.CancellationToken);

        var item = Assert.Single(Assert.IsAssignableFrom<IReadOnlyList<AdminAppListItemResponse>>(
            Assert.IsType<OkObjectResult>(result).Value));
        Assert.Equal(AppId, item.AppId);
        Assert.Equal(CallbackUrl, item.CallbackUrl);
        Assert.True(item.IsActive);
        Assert.Equal(nameof(OidcClientType.Confidential), item.ClientType);
        Assert.False(item.AllowAuthorizationCode);
        Assert.Equal(["openid"], item.AllowedScopes);
        Assert.False(item.AllowRefreshToken);
        Assert.Null(item.IdentitySessionMaxAgeSeconds);
        Assert.Empty(item.RedirectUris);
        Assert.Empty(item.PostLogoutRedirectUris);
    }

    /// <summary>
    /// The claims callback and the browser redirect registrations are separate fields with separate
    /// values, and configuring one never touches the other.
    /// </summary>
    [Fact]
    public async Task CallbackUrlAndRedirectUris_AreIsolatedFromEachOther()
    {
        await SeedAsync();
        await EnableCodeFlowAsync("https://bff.example.test/callback");

        var app = await LoadAsync();
        Assert.Equal(CallbackUrl, app.CallbackUrl);
        Assert.Equal(
            "https://bff.example.test/callback",
            app.RedirectUris.Single(uri => uri.Kind == RedirectUriKind.Redirect).CanonicalUri);
        Assert.DoesNotContain(app.RedirectUris, uri => uri.CanonicalUri == CallbackUrl);

        var result = await _controller.GetApps(
            _dbContext,
            TestJwtOptions,
            TestContext.Current.CancellationToken);
        var item = Assert.Single(Assert.IsAssignableFrom<IReadOnlyList<AdminAppListItemResponse>>(
            Assert.IsType<OkObjectResult>(result).Value));
        Assert.Equal(CallbackUrl, item.CallbackUrl);
        Assert.Equal(["https://bff.example.test/callback"], item.RedirectUris);
    }

    [Fact]
    public async Task GetOidcConfiguration_ForAnUnknownApplication_ReturnsNotFound()
    {
        var result = await _controller.GetOidcConfiguration(
            "missing",
            _repository,
            TestContext.Current.CancellationToken);

        Assert.IsType<NotFoundObjectResult>(result);
    }

    /// <summary>No administration response may carry the stored secret hash or a plaintext secret.</summary>
    [Fact]
    public async Task NoOidcResponse_ExposesTheSecretHash()
    {
        await SeedAsync();
        await EnableCodeFlowAsync("https://bff.example.test/callback");
        var app = await LoadAsync();

        var listResult = await _controller.GetApps(
            _dbContext,
            TestJwtOptions,
            TestContext.Current.CancellationToken);
        var oidcResult = await _controller.GetOidcConfiguration(
            AppId,
            _repository,
            TestContext.Current.CancellationToken);

        foreach (var payload in new[]
                 {
                     Serialize(Assert.IsType<OkObjectResult>(listResult).Value),
                     Serialize(Assert.IsType<OkObjectResult>(oidcResult).Value)
                 })
        {
            Assert.DoesNotContain("AppSecretHash", payload, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(app.AppSecretHash, payload, StringComparison.Ordinal);
        }
    }

    // ---- Policy updates ----

    [Fact]
    public async Task UpdateOidcPolicy_WithAnAcceptableConfiguration_CommitsAndAudits()
    {
        await SeedAsync();
        await AddUrisAsync(RedirectUriKind.Redirect, "https://bff.example.test/callback");

        var result = await UpdatePolicyAsync(new AdminUpdateOidcPolicyRequest(
            "Confidential",
            AllowAuthorizationCode: true,
            ["openid", "profile", "offline_access"],
            AllowRefreshToken: true,
            IdentitySessionMaxAgeSeconds: 7200));

        var response = Assert.IsType<AdminAppOidcResponse>(Assert.IsType<OkObjectResult>(result).Value);
        Assert.True(response.AllowAuthorizationCode);
        Assert.Equal(["openid", "profile", "offline_access"], response.AllowedScopes);
        Assert.Equal(7200, response.IdentitySessionMaxAgeSeconds);

        var app = await LoadAsync();
        Assert.Equal("openid profile offline_access", app.AllowedScopes);

        _auditServiceMock.Verify(
            audit => audit.RecordActionAsync(
                "app_oidc_policy_updated", "AppRegistration", AppId, AdminId, "admin",
                It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
                It.IsAny<object?>(), It.IsAny<object?>(), TestContext.Current.CancellationToken),
            Times.Once);
    }

    /// <summary>
    /// Four fields change and one of them is unacceptable, so none of the four is committed. This is
    /// asserted against the database rather than against the response.
    /// </summary>
    [Fact]
    public async Task UpdateOidcPolicy_WhenRejected_LeavesEveryFieldUnchanged()
    {
        await SeedAsync();
        await AddUrisAsync(RedirectUriKind.Redirect, "https://bff.example.test/callback");
        await UpdatePolicyAsync(new AdminUpdateOidcPolicyRequest(
            "Confidential", true, ["openid"], false, 600));
        _dbContext.ChangeTracker.Clear();

        var result = await UpdatePolicyAsync(new AdminUpdateOidcPolicyRequest(
            "Public",
            AllowAuthorizationCode: true,
            ["openid", "profile"],
            AllowRefreshToken: true,
            IdentitySessionMaxAgeSeconds: 1200));

        Assert.IsType<BadRequestObjectResult>(result);
        _dbContext.ChangeTracker.Clear();
        var app = await LoadAsync();
        Assert.Equal(OidcClientType.Confidential, app.ClientType);
        Assert.Equal("openid", app.AllowedScopes);
        Assert.False(app.AllowRefreshToken);
        Assert.Equal(600, app.IdentitySessionMaxAgeSeconds);
    }

    [Fact]
    public async Task UpdateOidcPolicy_EnablingCodeFlowWithoutARedirectUri_IsRejected()
    {
        await SeedAsync();

        var result = await UpdatePolicyAsync(new AdminUpdateOidcPolicyRequest(
            "Confidential", true, ["openid"], false, null));

        Assert.IsType<BadRequestObjectResult>(result);
        Assert.False((await LoadAsync()).AllowAuthorizationCode);
    }

    /// <summary>
    /// The audience mode has its own endpoint, so enabling the code flow on a shared-audience
    /// application is refused rather than silently switching that application's audience.
    /// </summary>
    [Fact]
    public async Task UpdateOidcPolicy_EnablingCodeFlowOnASharedAudienceApplication_IsRejected()
    {
        await SeedAsync(AudienceMode.Shared);
        await AddUrisAsync(RedirectUriKind.Redirect, "https://bff.example.test/callback", expectSuccess: false);

        var result = await UpdatePolicyAsync(new AdminUpdateOidcPolicyRequest(
            "Confidential", true, ["openid"], false, null));

        Assert.IsType<BadRequestObjectResult>(result);
        var app = await LoadAsync();
        Assert.Equal(AudienceMode.Shared, app.AudienceMode);
        Assert.False(app.AllowAuthorizationCode);
    }

    // ---- URI registrations ----

    /// <summary>
    /// Three URIs are submitted and the second is unacceptable, so none of the three is registered.
    /// </summary>
    [Fact]
    public async Task AddOidcRedirectUris_WithOneUnacceptableValue_RegistersNone()
    {
        await SeedAsync();

        var result = await _controller.AddOidcRedirectUris(
            AppId,
            new AdminAddRedirectUrisRequest(nameof(RedirectUriKind.Redirect),
            [
                "https://bff.example.test/first",
                "http://insecure.example.test/second",
                "https://bff.example.test/third"
            ]),
            _repository,
            _unitOfWork,
            _auditServiceMock.Object,
            _environment,
            TestContext.Current.CancellationToken);

        Assert.IsType<BadRequestObjectResult>(result);
        _dbContext.ChangeTracker.Clear();
        Assert.Empty(await _dbContext.AppRedirectUris.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AddOidcRedirectUris_WithAnUnknownKind_IsRejected()
    {
        await SeedAsync();

        var result = await _controller.AddOidcRedirectUris(
            AppId,
            new AdminAddRedirectUrisRequest("Backchannel", ["https://bff.example.test/cb"]),
            _repository,
            _unitOfWork,
            _auditServiceMock.Object,
            _environment,
            TestContext.Current.CancellationToken);

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task AddOidcRedirectUris_KeepsTheTwoKindsApart()
    {
        await SeedAsync();

        await AddUrisAsync(RedirectUriKind.Redirect, "https://bff.example.test/callback");
        await AddUrisAsync(RedirectUriKind.PostLogout, "https://bff.example.test/signed-out");

        var result = await _controller.GetOidcConfiguration(
            AppId,
            _repository,
            TestContext.Current.CancellationToken);
        var response = Assert.IsType<AdminAppOidcResponse>(Assert.IsType<OkObjectResult>(result).Value);
        Assert.Equal("https://bff.example.test/callback", Assert.Single(response.RedirectUris).Uri);
        Assert.Equal("https://bff.example.test/signed-out", Assert.Single(response.PostLogoutRedirectUris).Uri);
    }

    [Fact]
    public async Task RemoveOidcRedirectUri_RemovesOnlyThatRegistration()
    {
        await SeedAsync();
        await AddUrisAsync(RedirectUriKind.Redirect, "https://bff.example.test/a", "https://bff.example.test/b");
        var target = (await LoadAsync()).RedirectUris
            .Single(uri => uri.CanonicalUri == "https://bff.example.test/b");

        var result = await RemoveUriAsync(target.Id);

        Assert.IsType<OkObjectResult>(result);
        _dbContext.ChangeTracker.Clear();
        var remaining = await _dbContext.AppRedirectUris.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken);
        Assert.Equal("https://bff.example.test/a", Assert.Single(remaining).CanonicalUri);
    }

    /// <summary>
    /// An interactive client with no destination is not a configuration the authorization endpoint
    /// could act on, so removing the last redirect URI while the code flow is on is refused.
    /// </summary>
    [Fact]
    public async Task RemoveOidcRedirectUri_RemovingTheLastOneWhileCodeFlowIsEnabled_IsRejected()
    {
        await SeedAsync();
        await EnableCodeFlowAsync("https://bff.example.test/callback");
        var target = (await LoadAsync()).RedirectUris.Single();

        var result = await RemoveUriAsync(target.Id);

        Assert.IsType<BadRequestObjectResult>(result);
        _dbContext.ChangeTracker.Clear();
        Assert.Single(await _dbContext.AppRedirectUris.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RemoveOidcRedirectUri_ForAnUnknownRegistration_ReturnsNotFound()
    {
        await SeedAsync();

        Assert.IsType<NotFoundObjectResult>(await RemoveUriAsync(Guid.NewGuid()));
    }

    /// <summary>
    /// Failure paths are driven with recognisable values, then everything the request produced —
    /// the error body and both audit snapshots — is scanned. An untrusted URI never comes back, and
    /// the stored secret hash never appears.
    /// </summary>
    [Fact]
    public async Task RecognisableSensitiveValues_ReachNeitherAnErrorBodyNorAnAuditRecord()
    {
        const string canaryUri = "https://attacker.example.test/cb?api_key=CANARY-SECRET-VALUE";
        var snapshots = new List<string>();
        _auditServiceMock
            .Setup(audit => audit.RecordActionAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Guid?>(),
                It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
                It.IsAny<object?>(), It.IsAny<object?>(), It.IsAny<CancellationToken>()))
            .Callback<string, string, string, Guid?, string?, string?, string?, string?, object?, object?, CancellationToken>(
                (action, targetType, targetId, _, actorName, description, _, _, before, after, _) =>
                    snapshots.Add(string.Join(
                        "|",
                        action, targetType, targetId, actorName, description,
                        Serialize(before), Serialize(after))))
            .Returns(Task.CompletedTask);

        await SeedAsync();
        var app = await LoadAsync();

        var rejected = await _controller.AddOidcRedirectUris(
            AppId,
            new AdminAddRedirectUrisRequest(nameof(RedirectUriKind.Redirect), ["http://" + canaryUri[8..]]),
            _repository,
            _unitOfWork,
            _auditServiceMock.Object,
            _environment,
            TestContext.Current.CancellationToken);

        var body = Serialize(Assert.IsType<BadRequestObjectResult>(rejected).Value);
        Assert.DoesNotContain("CANARY-SECRET-VALUE", body, StringComparison.Ordinal);
        Assert.DoesNotContain("attacker.example.test", body, StringComparison.Ordinal);

        await AddUrisAsync(RedirectUriKind.Redirect, "https://bff.example.test/callback");
        Assert.NotEmpty(snapshots);
        foreach (var snapshot in snapshots)
        {
            Assert.DoesNotContain("CANARY-SECRET-VALUE", snapshot, StringComparison.Ordinal);
            Assert.DoesNotContain(app.AppSecretHash, snapshot, StringComparison.Ordinal);
            Assert.DoesNotContain("AppSecretHash", snapshot, StringComparison.OrdinalIgnoreCase);
        }
    }

    // ---- Agreement with the bootstrap pre-seed ----

    /// <summary>
    /// The same acceptable configuration is applied through both entry points and the two rows are
    /// compared field by field, including canonical scope order and canonical URI strings.
    /// </summary>
    [Fact]
    public async Task TheSameConfiguration_LandsIdenticallyThroughBothPaths()
    {
        await SeedAsync();
        await AddUrisAsync(RedirectUriKind.Redirect, "HTTPS://BFF.Example.Test:443/Callback");
        await AddUrisAsync(RedirectUriKind.PostLogout, "https://bff.example.test");
        await UpdatePolicyAsync(new AdminUpdateOidcPolicyRequest(
            "Confidential", true, ["offline_access", "openid", "profile"], true, 3600));
        _dbContext.ChangeTracker.Clear();
        var throughApi = await LoadAsync();

        await SeedBootstrapAsync($$"""
            {
              "Apps": [
                {
                  "AppId": "bootstrap-parity-app",
                  "AppSecret": "bootstrap-parity-secret",
                  "AppName": "Bootstrap Parity App",
                  "CallbackUrl": "{{CallbackUrl}}",
                  "Oidc": {
                    "ClientType": "Confidential",
                    "AllowAuthorizationCode": true,
                    "AllowedScopes": ["offline_access", "openid", "profile"],
                    "AllowRefreshToken": true,
                    "IdentitySessionMaxAgeSeconds": 3600,
                    "AudienceMode": "PerApplication",
                    "RedirectUris": ["HTTPS://BFF.Example.Test:443/Callback"],
                    "PostLogoutRedirectUris": ["https://bff.example.test"]
                  }
                }
              ]
            }
            """);
        var throughBootstrap = await LoadAsync("bootstrap-parity-app");

        Assert.Equal(throughApi.ClientType, throughBootstrap.ClientType);
        Assert.Equal(throughApi.AllowAuthorizationCode, throughBootstrap.AllowAuthorizationCode);
        Assert.Equal(throughApi.AllowedScopes, throughBootstrap.AllowedScopes);
        Assert.Equal(throughApi.AllowRefreshToken, throughBootstrap.AllowRefreshToken);
        Assert.Equal(throughApi.IdentitySessionMaxAgeSeconds, throughBootstrap.IdentitySessionMaxAgeSeconds);
        Assert.Equal(throughApi.AudienceMode, throughBootstrap.AudienceMode);
        Assert.Equal(
            Registrations(throughApi),
            Registrations(throughBootstrap));
        Assert.Equal("openid profile offline_access", throughBootstrap.AllowedScopes);
    }

    /// <summary>
    /// Every configuration the administration API refuses is also refused by the pre-seed, and the
    /// pre-seed refuses it by registering nothing at all rather than by registering a narrowed
    /// version of it.
    /// </summary>
    [Theory]
    [InlineData("""{"AllowedScopes": ["profile"]}""")]
    [InlineData("""{"AllowedScopes": ["openid", "email"]}""")]
    [InlineData("""{"AllowedScopes": ["openid", "openid"]}""")]
    [InlineData("""{"AllowedScopes": ["openid", "offline_access"], "AllowRefreshToken": false}""")]
    [InlineData("""{"ClientType": "Public", "AllowAuthorizationCode": true, "AudienceMode": "PerApplication", "RedirectUris": ["https://bff.example.test/cb"]}""")]
    [InlineData("""{"AllowAuthorizationCode": true, "AudienceMode": "Shared", "RedirectUris": ["https://bff.example.test/cb"]}""")]
    [InlineData("""{"AllowAuthorizationCode": true, "AudienceMode": "PerApplication"}""")]
    [InlineData("""{"IdentitySessionMaxAgeSeconds": 0}""")]
    [InlineData("""{"IdentitySessionMaxAgeSeconds": -1}""")]
    [InlineData("""{"IdentitySessionMaxAgeSeconds": 43201}""")]
    public async Task ARejectedConfiguration_IsRejectedByTheBootstrapPathToo(string oidcSection)
    {
        await SeedBootstrapAsync($$"""
            {
              "Apps": [
                {
                  "AppId": "bootstrap-rejected-app",
                  "AppSecret": "bootstrap-rejected-secret",
                  "AppName": "Bootstrap Rejected App",
                  "Oidc": {{oidcSection}}
                }
              ]
            }
            """);

        Assert.Empty(await _dbContext.AppRegistrations
            .AsNoTracking()
            .Where(app => app.AppId == "bootstrap-rejected-app")
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A file written before the interactive section existed pre-seeds exactly what it always did:
    /// the application appears, its OIDC configuration is fail closed, and its claims callback is
    /// not turned into a browser redirect registration.
    /// </summary>
    [Fact]
    public async Task ABootstrapFileWithoutTheInteractiveSection_KeepsItsPreviousBehaviour()
    {
        await SeedBootstrapAsync($$"""
            {
              "Apps": [
                {
                  "AppId": "bootstrap-legacy-app",
                  "AppSecret": "bootstrap-legacy-secret",
                  "AppName": "Bootstrap Legacy App",
                  "CallbackUrl": "{{CallbackUrl}}"
                }
              ]
            }
            """);

        var app = await LoadAsync("bootstrap-legacy-app");
        Assert.Equal("Bootstrap Legacy App", app.AppName);
        Assert.Equal(CallbackUrl, app.CallbackUrl);
        Assert.True(app.IsActive);
        Assert.Equal(OidcClientType.Confidential, app.ClientType);
        Assert.False(app.AllowAuthorizationCode);
        Assert.Equal("openid", app.AllowedScopes);
        Assert.False(app.AllowRefreshToken);
        Assert.Null(app.IdentitySessionMaxAgeSeconds);
        Assert.Equal(AudienceMode.Shared, app.AudienceMode);
        Assert.Empty(app.RedirectUris);
    }

    [Fact]
    public async Task ABootstrapEntryForAnExistingApplication_IsStillSkipped()
    {
        await SeedAsync();
        await EnableCodeFlowAsync("https://bff.example.test/callback");
        _dbContext.ChangeTracker.Clear();

        await SeedBootstrapAsync($$"""
            {
              "Apps": [
                {
                  "AppId": "{{AppId}}",
                  "AppSecret": "replacement-secret",
                  "AppName": "Replacement Name",
                  "Oidc": { "AllowedScopes": ["openid"] }
                }
              ]
            }
            """);

        var app = await LoadAsync();
        Assert.Equal("OIDC Admin Test App", app.AppName);
        Assert.True(app.AllowAuthorizationCode);
        Assert.Single(app.RedirectUris);
    }

    [Fact]
    public async Task AMissingBootstrapFile_IsNotAnError()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["BootstrapApps:FilePath"] = Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.json")
            })
            .Build();

        await BootstrapAppSeeder.SeedBootstrapAppsAsync(
            configuration,
            _dbContext,
            _auditServiceMock.Object,
            _passwordHasher,
            NullLogger.Instance,
            isDevelopment: false);

        Assert.Empty(await _dbContext.AppRegistrations.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken));
    }

    public void Dispose()
    {
        _dbContext.Dispose();
        GC.SuppressFinalize(this);
    }

    private static IReadOnlyList<string> Registrations(AppRegistrationEntity app) =>
        app.RedirectUris
            .Select(uri => $"{uri.Kind}:{uri.CanonicalUri}")
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToList();

    private static string Serialize(object? value) => JsonSerializer.Serialize(value);

    private Task<IActionResult> UpdatePolicyAsync(AdminUpdateOidcPolicyRequest request) =>
        _controller.UpdateOidcPolicy(
            AppId,
            request,
            _repository,
            _unitOfWork,
            _auditServiceMock.Object,
            _environment,
            TestContext.Current.CancellationToken);

    private Task<IActionResult> RemoveUriAsync(Guid registrationId) =>
        _controller.RemoveOidcRedirectUri(
            AppId,
            registrationId,
            _repository,
            _unitOfWork,
            _auditServiceMock.Object,
            _environment,
            TestContext.Current.CancellationToken);

    private async Task AddUrisAsync(RedirectUriKind kind, params string[] uris)
    {
        await AddUrisAsync(kind, expectSuccess: true, uris);
    }

    private async Task AddUrisAsync(RedirectUriKind kind, string uri, bool expectSuccess)
    {
        await AddUrisAsync(kind, expectSuccess, uri);
    }

    private async Task AddUrisAsync(RedirectUriKind kind, bool expectSuccess, params string[] uris)
    {
        var result = await _controller.AddOidcRedirectUris(
            AppId,
            new AdminAddRedirectUrisRequest(kind.ToString(), uris),
            _repository,
            _unitOfWork,
            _auditServiceMock.Object,
            _environment,
            TestContext.Current.CancellationToken);

        if (expectSuccess)
        {
            Assert.IsType<OkObjectResult>(result);
        }
    }

    private async Task EnableCodeFlowAsync(string redirectUri)
    {
        await AddUrisAsync(RedirectUriKind.Redirect, redirectUri);
        Assert.IsType<OkObjectResult>(await UpdatePolicyAsync(new AdminUpdateOidcPolicyRequest(
            "Confidential", true, ["openid", "profile"], false, null)));
    }

    private Task<AppRegistrationEntity> LoadAsync(string appId = AppId) =>
        _dbContext.AppRegistrations
            .Include(app => app.RedirectUris)
            .FirstAsync(app => app.AppId == appId, TestContext.Current.CancellationToken);

    private async Task SeedAsync(AudienceMode audienceMode = AudienceMode.PerApplication)
    {
        _dbContext.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = AppId,
            AppSecretHash = "hashed-secret-value",
            AppName = "OIDC Admin Test App",
            CallbackUrl = CallbackUrl,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = audienceMode
        });
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        _dbContext.ChangeTracker.Clear();
    }

    private async Task SeedBootstrapAsync(string json)
    {
        var path = Path.Combine(Path.GetTempPath(), $"bootstrap-apps-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path, json, TestContext.Current.CancellationToken);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["BootstrapApps:FilePath"] = path
                })
                .Build();

            await BootstrapAppSeeder.SeedBootstrapAppsAsync(
                configuration,
                _dbContext,
                _auditServiceMock.Object,
                _passwordHasher,
                NullLogger.Instance,
                isDevelopment: false);
            _dbContext.ChangeTracker.Clear();
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static IWebHostEnvironment ProductionEnvironment()
    {
        var environment = new Mock<IWebHostEnvironment>();
        environment.SetupGet(item => item.EnvironmentName).Returns("Production");
        environment.SetupGet(item => item.ApplicationName).Returns("SignaCore.Host");
        environment.SetupGet(item => item.ContentRootPath).Returns(AppContext.BaseDirectory);
        environment.SetupGet(item => item.ContentRootFileProvider)
            .Returns(new NullFileProvider());
        environment.SetupGet(item => item.WebRootPath).Returns(AppContext.BaseDirectory);
        environment.SetupGet(item => item.WebRootFileProvider).Returns(new NullFileProvider());
        return environment.Object;
    }
}
