using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ServiceMantle.Audit;
using ServiceMantle.AspNetCore.Management;
using ServiceMantle.Management;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using SignaCore.Host;
using SignaCore.Host.Management;
using SignaCore.Host.Security;
using Xunit;

namespace SignaCore.Tests.Host.Security;

/// <summary>
/// The isolated identity cookie scheme as composed by the normal host (canonical PS-18): its
/// security attributes, its explicit-scheme authorization policy, the minimal protected payload,
/// and the two-way isolation from the shared ServiceMantle management cookie under the one fixed
/// Data Protection application discriminator.
/// </summary>
public sealed class IdentitySessionCookieTests(SqliteKeyStoreFixture fixture)
    : IClassFixture<SqliteKeyStoreFixture>
{
    private static readonly Guid OperatorId = Guid.NewGuid();
    private static readonly Guid SessionId = Guid.NewGuid();

    private ServiceProvider BuildServices()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "https://identity.example.test"
            }).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddIdentityInfrastructure(
            configuration,
            new StubHostEnvironment { EnvironmentName = Environments.Production },
            fixture.DatabaseOptions,
            new BootstrapMasterKeyProvider("identity-session-cookie-tests-root-secret"));
        services.AddSignaCoreServiceMantle().AddSignaCoreManagementSession(fixture.DatabaseOptions);
        return services.BuildServiceProvider();
    }

    private static CookieAuthenticationOptions GetCookieOptions(
        IServiceProvider provider,
        string scheme) =>
        provider.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(scheme);

    private static async Task<AuthorizationPolicy> GetPolicyAsync(
        IServiceProvider provider,
        string policyName)
    {
        var policy = await provider.GetRequiredService<IAuthorizationPolicyProvider>()
            .GetPolicyAsync(policyName);
        Assert.NotNull(policy);
        return policy!;
    }

    private static async Task<AuthorizationResult> EvaluateAsync(
        IServiceProvider provider,
        string policyName,
        ClaimsPrincipal principal)
    {
        var policy = await GetPolicyAsync(provider, policyName);
        return await provider.GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(principal, policy);
    }

    private static ClaimsPrincipal ManagementPrincipal(params ManagementPermission[] permissions) =>
        ManagementIdentity.Create(
            WellKnownManagementAuditOperatorSources.InteractiveAdmin,
            OperatorId.ToString(),
            permissions,
            "console-admin").ToClaimsPrincipal();

    private static AuthenticationTicket IdentityTicket(Guid sessionId) =>
        new(
            IdentitySessionPrincipal.Create(sessionId),
            IdentitySessionDefaults.AuthenticationScheme);

    [Fact]
    public void TheIdentityCookie_CarriesTheCanonicalPs18Attributes()
    {
        using var provider = BuildServices();

        var options = GetCookieOptions(provider, IdentitySessionDefaults.AuthenticationScheme);

        // PS-18 pins the literal cookie contract; the constants must keep matching it.
        Assert.Equal("__Host-signacore_identity", options.Cookie.Name);
        Assert.True(options.Cookie.HttpOnly);
        Assert.Equal(CookieSecurePolicy.Always, options.Cookie.SecurePolicy);
        Assert.Equal(SameSiteMode.Lax, options.Cookie.SameSite);
        Assert.Equal("/", options.Cookie.Path);
        Assert.Null(options.Cookie.Domain);
    }

    [Fact]
    public void TheIdentityCookie_PinsItsPayloadToTheExplicitPurpose()
    {
        using var provider = BuildServices();
        var options = GetCookieOptions(provider, IdentitySessionDefaults.AuthenticationScheme);
        Assert.NotNull(options.TicketDataFormat);
        var pinnedFormat = new TicketDataFormat(
            provider.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector(IdentitySessionDefaults.DataProtectionPurpose));

        var protectedValue = options.TicketDataFormat!.Protect(IdentityTicket(SessionId));
        var roundTripped = pinnedFormat.Unprotect(protectedValue);

        // The effective format is exactly the pinned purpose, so the payload stays bound to the
        // contract constant instead of the scheme name.
        Assert.NotNull(roundTripped);
        Assert.Equal(
            SessionId.ToString(),
            roundTripped!.Principal.FindFirstValue(IdentitySessionDefaults.SessionIdClaim));
    }

    [Fact]
    public void TheIdentityScheme_IsNeverADefaultScheme()
    {
        using var provider = BuildServices();

        var authentication = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;

        // The shared ServiceMantle package keeps owning every default; the identity scheme only
        // contributes a non-interactive scheme that identity paths must name explicitly.
        Assert.Equal(
            ManagementSessionDefaults.AuthenticationScheme, authentication.DefaultAuthenticateScheme);
        Assert.Equal(
            ManagementSessionDefaults.AuthenticationScheme, authentication.DefaultChallengeScheme);
        Assert.Equal(
            ManagementSessionDefaults.AuthenticationScheme, authentication.DefaultForbidScheme);
        Assert.Equal(
            ManagementSessionDefaults.AuthenticationScheme, authentication.DefaultSignInScheme);
        Assert.Equal(
            ManagementSessionDefaults.AuthenticationScheme, authentication.DefaultSignOutScheme);
        Assert.NotEqual(
            IdentitySessionDefaults.AuthenticationScheme, authentication.DefaultScheme);
    }

    [Fact]
    public async Task TheIdentityPolicy_RidesOnlyTheIdentityScheme()
    {
        using var provider = BuildServices();

        var policy = await GetPolicyAsync(provider, IdentitySessionDefaults.Policy);

        Assert.Equal(
            IdentitySessionDefaults.AuthenticationScheme,
            Assert.Single(policy.AuthenticationSchemes));
        Assert.Contains(
            policy.Requirements,
            requirement => requirement is IdentitySessionRequirement);
    }

    [Fact]
    public async Task AnIdentitySessionPrincipal_SatisfiesTheIdentityPolicy()
    {
        using var provider = BuildServices();

        var result = await EvaluateAsync(
            provider, IdentitySessionDefaults.Policy, IdentityTicket(SessionId).Principal);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task AManagementPrincipal_DoesNotSatisfyTheIdentityPolicy()
    {
        using var provider = BuildServices();

        var result = await EvaluateAsync(
            provider,
            IdentitySessionDefaults.Policy,
            ManagementPrincipal(ManagementPermission.Admin));

        // Possessing the management cookie never produces an identity authorization result.
        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task APrincipalWithOnlyLegacyNameClaims_DoesNotSatisfyTheIdentityPolicy()
    {
        using var provider = BuildServices();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, OperatorId.ToString()),
            new Claim(ClaimTypes.Name, "admin"),
            new Claim("admin_access", "true")
        ], "Test"));

        var result = await EvaluateAsync(provider, IdentitySessionDefaults.Policy, principal);

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task ASessionIdClaimOnAForeignIdentity_DoesNotSatisfyTheIdentityPolicy()
    {
        using var provider = BuildServices();
        // The session id claim alone is not enough: it must ride an identity authenticated by the
        // identity scheme, so a default-populated principal can never satisfy the policy.
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(IdentitySessionDefaults.SessionIdClaim, SessionId.ToString())
        ], "SomeOtherScheme"));

        var result = await EvaluateAsync(provider, IdentitySessionDefaults.Policy, principal);

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task AnUnauthenticatedPrincipal_DoesNotSatisfyTheIdentityPolicy()
    {
        using var provider = BuildServices();

        var result = await EvaluateAsync(
            provider, IdentitySessionDefaults.Policy, new ClaimsPrincipal(new ClaimsIdentity()));

        Assert.False(result.Succeeded);
    }

    [Theory]
    [InlineData("AdminSession")]
    [InlineData(GatewayAppAuthenticationDefaults.OpsPolicy)]
    public async Task AnIdentitySessionPrincipal_NeverPassesAManagementPolicy(string policyName)
    {
        using var provider = BuildServices();

        var result = await EvaluateAsync(
            provider, policyName, IdentityTicket(SessionId).Principal);

        // Possessing the identity cookie never produces a management authorization result.
        Assert.False(result.Succeeded);
    }

    [Fact]
    public void TheProtectedPayload_CarriesOnlyTheOpaqueSessionId()
    {
        using var provider = BuildServices();
        var format = GetCookieOptions(provider, IdentitySessionDefaults.AuthenticationScheme)
            .TicketDataFormat!;

        var protectedValue = format.Protect(IdentityTicket(SessionId));
        var ticket = format.Unprotect(protectedValue);

        Assert.NotNull(ticket);
        var identity = Assert.Single(ticket!.Principal.Identities);
        Assert.Equal(IdentitySessionDefaults.AuthenticationScheme, identity.AuthenticationType);
        var claim = Assert.Single(identity.Claims);
        Assert.Equal(IdentitySessionDefaults.SessionIdClaim, claim.Type);
        Assert.Equal(SessionId.ToString(), claim.Value);

        // The PS-04 facts never ride the cookie: a successfully unprotected payload proves no
        // account, authentication time/method, or permission.
        Assert.Null(ticket.Principal.FindFirst("sub"));
        Assert.Null(ticket.Principal.FindFirst("name"));
        Assert.Null(ticket.Principal.FindFirst("auth_method"));
        Assert.Null(ticket.Principal.FindFirst(ClaimTypes.NameIdentifier));
        Assert.Null(ticket.Principal.FindFirst(ClaimTypes.Name));
        Assert.Null(ticket.Principal.FindFirst(IdentityConstants.ClaimPermission));
    }

    [Fact]
    public void TheIdentityAndManagementPayloads_DoNotUnprotectUnderEachOthersPurpose()
    {
        using var provider = BuildServices();
        var identityFormat =
            GetCookieOptions(provider, IdentitySessionDefaults.AuthenticationScheme)
                .TicketDataFormat!;
        var managementFormat =
            GetCookieOptions(provider, ManagementSessionDefaults.AuthenticationScheme)
                .TicketDataFormat!;
        var identityValue = identityFormat.Protect(IdentityTicket(SessionId));
        var managementValue = managementFormat.Protect(new AuthenticationTicket(
            ManagementPrincipal(ManagementPermission.Admin),
            ManagementSessionDefaults.AuthenticationScheme));

        // Both formats share the fixed ServiceMantle application discriminator and the same key
        // ring, so the rejection can only come from the distinct purposes: each format refuses
        // the other's payload instead of deserializing it.
        Assert.Null(managementFormat.Unprotect(identityValue));
        Assert.Null(identityFormat.Unprotect(managementValue));
    }

    [Fact]
    public void TheMinimalPrincipal_CarriesExactlyOneAuthenticatedSessionClaim()
    {
        var principal = IdentitySessionPrincipal.Create(SessionId);

        var identity = Assert.Single(principal.Identities);
        Assert.True(identity.IsAuthenticated);
        Assert.Equal(IdentitySessionDefaults.AuthenticationScheme, identity.AuthenticationType);
        var claim = Assert.Single(identity.Claims);
        Assert.Equal(IdentitySessionDefaults.SessionIdClaim, claim.Type);
        Assert.Equal(SessionId.ToString(), claim.Value);
    }

    [Fact]
    public void AnEmptySessionId_IsRejected()
    {
        Assert.Throws<ArgumentException>(() => IdentitySessionPrincipal.Create(Guid.Empty));
    }

    private sealed class StubHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "SignaCore.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}

/// <summary>
/// One migrated temporary SQLite database shared by the whole test class, so the Data Protection
/// assertions exercise the real wiring: the shared EF Core key-ring store under the fixed
/// ServiceMantle application discriminator, with keys encrypted by the bootstrap master key.
/// </summary>
public sealed class SqliteKeyStoreFixture : IAsyncLifetime
{
    private string? _directory;

    public string ConnectionString { get; private set; } = string.Empty;

    public DatabaseOptions DatabaseOptions => new()
    {
        Provider = "SQLite",
        ConnectionString = ConnectionString
    };

    public async ValueTask InitializeAsync()
    {
        _directory = Path.Combine(
            Path.GetTempPath(), $"signacore-identity-cookie-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_directory);
        ConnectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(_directory, "keys.db")
        }.ConnectionString;

        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(DatabaseOptions);
        await using var context = new IdentityDbContext(optionsBuilder.Options);
        await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        SqliteConnection.ClearAllPools();
        if (_directory != null && Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        await ValueTask.CompletedTask;
    }
}
