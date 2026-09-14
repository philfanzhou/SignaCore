using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ServiceMantle.Audit;
using ServiceMantle.AspNetCore.Management;
using ServiceMantle.Management;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using SignaCore.Host;
using SignaCore.Host.Management;
using SignaCore.Host.Security;
using SignaCore.Tests.Domain.Keys;
using Xunit;

namespace SignaCore.Tests.Host.Management;

/// <summary>
/// The AdminSession and Ops policies as composed by the normal host: both ride the fixed shared
/// management cookie scheme and admit only a principal that resolves to exactly one legitimate
/// operator holding the Admin permission.
/// </summary>
public sealed class AdminSessionPolicyTests
{
    private static readonly Guid OperatorId = Guid.NewGuid();

    private static ServiceProvider BuildServices()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "https://identity.example.test"
            }).Build();
        var databaseOptions = new DatabaseOptions
        {
            Provider = "PostgreSQL",
            ServerVersion = "15",
            ConnectionString = "Host=localhost;Database=identity;Username=postgres;Password=test"
        };
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddIdentityInfrastructure(
            configuration,
            new StubHostEnvironment { EnvironmentName = Environments.Production },
            databaseOptions,
            new BootstrapMasterKeyProvider("admin-session-policy-tests-root-secret"));
        services.AddSignaCoreServiceMantle().AddSignaCoreManagementSession(databaseOptions);
        return services.BuildServiceProvider();
    }

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

    public static TheoryData<string> PolicyNames =>
        ["AdminSession", GatewayAppAuthenticationDefaults.OpsPolicy];

    [Theory]
    [MemberData(nameof(PolicyNames))]
    public async Task AManagementOperatorWithAdminPermission_IsAuthorized(string policyName)
    {
        using var provider = BuildServices();

        var result = await EvaluateAsync(
            provider, policyName, ManagementPrincipal(ManagementPermission.Admin));

        Assert.True(result.Succeeded);
    }

    [Theory]
    [MemberData(nameof(PolicyNames))]
    public async Task AManagementOperatorWithoutAdminPermission_IsRejected(string policyName)
    {
        using var provider = BuildServices();

        var result = await EvaluateAsync(
            provider, policyName, ManagementPrincipal(ManagementPermission.Read, ManagementPermission.Write));

        Assert.False(result.Succeeded);
    }

    [Theory]
    [MemberData(nameof(PolicyNames))]
    public async Task AnAuthenticatedPrincipalWithOnlyLegacyNameClaims_IsRejected(string policyName)
    {
        using var provider = BuildServices();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, OperatorId.ToString()),
            new Claim(ClaimTypes.Name, "admin"),
            new Claim("admin_access", "true")
        ], "Test"));

        var result = await EvaluateAsync(provider, policyName, principal);

        // The exact claims the legacy qz_admin_session cookie used to carry resolve to no operator.
        Assert.False(result.Succeeded);
    }

    [Theory]
    [MemberData(nameof(PolicyNames))]
    public async Task AnUnauthenticatedPrincipal_IsRejected(string policyName)
    {
        using var provider = BuildServices();

        var result = await EvaluateAsync(
            provider, policyName, new ClaimsPrincipal(new ClaimsIdentity()));

        Assert.False(result.Succeeded);
    }

    [Theory]
    [MemberData(nameof(PolicyNames))]
    public async Task BothPolicies_RideTheFixedManagementScheme(string policyName)
    {
        using var provider = BuildServices();

        var policy = await GetPolicyAsync(provider, policyName);

        Assert.Equal(
            ManagementSessionDefaults.AuthenticationScheme,
            Assert.Single(policy.AuthenticationSchemes));
    }

    private sealed class StubHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "SignaCore.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
