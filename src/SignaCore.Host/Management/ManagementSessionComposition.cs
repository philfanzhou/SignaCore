using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using ServiceMantle.AspNetCore;
using ServiceMantle.AspNetCore.Health;
using ServiceMantle.Management;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using SignaCore.Host.Installation;

namespace SignaCore.Host.Management;

/// <summary>
/// Composes the shared ServiceMantle management session in the normal host: the fixed management
/// cookie scheme, the management bearer scheme and its selector, the phase-gated management API
/// v1, the three session entries, and the Data Protection key ring persisted through the shared
/// EF Core store.
/// </summary>
internal static class ManagementSessionComposition
{
    private static readonly JsonSerializerOptions CredentialJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    /// <summary>
    /// Registers the management session capabilities. Call after the legacy identity
    /// infrastructure: <c>AddManagementCookieAuthentication</c> sets the Data Protection
    /// application name <c>ServiceMantle.Management:signacore</c>, which its startup validator
    /// requires to be the effective value, so it must be the last application-name registration.
    /// </summary>
    internal static ServiceMantleBuilder AddSignaCoreManagementSession(
        this ServiceMantleBuilder builder,
        DatabaseOptions databaseOptions)
    {
        // The shared default lifetime is 8h; SignaCore keeps the legacy non-persistent admin
        // session length of 12 sliding hours, so operators see no lifetime change in the switch.
        builder.AddManagementCookieAuthentication(options =>
            options.ExpireTimeSpan = TimeSpan.FromHours(12));

        // The management bearer (#360, stage 3). The selector becomes the default authenticate,
        // challenge, and forbid scheme, overriding the shared cookie defaults registered just
        // above; sign-in and sign-out stay on the cookie. The shared ServiceMantle.ManagementAdmin
        // policy names no scheme, so it follows the selector, while the session-pinned entries
        // (session, bootstrap) keep resolving through the cookie alone.
        builder.Services.AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, ManagementBearerAuthenticationHandler>(
                ManagementBearerAuthenticationDefaults.AuthenticationScheme,
                _ => { })
            .AddPolicyScheme(
                ManagementBearerAuthenticationDefaults.SelectorScheme,
                displayName: null,
                options => options.ForwardDefaultSelector = ManagementBearerAuthenticationDefaults.SelectScheme);
        builder.Services.Configure<AuthenticationOptions>(options =>
        {
            options.DefaultAuthenticateScheme = ManagementBearerAuthenticationDefaults.SelectorScheme;
            options.DefaultChallengeScheme = ManagementBearerAuthenticationDefaults.SelectorScheme;
            options.DefaultForbidScheme = ManagementBearerAuthenticationDefaults.SelectorScheme;
        });
        builder.AddServiceMantleManagementApiV1();
        builder.AddServiceMantleManagementEntries();

        // The shared key-ring repository resolves its own contexts through the factory, independent
        // of the scoped business context. Both use the same provider options as the host context.
        builder.Services.AddDbContextFactory<IdentityDbContext>(options =>
            options.UseIdentityDatabase(databaseOptions));
        builder.Services.AddDataProtection()
            .PersistKeysToServiceMantleEfCore<IdentityDbContext>(
                InstallationStores.ServiceId,
                serviceProvider => Convert.ToBase64String(
                    serviceProvider.GetRequiredService<IMasterKeyProvider>().GetMasterKey()));

        builder.Services.AddHttpContextAccessor();
        builder.Services.AddScoped<ManagementCredentialAccessor>();
        builder.Services.AddScoped<IManagementIdentityProvider, SignaCoreManagementIdentityProvider>();
        builder.Services.AddSingleton<ManagementOperatorReader>();
        builder.Services.AddScoped<IServiceHealthSnapshotSource, InstallationHealthSnapshotSource>();

        return builder;
    }

    /// <summary>Maps the three management session entries with the SignaCore login adapter.</summary>
    internal static IEndpointRouteBuilder MapSignaCoreManagementSession(this IEndpointRouteBuilder endpoints) =>
        endpoints.MapServiceMantleManagementSession(LoginAdapter);

    /// <summary>
    /// Parses the SignaCore credential body — the same <c>username</c>/<c>password</c> JSON shape
    /// the legacy admin console submits — places it in the scoped accessor, and invokes the
    /// identity provider through the shared invoker. A body without a usable credential pair is an
    /// expected rejection, not a failure.
    /// </summary>
    internal static async ValueTask<ManagementIdentityResult> LoginAdapter(
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        string body;
        using (var reader = new StreamReader(
                   httpContext.Request.Body,
                   System.Text.Encoding.UTF8,
                   detectEncodingFromByteOrderMarks: false,
                   leaveOpen: true))
        {
            body = await reader.ReadToEndAsync(cancellationToken);
        }

        ManagementSessionCredentials? credentials;
        try
        {
            credentials = JsonSerializer.Deserialize<ManagementSessionCredentials>(body, CredentialJsonOptions);
        }
        catch (JsonException)
        {
            return ManagementIdentityResult.Unauthenticated();
        }

        if (string.IsNullOrWhiteSpace(credentials?.Username) || string.IsNullOrWhiteSpace(credentials.Password))
        {
            return ManagementIdentityResult.Unauthenticated();
        }

        var accessor = httpContext.RequestServices.GetRequiredService<ManagementCredentialAccessor>();
        accessor.Set(credentials.Username.Trim(), credentials.Password);

        var provider = httpContext.RequestServices.GetRequiredService<IManagementIdentityProvider>();
        return await ManagementIdentityProviderInvoker.InvokeAsync(provider, cancellationToken);
    }

    private sealed record ManagementSessionCredentials(string? Username, string? Password);
}
