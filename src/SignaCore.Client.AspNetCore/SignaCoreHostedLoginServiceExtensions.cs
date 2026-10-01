using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The registration entry of the hosted-login package. Validates the options at startup and
/// wires the protocol services, the default in-process ticket store with its periodic sweep, the
/// bounded backchannel HTTP client, and the package's two authentication schemes: the session
/// scheme and the forwarding scheme consumers authorize against.
/// </summary>
public static class SignaCoreHostedLoginServiceExtensions
{
    /// <summary>
    /// Registers the SignaCore hosted-login integration. Call
    /// <c>MapSignaCoreHostedLogin</c> on the app's endpoints afterwards. An illegal or incomplete
    /// option fails startup; the diagnostics name the option, never its value.
    /// </summary>
    /// <param name="services">The application's service collection.</param>
    /// <param name="configure">The protocol configuration.</param>
    public static IServiceCollection AddSignaCoreHostedLogin(
        this IServiceCollection services,
        Action<SignaCoreHostedLoginOptions> configure)
    {
        services.AddOptions<SignaCoreHostedLoginOptions>()
            .Configure(configure)
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<SignaCoreHostedLoginOptions>,
            SignaCoreHostedLoginOptionsValidator>();
        services.TryAddSingleton(TimeProvider.System);

        services.AddSingleton<PendingSignInStore>();
        services.TryAddSingleton<ITicketStore>(static services =>
            new InMemoryTicketStore(services.GetRequiredService<TimeProvider>())
            {
                Capacity = services.GetRequiredService<IOptions<SignaCoreHostedLoginOptions>>()
                    .Value.TicketCapacity
            });
        services.AddHostedService<TicketStoreCleanupService>();

        services.AddHttpClient(SignaCoreHostedLoginDefaults.HttpClientName)
            .ConfigureHttpClient(static client => client.Timeout = TimeSpan.FromSeconds(30));

        services.AddSingleton<SignaCoreDiscoveryClient>();
        services.AddSingleton<SignaCoreTokenClient>();
        services.AddSingleton<SignaCoreIdTokenValidator>();
        services.AddSingleton<SignaCoreHostedLoginEndpointService>();

        services.AddAuthentication()
            .AddScheme<SignaCoreSessionSchemeOptions, SignaCoreSessionAuthenticationHandler>(
                SignaCoreHostedLoginDefaults.SessionAuthenticationScheme,
                static _ => { })
            .AddPolicyScheme(
                SignaCoreHostedLoginDefaults.AuthenticationScheme,
                "SignaCore hosted login",
                static policy =>
                {
                    // Extension point 4 — session and Bearer scheme selection: the consumer's
                    // selector, per request, picks the scheme that serves it; the package's
                    // session scheme is the default.
                    policy.ForwardDefaultSelector = static context =>
                        context.RequestServices
                            .GetRequiredService<IOptionsMonitor<SignaCoreHostedLoginOptions>>()
                            .CurrentValue.SchemeSelector?.Invoke(context)
                        ?? SignaCoreHostedLoginDefaults.SessionAuthenticationScheme;
                });

        return services;
    }
}
