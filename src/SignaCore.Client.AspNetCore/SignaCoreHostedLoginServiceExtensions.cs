using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The registration entry of the hosted-login package. Validates the options at startup and
/// wires the protocol services, the default in-process ticket store with its periodic sweep, the
/// logout-return state store, the antiforgery services behind the package's CSRF boundary, the
/// bounded backchannel HTTP client — logged nowhere, redirected nowhere, cookie-free, and excluded
/// from HttpClient instrumentation — and the package's two authentication schemes: the session
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

        // The CSRF boundary's token store and validator. The package's header name is the
        // configuration point for session-authenticated unsafe methods; an application that
        // needs its own name either sets the package option or post-configures AntiforgeryOptions
        // after this registration, which then runs later and wins.
        services.AddAntiforgery(static options =>
        {
            options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict;
            options.Cookie.IsEssential = true;
        });
        services.AddOptions<Microsoft.AspNetCore.Antiforgery.AntiforgeryOptions>()
            .PostConfigure<IOptions<SignaCoreHostedLoginOptions>>(
                static (antiforgery, login) =>
                    antiforgery.HeaderName = login.Value.AntiforgeryHeaderName);

        // The backchannel carries the client secret and, at logout, the ID token: it never
        // follows a redirect, never carries a cookie, writes no request/response log line, and is
        // excluded from HttpClient instrumentation, so those values reach neither logs, nor
        // traces, nor metrics.
        services.AddTransient<SignaCoreBackchannelTelemetryHandler>();
        services.AddHttpClient(SignaCoreHostedLoginDefaults.HttpClientName)
            .ConfigureHttpClient(static client => client.Timeout = TimeSpan.FromSeconds(30))
            .ConfigurePrimaryHttpMessageHandler(static () =>
                new System.Net.Http.SocketsHttpHandler
                {
                    AllowAutoRedirect = false,
                    UseCookies = false
                })
            .AddHttpMessageHandler<SignaCoreBackchannelTelemetryHandler>()
            .RemoveAllLoggers();

        services.AddSingleton<SignaCoreDiscoveryClient>();
        services.AddSingleton<SignaCoreTokenClient>();
        services.AddSingleton<SignaCoreIdTokenValidator>();
        services.AddSingleton<SignaCoreAccessTokenValidator>();
        services.AddSingleton<SignaCoreLogoutClient>();
        services.AddSingleton<LogoutReturnStateStore>();
        services.AddSingleton<SignaCoreHostedLoginEndpointService>();
        services.AddSingleton<SignaCoreHostedLogoutService>();

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
