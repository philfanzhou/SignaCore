using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The endpoint mapping entry of the hosted-login package. It mounts the sign-in start, the
/// callback (at exactly the registered redirect URI's path), the session-status endpoint, and the
/// fixed failure page under the consumer's prefix.
/// </summary>
public static class SignaCoreHostedLoginEndpointExtensions
{
    /// <summary>
    /// Maps the hosted-login endpoints. The configured <c>RedirectUri</c>'s path must be exactly
    /// <c>&lt;prefix&gt;/callback</c>; a mismatch is a startup failure whose diagnostic names the
    /// option, never the value.
    /// </summary>
    /// <param name="endpoints">The route builder.</param>
    /// <param name="prefix">The consumer's route prefix, for example <c>/auth</c>.</param>
    public static void MapSignaCoreHostedLogin(
        this IEndpointRouteBuilder endpoints,
        string prefix = "/auth")
    {
        ArgumentNullException.ThrowIfNull(prefix);

        var normalizedPrefix = NormalizePrefix(prefix);
        // The live options monitor instance is the one every runtime component reads; writing
        // the prefix there keeps the mapped prefix and the challenge redirect in one place.
        var options = endpoints.ServiceProvider
            .GetRequiredService<IOptionsMonitor<SignaCoreHostedLoginOptions>>()
            .CurrentValue;

        if (string.IsNullOrEmpty(options.RedirectUri)
            || !Uri.TryCreate(options.RedirectUri, UriKind.Absolute, out var redirectUri))
        {
            throw new InvalidOperationException(
                "SignaCoreHostedLoginOptions.RedirectUri must be configured by AddSignaCoreHostedLogin before MapSignaCoreHostedLogin runs.");
        }

        var expectedCallbackPath = normalizedPrefix + "/"
            + SignaCoreHostedLoginDefaults.CallbackPathSegment;
        if (!string.Equals(
                redirectUri.AbsolutePath.TrimEnd('/'),
                expectedCallbackPath,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "SignaCoreHostedLoginOptions.RedirectUri does not match the hosted-login callback path; the redirect URI's path must be exactly <prefix>/callback.");
        }

        options.Prefix = normalizedPrefix;

        endpoints.MapGet(
            normalizedPrefix + "/" + SignaCoreHostedLoginDefaults.StartPathSegment,
            static context => context.RequestServices
                .GetRequiredService<SignaCoreHostedLoginEndpointService>()
                .HandleStartAsync(context));
        // The callback is mapped at the redirect URI's own path so the two can never drift apart.
        endpoints.MapGet(
            redirectUri.AbsolutePath.TrimEnd('/'),
            static context => context.RequestServices
                .GetRequiredService<SignaCoreHostedLoginEndpointService>()
                .HandleCallbackAsync(context));
        endpoints.MapGet(
            normalizedPrefix + "/" + SignaCoreHostedLoginDefaults.SessionPathSegment,
            static context => context.RequestServices
                .GetRequiredService<SignaCoreHostedLoginEndpointService>()
                .HandleSessionAsync(context));
        endpoints.MapGet(
            normalizedPrefix + "/" + SignaCoreHostedLoginDefaults.FailurePathSegment,
            static context => context.RequestServices
                .GetRequiredService<SignaCoreHostedLoginEndpointService>()
                .HandleFailurePageAsync(context));
    }

    private static string NormalizePrefix(string prefix)
    {
        var trimmed = prefix.TrimEnd('/');
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        return trimmed[0] == '/' ? trimmed : "/" + trimmed;
    }
}
