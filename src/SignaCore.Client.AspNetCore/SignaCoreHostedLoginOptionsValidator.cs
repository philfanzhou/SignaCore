using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The startup validation of <see cref="SignaCoreHostedLoginOptions"/>. Every failure message
/// names the option — never the configured value, so a misconfiguration cannot leak a secret or
/// an internal address through its own diagnostics.
/// </summary>
internal sealed class SignaCoreHostedLoginOptionsValidator(IHostEnvironment environment)
    : IValidateOptions<SignaCoreHostedLoginOptions>
{
    private const string OptionsName = "SignaCoreHostedLoginOptions";

    public ValidateOptionsResult Validate(string? name, SignaCoreHostedLoginOptions options)
    {
        if (!string.IsNullOrEmpty(name) && name != Options.DefaultName)
        {
            return ValidateOptionsResult.Skip;
        }

        var failures = new List<string>();
        var environmentName = environment.EnvironmentName;
        var allowInsecureLoopback = environmentName == Environments.Development
            || environmentName == "Testing";

        // The intranet opt-in is environment-independent: a non-empty, legal list admits exactly
        // its origins in every environment name, and an illegal entry is a startup failure that
        // names the option without echoing the configured value.
        if (!IntranetHttpOrigin.TryResolve(options.IntranetHttpOrigins, out var intranetHttpOrigins))
        {
            failures.Add(
                $"{OptionsName}.IntranetHttpOrigins must be a list of exact intranet HTTP origins: 'http://' plus a private IPv4 literal (10/8, 172.16/12, or 192.168/16) or a bracketed IPv6 Unique Local Address literal, plus an explicit port from 1 to 65535, without user info, path, query, fragment, percent escapes, whitespace, domain names, or duplicates.");
        }

        var intranetHttpEnabled = intranetHttpOrigins.Count > 0;
        if (intranetHttpEnabled
            && (options.SessionCookieName.StartsWith(
                    SignaCoreHostedLoginDefaults.HostCookiePrefix, StringComparison.OrdinalIgnoreCase)
                || options.SessionCookieName.StartsWith(
                    SignaCoreHostedLoginDefaults.SecureCookiePrefix, StringComparison.OrdinalIgnoreCase)))
        {
            failures.Add(
                $"{OptionsName}.SessionCookieName cannot carry the __Host- or __Secure- cookie prefix while {OptionsName}.IntranetHttpOrigins is configured: those prefixes require the Secure attribute, which an intranet HTTP deployment cannot set, so every cookie of the session would be refused by the browser.");
        }

        if (string.IsNullOrWhiteSpace(options.Authority))
        {
            if (!options.AllowUnconfiguredStartup)
            {
                failures.Add($"{OptionsName}.Authority is required.");
            }
        }
        else if (!SignaCoreAuthorityUriRules.IsAcceptableAuthority(
                     options.Authority, allowInsecureLoopback, intranetHttpOrigins))
        {
            // The message is the historical one byte for byte, whatever the intranet list holds:
            // an unmatched origin takes the existing rejection path and wording.
            failures.Add(
                $"{OptionsName}.Authority must be an absolute HTTPS URI without a path, query, fragment, or user info. An explicit loopback HTTP origin (127.0.0.1 or [::1]) is accepted only in the Development and Testing environments.");
        }

        if (string.IsNullOrWhiteSpace(options.ClientId) && !options.AllowUnconfiguredStartup)
        {
            failures.Add($"{OptionsName}.ClientId is required.");
        }

        if (string.IsNullOrWhiteSpace(options.ClientSecret) && !options.AllowUnconfiguredStartup)
        {
            failures.Add($"{OptionsName}.ClientSecret is required.");
        }

        if (string.IsNullOrWhiteSpace(options.RedirectUri))
        {
            if (!options.AllowUnconfiguredStartup)
            {
                failures.Add($"{OptionsName}.RedirectUri is required.");
            }
        }
        else if (!SignaCoreAuthorityUriRules.IsAcceptableRedirectUri(
                     options.RedirectUri, allowInsecureLoopback, intranetHttpOrigins))
        {
            failures.Add(
                $"{OptionsName}.RedirectUri must be an absolute HTTPS URI with a path and without a query, fragment, or user info. An explicit loopback HTTP origin (127.0.0.1 or [::1]) is accepted only in the Development and Testing environments.");
        }

        if (options.PreSignInAuthorizationTimeout <= TimeSpan.Zero
            || options.PreSignInAuthorizationTimeout > TimeSpan.FromSeconds(30))
        {
            failures.Add($"{OptionsName}.PreSignInAuthorizationTimeout is invalid.");
        }

        if (options.TicketCapacity <= 0)
        {
            failures.Add($"{OptionsName}.TicketCapacity must be positive.");
        }

        if (string.IsNullOrWhiteSpace(options.Scope))
        {
            failures.Add($"{OptionsName}.Scope is required.");
        }
        else if (!options.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Contains("openid", StringComparer.Ordinal))
        {
            failures.Add($"{OptionsName}.Scope must include openid.");
        }

        if (string.IsNullOrWhiteSpace(options.SessionCookieName))
        {
            failures.Add($"{OptionsName}.SessionCookieName is required.");
        }

        if (string.IsNullOrWhiteSpace(options.AntiforgeryHeaderName))
        {
            failures.Add($"{OptionsName}.AntiforgeryHeaderName is required.");
        }

        if (options.PostLogoutRedirectUri is not null)
        {
            if (!SignaCoreAuthorityUriRules.IsAcceptableRedirectUri(
                    options.PostLogoutRedirectUri, allowInsecureLoopback, intranetHttpOrigins))
            {
                failures.Add(
                    $"{OptionsName}.PostLogoutRedirectUri must be an absolute HTTPS URI with a path and without a query, fragment, or user info. An explicit loopback HTTP origin (127.0.0.1 or [::1]) is accepted only in the Development and Testing environments.");
            }
            else if (options.Prefix is { } prefix
                && new Uri(options.PostLogoutRedirectUri).AbsolutePath.TrimEnd('/')
                    != prefix + "/" + SignaCoreHostedLoginDefaults.LogoutReturnPathSegment)
            {
                failures.Add(
                    $"{OptionsName}.PostLogoutRedirectUri does not match the hosted-login logout-return path; the redirect URI's path must be exactly <prefix>/logout/return.");
            }
        }

        if (SignaCoreHostedLoginEndpointService.AsLocalPath(options.PostLogoutReturnPath) is null)
        {
            failures.Add(
                $"{OptionsName}.PostLogoutReturnPath must be a local absolute path that starts with exactly one slash.");
        }

        if (options.Validation.ClockSkew < TimeSpan.Zero
            || options.Validation.ClockSkew > TimeSpan.FromSeconds(30))
        {
            failures.Add(
                $"{OptionsName}.Validation.ClockSkew is invalid; it must be zero to thirty seconds.");
        }

        if (options.Validation.MaxTokenResponseBytes <= 0)
        {
            failures.Add($"{OptionsName}.Validation.MaxTokenResponseBytes must be positive.");
        }

        if (options.Validation.MaxLogoutResponseBytes <= 0)
        {
            failures.Add($"{OptionsName}.Validation.MaxLogoutResponseBytes must be positive.");
        }

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}
