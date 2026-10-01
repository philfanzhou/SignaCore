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

        if (string.IsNullOrWhiteSpace(options.Authority))
        {
            failures.Add($"{OptionsName}.Authority is required.");
        }
        else if (!SignaCoreAuthorityUriRules.IsAcceptableAuthority(options.Authority, allowInsecureLoopback))
        {
            failures.Add(
                $"{OptionsName}.Authority must be an absolute HTTPS URI without a path, query, fragment, or user info. An explicit loopback HTTP origin (127.0.0.1 or [::1]) is accepted only in the Development and Testing environments.");
        }

        if (string.IsNullOrWhiteSpace(options.ClientId))
        {
            failures.Add($"{OptionsName}.ClientId is required.");
        }

        if (string.IsNullOrWhiteSpace(options.ClientSecret))
        {
            failures.Add($"{OptionsName}.ClientSecret is required.");
        }

        if (string.IsNullOrWhiteSpace(options.RedirectUri))
        {
            failures.Add($"{OptionsName}.RedirectUri is required.");
        }
        else if (!SignaCoreAuthorityUriRules.IsAcceptableRedirectUri(options.RedirectUri, allowInsecureLoopback))
        {
            failures.Add(
                $"{OptionsName}.RedirectUri must be an absolute HTTPS URI with a path and without a query, fragment, or user info. An explicit loopback HTTP origin (127.0.0.1 or [::1]) is accepted only in the Development and Testing environments.");
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

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}
