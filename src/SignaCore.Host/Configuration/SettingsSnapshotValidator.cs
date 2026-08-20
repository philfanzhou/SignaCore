using System.Globalization;
using System.Text.Json;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services.Ldap;
using SignaCore.Domain.Services.Sms;
using SignaCore.Domain.Services.WeChat;

namespace SignaCore.Host.Configuration;

/// <summary>
/// Validates a proposed or loaded settings snapshot as one unit.
/// <para>
/// A <c>Completed</c> installation with missing or invalid required settings fails closed with the
/// full list of problems; it is never rolled back to <c>Pending</c>, because that would reopen
/// anonymous setup against a database that already owns accounts.
/// </para>
/// </summary>
internal static class SettingsSnapshotValidator
{
    public static IReadOnlyList<string> Validate(
        IReadOnlyDictionary<string, string> values,
        bool isDevelopment = false)
    {
        var errors = new List<string>();

        foreach (var definition in SystemSettingsCatalog.Definitions)
        {
            if (!values.TryGetValue(definition.Key, out var value))
            {
                errors.Add($"{definition.Key} is missing.");
                continue;
            }

            ValidateType(definition, value, errors);
        }

        ValidatePublicBaseUrl(values, errors);
        RequireNonEmpty(values, SystemSettingKeys.JwtAudience, errors);
        RequireNonEmpty(values, SystemSettingKeys.AdminUsername, errors);
        ValidateRanges(values, errors);
        ValidateRuntimeOptions(values, isDevelopment, errors);

        return errors;
    }

    /// <summary>
    /// Throws when the snapshot is unusable, listing every problem at once so an operator can fix a
    /// deployment in a single pass instead of restarting per error.
    /// </summary>
    public static void ThrowIfInvalid(
        IReadOnlyDictionary<string, string> values,
        bool isDevelopment = false)
    {
        var errors = Validate(values, isDevelopment);
        if (errors.Count == 0)
        {
            return;
        }

        throw new SettingsSnapshotException(
            "The stored configuration snapshot is not valid:" + Environment.NewLine +
            string.Join(Environment.NewLine, errors.Select(error => "  - " + error)),
            errors);
    }

    private static void ValidateType(
        SystemSettingDefinition definition,
        string value,
        List<string> errors)
    {
        switch (definition.ValueType)
        {
            case SettingValueTypes.Number:
                if (!long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out _))
                {
                    errors.Add($"{definition.Key} must be an integer.");
                }

                break;

            case SettingValueTypes.Boolean:
                if (!bool.TryParse(value, out _))
                {
                    errors.Add($"{definition.Key} must be 'true' or 'false'.");
                }

                break;

            case SettingValueTypes.Json:
                try
                {
                    using var _ = JsonDocument.Parse(value);
                }
                catch (JsonException)
                {
                    errors.Add($"{definition.Key} must be valid JSON.");
                }

                break;
        }
    }

    private static void ValidatePublicBaseUrl(
        IReadOnlyDictionary<string, string> values,
        List<string> errors)
    {
        if (!values.TryGetValue(SystemSettingKeys.PublicBaseUrl, out var publicBaseUrl) ||
            string.IsNullOrWhiteSpace(publicBaseUrl))
        {
            errors.Add($"{SystemSettingKeys.PublicBaseUrl} is required.");
            return;
        }

        if (!TryNormalizeBaseUrl(publicBaseUrl, out var normalized, out var reason))
        {
            errors.Add($"{SystemSettingKeys.PublicBaseUrl} {reason}");
            return;
        }

        var allowNonHttps = values.TryGetValue(SystemSettingKeys.SecurityAllowNonHttpsIssuer, out var raw)
            && bool.TryParse(raw, out var parsed)
            && parsed;

        // Deliberately unconditional. SignaCore does not classify a URL as public, private,
        // loopback, or container-local: plain HTTP is either explicitly accepted by the operator or
        // it is not, and the environment name is not a substitute for that decision.
        if (!allowNonHttps && !normalized.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            errors.Add(
                $"{SystemSettingKeys.PublicBaseUrl} must be an absolute HTTPS URL unless " +
                $"{SystemSettingKeys.SecurityAllowNonHttpsIssuer} is explicitly enabled.");
        }

        if (!values.TryGetValue(SystemSettingKeys.JwtIssuer, out var issuer) ||
            string.IsNullOrWhiteSpace(issuer))
        {
            errors.Add($"{SystemSettingKeys.JwtIssuer} is required.");
            return;
        }

        // Every conforming OAuth/OIDC client compares the `iss` claim with the URL it fetched
        // discovery from, so the two cannot be allowed to drift apart.
        if (!string.Equals(issuer.Trim().TrimEnd('/'), normalized, StringComparison.Ordinal))
        {
            errors.Add(
                $"{SystemSettingKeys.JwtIssuer} must equal the normalized " +
                $"{SystemSettingKeys.PublicBaseUrl}.");
        }
    }

    private static void ValidateRanges(
        IReadOnlyDictionary<string, string> values,
        List<string> errors)
    {
        RequirePositive(values, SystemSettingKeys.JwtTokenExpirationHours, 1, 24, errors);
        RequirePositive(values, SystemSettingKeys.RefreshTokenExpirationDays, 1, 365, errors);
        RequirePositive(values, SystemSettingKeys.PasswordHasherWorkFactor, 10, 15, errors);
    }

    /// <summary>
    /// Runs the same option binders and validators used while composing the application. Structural
    /// JSON validity alone is insufficient: a syntactically valid SMS/LDAP/WeChat document can still
    /// make the next process startup fail.
    /// </summary>
    private static void ValidateRuntimeOptions(
        IReadOnlyDictionary<string, string> values,
        bool isDevelopment,
        List<string> errors)
    {
        var entries = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var definition in SystemSettingsCatalog.Definitions)
            {
                if (!values.TryGetValue(definition.Key, out var value))
                {
                    continue;
                }

                if (definition.ValueType == SettingValueTypes.Json)
                {
                    JsonSettingFlattener.Flatten(definition.Key, value, entries);
                }
                else
                {
                    entries[definition.Key] = value;
                }
            }
        }
        catch (JsonException)
        {
            // ValidateType already records the key-specific JSON error.
            return;
        }

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(entries)
            .Build();

        CaptureValidationError(() =>
        {
            var options = configuration.GetSection(SmsOptions.SectionName).Get<SmsOptions>() ?? new SmsOptions();
            options.Validate(isDevelopment);
        }, errors);

        CaptureValidationError(() =>
        {
            var options = configuration.GetSection(LdapOptions.SectionName).Get<LdapOptions>() ?? new LdapOptions();
            options.Validate();
        }, errors);

        CaptureValidationError(() =>
        {
            var options = configuration.GetSection(WechatOptions.SectionName).Get<WechatOptions>() ?? new WechatOptions();
            options.Validate();
        }, errors);

        foreach (var proxy in configuration
                     .GetSection(SystemSettingKeys.ReverseProxyKnownProxies)
                     .Get<string[]>() ?? [])
        {
            if (!System.Net.IPAddress.TryParse(proxy, out _))
            {
                errors.Add($"{SystemSettingKeys.ReverseProxyKnownProxies} contains an invalid IP address: '{proxy}'.");
            }
        }
    }

    private static void CaptureValidationError(Action validate, List<string> errors)
    {
        try
        {
            validate();
        }
        catch (InvalidOperationException exception)
        {
            errors.Add(exception.Message);
        }
    }

    private static void RequireNonEmpty(
        IReadOnlyDictionary<string, string> values,
        string key,
        List<string> errors)
    {
        if (values.TryGetValue(key, out var value) && string.IsNullOrWhiteSpace(value))
        {
            errors.Add($"{key} is required.");
        }
    }

    private static void RequirePositive(
        IReadOnlyDictionary<string, string> values,
        string key,
        int minimum,
        int maximum,
        List<string> errors)
    {
        if (!values.TryGetValue(key, out var raw) ||
            !int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
        {
            return;
        }

        if (value < minimum || value > maximum)
        {
            errors.Add($"{key} must be between {minimum} and {maximum}.");
        }
    }

    /// <summary>
    /// Normalizes a public base URL to the canonical form stored in <c>system_settings</c>: absolute,
    /// no trailing slash, no user information, query, or fragment.
    /// </summary>
    public static bool TryNormalizeBaseUrl(
        string? candidate,
        out string normalized,
        out string reason)
    {
        normalized = string.Empty;
        reason = string.Empty;

        if (string.IsNullOrWhiteSpace(candidate))
        {
            reason = "is required.";
            return false;
        }

        var trimmed = candidate.Trim();
        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp) ||
            string.IsNullOrWhiteSpace(uri.Host) ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment))
        {
            reason = "must be an absolute http or https base URL without user information, " +
                     "query, or fragment.";
            return false;
        }

        normalized = trimmed.TrimEnd('/');
        return true;
    }
}
