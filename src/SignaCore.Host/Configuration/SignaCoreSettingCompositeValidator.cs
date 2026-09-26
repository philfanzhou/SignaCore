using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using ServiceMantle.Configuration;
using SignaCore.Domain.Services.Ldap;
using SignaCore.Domain.Services.Sms;
using SignaCore.Domain.Services.WeChat;

namespace SignaCore.Host.Configuration;

/// <summary>
/// Carries every cross-key rule of the retired legacy snapshot validator onto the shared setting
/// contract: the public base URL rules, the issuer equality, the non-blank keys, and the runtime
/// option binders (SMS, LDAP, WeChat, reverse-proxy IPs).
/// </summary>
/// <remarks>
/// The validator reconstructs the legacy-keyed snapshot from the candidate values — missing
/// sensitive (or defensively missing) keys take the legacy default, exactly what the legacy
/// validator saw — and then applies the same rule logic and the same option binders, so equivalent
/// inputs keep equivalent outcomes. Errors are closed, key-scoped codes; they never contain values.
/// The <c>isDevelopment</c> flag is fixed at composition time and, as before, only affects the
/// development-only SMS logging profile.
/// <para>
/// The <c>validateManagementUpdateRules</c> flag adds the rules for the remote sinks the normal
/// host enables from the snapshot: the OTLP endpoint (empty, or an absolute HTTPS URL without user
/// info, query, or fragment) and the Loki pair (an absolute HTTPS endpoint without user info,
/// query, or fragment, and an endpoint and Authorization value that are either both set or both
/// empty). Only the management update registry sets it: the startup snapshot load, the legacy
/// import, and the bootstrap target probe must keep accepting values an older release stored,
/// which the normal host then switches off with a warning instead of failing.
/// </para>
/// </remarks>
internal sealed class SignaCoreSettingCompositeValidator(
    bool isDevelopment,
    bool validateManagementUpdateRules = false)
    : IServiceSettingCompositeValidator
{
    internal const string RequiredCode = "signacore.setting.required";
    internal const string BaseUrlInvalidCode = "signacore.setting.base_url_invalid";
    internal const string HttpsRequiredCode = "signacore.setting.https_required";
    internal const string IssuerMismatchCode = "signacore.setting.issuer_mismatch";
    internal const string RuntimeInvalidCode = "signacore.setting.runtime_invalid";

    private static string PublicBaseUrl => SharedSettingKeys.NormalizedByLegacyKey[SystemSettingKeys.PublicBaseUrl];
    private static string JwtIssuerKey => SharedSettingKeys.NormalizedByLegacyKey[SystemSettingKeys.JwtIssuer];

    public IEnumerable<ServiceSettingValidationError> Validate(ServiceSettingValidationContext context)
    {
        var legacy = BuildLegacySnapshot(context);
        var errors = new List<ServiceSettingValidationError>();

        ValidatePublicBaseUrl(legacy, errors);
        RequireNonBlank(legacy, SystemSettingKeys.JwtAudience, errors);
        RequireNonBlank(legacy, SystemSettingKeys.AdminUsername, errors);
        ValidateRuntimeOptions(legacy, errors);
        if (validateManagementUpdateRules)
        {
            ValidateOtlpEndpoint(legacy, errors);
            ValidateLoki(legacy, errors);
        }

        return errors;
    }

    /// <summary>
    /// Rebuilds the legacy-keyed snapshot. Values present in the candidate are rendered in the
    /// legacy wire format; values absent (allowed only for sensitive keys and keys whose empty
    /// default was not migrated) fall back to the legacy default, which is exactly the value the
    /// legacy validator would have seen.
    /// </summary>
    private static Dictionary<string, string> BuildLegacySnapshot(ServiceSettingValidationContext context)
    {
        var snapshot = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var definition in ServiceSettingDefinitions.Table)
        {
            var legacyKey = ServiceSettingDefinitions.LegacyKeyOf(definition);
            if (context.TryGetValue(definition.Key, out var value) && value.HasValue)
            {
                snapshot[legacyKey] = definition.ValueType switch
                {
                    ServiceSettingValueType.String => value.GetString(),
                    ServiceSettingValueType.Number => value.GetNumber().ToString("G29", CultureInfo.InvariantCulture),
                    ServiceSettingValueType.Boolean => value.GetBoolean() ? "true" : "false",
                    ServiceSettingValueType.Json => JsonSerializer.Serialize(value.GetJson()),
                    _ => throw new InvalidOperationException(
                        $"Unsupported setting value type: {definition.ValueType}")
                };
            }
            else
            {
                snapshot[legacyKey] = definition.LegacyDefault ?? string.Empty;
            }
        }

        return snapshot;
    }

    private static void ValidatePublicBaseUrl(
        IReadOnlyDictionary<string, string> values,
        List<ServiceSettingValidationError> errors)
    {
        if (!values.TryGetValue(SystemSettingKeys.PublicBaseUrl, out var publicBaseUrl) ||
            string.IsNullOrWhiteSpace(publicBaseUrl))
        {
            errors.Add(new ServiceSettingValidationError(PublicBaseUrl, RequiredCode));
            return;
        }

        if (!PublicBaseUrlNormalizer.TryNormalizeBaseUrl(publicBaseUrl, out var normalized, out _))
        {
            errors.Add(new ServiceSettingValidationError(PublicBaseUrl, BaseUrlInvalidCode));
            return;
        }

        var allowNonHttps = values.TryGetValue(SystemSettingKeys.SecurityAllowNonHttpsIssuer, out var raw)
            && bool.TryParse(raw, out var parsed)
            && parsed;

        // Deliberately unconditional, exactly as in the legacy validator: plain HTTP is either
        // explicitly accepted by the operator or it is not; the environment name is not a
        // substitute for that decision.
        if (!allowNonHttps && !normalized.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            errors.Add(new ServiceSettingValidationError(PublicBaseUrl, HttpsRequiredCode));
        }

        if (!values.TryGetValue(SystemSettingKeys.JwtIssuer, out var issuer) ||
            string.IsNullOrWhiteSpace(issuer))
        {
            errors.Add(new ServiceSettingValidationError(JwtIssuerKey, RequiredCode));
            return;
        }

        // Every conforming OAuth/OIDC client compares the `iss` claim with the URL it fetched
        // discovery from, so the two cannot be allowed to drift apart.
        if (!string.Equals(issuer.Trim().TrimEnd('/'), normalized, StringComparison.Ordinal))
        {
            errors.Add(new ServiceSettingValidationError(JwtIssuerKey, IssuerMismatchCode));
        }
    }

    /// <summary>The same endpoint rule the normal host applies before it enables OTLP.</summary>
    private static void ValidateOtlpEndpoint(
        IReadOnlyDictionary<string, string> values,
        List<ServiceSettingValidationError> errors)
    {
        if (!values.TryGetValue(SystemSettingKeys.OpenTelemetryOtlpEndpoint, out var endpoint) ||
            string.IsNullOrWhiteSpace(endpoint) ||
            Telemetry.OtlpEndpointState.TryParse(endpoint, out _))
        {
            return;
        }

        errors.Add(new ServiceSettingValidationError(
            SharedSettingKeys.NormalizedByLegacyKey[SystemSettingKeys.OpenTelemetryOtlpEndpoint],
            IsAbsoluteHttp(endpoint) ? HttpsRequiredCode : RuntimeInvalidCode));
    }

    /// <summary>
    /// The Loki pair: the same rules the normal host applies before it enables the sink, so a
    /// saved value is always one the next start can use.
    /// </summary>
    private static void ValidateLoki(
        IReadOnlyDictionary<string, string> values,
        List<ServiceSettingValidationError> errors)
    {
        values.TryGetValue(SystemSettingKeys.LokiUri, out var uri);
        values.TryGetValue(SystemSettingKeys.LokiAuthorization, out var authorization);
        var hasUri = !string.IsNullOrWhiteSpace(uri);
        var hasAuthorization = !string.IsNullOrWhiteSpace(authorization);

        if (hasUri && !Logging.LokiSettings.TryParseEndpoint(uri, out _))
        {
            errors.Add(new ServiceSettingValidationError(
                SharedSettingKeys.NormalizedByLegacyKey[SystemSettingKeys.LokiUri],
                IsAbsoluteHttp(uri!) ? HttpsRequiredCode : RuntimeInvalidCode));
        }

        if (hasAuthorization && !Logging.LokiSettings.IsUsableAuthorization(authorization))
        {
            errors.Add(new ServiceSettingValidationError(
                SharedSettingKeys.NormalizedByLegacyKey[SystemSettingKeys.LokiAuthorization],
                RuntimeInvalidCode));
        }

        if (hasUri != hasAuthorization)
        {
            var missingKey = hasUri ? SystemSettingKeys.LokiAuthorization : SystemSettingKeys.LokiUri;
            errors.Add(new ServiceSettingValidationError(
                SharedSettingKeys.NormalizedByLegacyKey[missingKey],
                RequiredCode));
        }
    }

    private static bool IsAbsoluteHttp(string value) =>
        Uri.TryCreate(value.Trim(), UriKind.Absolute, out var parsed) &&
        parsed.Scheme == Uri.UriSchemeHttp;

    private static void RequireNonBlank(
        IReadOnlyDictionary<string, string> values,
        string legacyKey,
        List<ServiceSettingValidationError> errors)
    {
        if (values.TryGetValue(legacyKey, out var value) && string.IsNullOrWhiteSpace(value))
        {
            errors.Add(new ServiceSettingValidationError(
                SharedSettingKeys.NormalizedByLegacyKey[legacyKey],
                RequiredCode));
        }
    }

    /// <summary>
    /// The same option binders and validators the host itself composes with; a syntactically valid
    /// document can still be a configuration the next process start would reject.
    /// </summary>
    private void ValidateRuntimeOptions(
        IReadOnlyDictionary<string, string> values,
        List<ServiceSettingValidationError> errors)
    {
        var entries = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var definition in ServiceSettingDefinitions.Table)
            {
                var legacyKey = ServiceSettingDefinitions.LegacyKeyOf(definition);
                var value = values[legacyKey];
                if (definition.ValueType == ServiceSettingValueType.Json)
                {
                    JsonSettingFlattener.Flatten(legacyKey, value, entries);
                }
                else
                {
                    entries[legacyKey] = value;
                }
            }
        }
        catch (JsonException)
        {
            // Per-key JSON validity is already enforced by the definition constraints.
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
                errors.Add(new ServiceSettingValidationError(
                    SharedSettingKeys.NormalizedByLegacyKey[SystemSettingKeys.ReverseProxyKnownProxies],
                    RuntimeInvalidCode));
            }
        }
    }

    private static void CaptureValidationError(
        Action validate,
        List<ServiceSettingValidationError> errors)
    {
        try
        {
            validate();
        }
        catch (InvalidOperationException)
        {
            // The binder message is not surfaced: the error code is closed and carries no values.
            errors.Add(new ServiceSettingValidationError(null, RuntimeInvalidCode));
        }
    }
}
