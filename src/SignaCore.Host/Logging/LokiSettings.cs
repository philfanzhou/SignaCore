namespace SignaCore.Host.Logging;

/// <summary>What the stored <c>loki.uri</c> / <c>loki.authorization</c> pair means for this start.</summary>
internal enum LokiSettingStatus
{
    /// <summary>Both values are empty: remote log shipping is off by choice.</summary>
    Disabled,

    /// <summary>A usable HTTPS endpoint and a usable Authorization value: the sink is enabled.</summary>
    Enabled,

    /// <summary>The endpoint is not an absolute HTTPS URL without user info, query, or fragment.</summary>
    EndpointInvalid,

    /// <summary>An authorization value is stored without an endpoint.</summary>
    EndpointMissing,

    /// <summary>An endpoint is stored without a usable authorization value.</summary>
    AuthorizationMissing,

    /// <summary>The stored authorization value is not a usable header value.</summary>
    AuthorizationInvalid
}

/// <summary>The classified Loki settings. The authorization value is never rendered.</summary>
internal sealed class LokiSettingState
{
    private LokiSettingState(LokiSettingStatus status, Uri? endpoint, string? authorization)
    {
        Status = status;
        Endpoint = endpoint;
        Authorization = authorization;
    }

    public LokiSettingStatus Status { get; }

    /// <summary>The endpoint; set only when <see cref="Status"/> is <see cref="LokiSettingStatus.Enabled"/>.</summary>
    public Uri? Endpoint { get; }

    /// <summary>The header value; set only when <see cref="Status"/> is <see cref="LokiSettingStatus.Enabled"/>.</summary>
    public string? Authorization { get; }

    /// <summary>True when stored values exist but cannot be used, so the start has to say so.</summary>
    public bool IsUnusable => Status is not (LokiSettingStatus.Disabled or LokiSettingStatus.Enabled);

    /// <summary>The fixed, value-free category written with the startup warning.</summary>
    public string Category => Status switch
    {
        LokiSettingStatus.EndpointInvalid => "endpoint_not_https",
        LokiSettingStatus.EndpointMissing => "endpoint_missing",
        LokiSettingStatus.AuthorizationMissing => "authorization_missing",
        LokiSettingStatus.AuthorizationInvalid => "authorization_invalid",
        LokiSettingStatus.Enabled => "enabled",
        _ => "disabled"
    };

    public override string ToString() => $"LokiSettingState({Category})";

    internal static LokiSettingState Create(LokiSettingStatus status) => new(status, null, null);

    internal static LokiSettingState Create(Uri endpoint, string authorization) =>
        new(LokiSettingStatus.Enabled, endpoint, authorization);
}

/// <summary>
/// The one set of Loki setting rules, shared by the management update validation and the normal
/// host's startup decision so a value the console accepts is exactly a value the host enables.
/// </summary>
/// <remarks>
/// The endpoint and header rules mirror what the ServiceMantle Grafana Loki sink itself enforces
/// when it starts (absolute HTTPS without user info, query, or fragment; a non-blank header value
/// of at most 4096 characters without control characters). Deciding here first is what lets a
/// value stored by an older release switch Loki off with a warning instead of failing the start.
/// </remarks>
internal static class LokiSettings
{
    internal const string UriKey = "loki.uri";
    internal const string AuthorizationKey = "loki.authorization";
    internal const int MaximumAuthorizationLength = 4_096;

    public static LokiSettingState Classify(string? uri, string? authorization)
    {
        var hasUri = !string.IsNullOrWhiteSpace(uri);
        var hasAuthorization = !string.IsNullOrWhiteSpace(authorization);
        if (!hasUri)
        {
            return LokiSettingState.Create(
                hasAuthorization ? LokiSettingStatus.EndpointMissing : LokiSettingStatus.Disabled);
        }

        if (!TryParseEndpoint(uri, out var endpoint))
        {
            return LokiSettingState.Create(LokiSettingStatus.EndpointInvalid);
        }

        if (!hasAuthorization)
        {
            return LokiSettingState.Create(LokiSettingStatus.AuthorizationMissing);
        }

        return IsUsableAuthorization(authorization)
            ? LokiSettingState.Create(endpoint!, authorization!)
            : LokiSettingState.Create(LokiSettingStatus.AuthorizationInvalid);
    }

    public static bool TryParseEndpoint(string? value, out Uri? endpoint)
    {
        endpoint = null;
        if (string.IsNullOrWhiteSpace(value) ||
            !Uri.TryCreate(value.Trim(), UriKind.Absolute, out var parsed) ||
            parsed.Scheme != Uri.UriSchemeHttps ||
            string.IsNullOrEmpty(parsed.Host) ||
            !string.IsNullOrEmpty(parsed.UserInfo) ||
            !string.IsNullOrEmpty(parsed.Query) ||
            !string.IsNullOrEmpty(parsed.Fragment))
        {
            return false;
        }

        endpoint = parsed;
        return true;
    }

    public static bool IsUsableAuthorization(string? value) =>
        value is { Length: >= 1 and <= MaximumAuthorizationLength } &&
        !string.IsNullOrWhiteSpace(value) &&
        !value.Any(char.IsControl);
}
