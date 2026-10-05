using System.Collections.Frozen;
using System.Globalization;
using ServiceMantle.Configuration;

namespace SignaCore.Host.Security;

/// <summary>Immutable per-host policy from the activated shared snapshot, effective until restart.</summary>
internal sealed class HostedLoginHttpTestPolicy
{
    private readonly FrozenSet<string> _origins;
    private HostedLoginHttpTestPolicy(HashSet<string> origins) => _origins = origins.ToFrozenSet(StringComparer.Ordinal);
    internal SignaCore.Domain.Validators.OidcRedirectUriPolicy ToRedirectUriPolicy(bool isDevelopment) => new(isDevelopment, _origins);
    internal bool Enabled => _origins.Count != 0;
    internal bool ContainsOrigin(string origin) =>
        HostedLoginHttpTestOrigins.TryCanonicalize(origin, out var canonical) && _origins.Contains(canonical);

    internal static HostedLoginHttpTestPolicy Create(ServiceSettingSnapshot snapshot, IHostEnvironment environment)
    {
        var json = snapshot.Values.TryGetValue(HostedLoginHttpTestOrigins.SettingKey, out var value) && value.HasValue
            ? value.GetJson().GetRawText() : null;
        if (!HostedLoginHttpTestOrigins.TryParseJson(json, out var origins))
            throw new InvalidOperationException("The shared hosted-login HTTP test origins are invalid.");
        var policy = new HostedLoginHttpTestPolicy(origins);
        if (!policy.Enabled) return policy;
        if (!string.Equals(environment.EnvironmentName, "Testing", StringComparison.Ordinal))
            throw new InvalidOperationException("HTTP hosted-login test origins require the Testing environment.");

        var publicBaseUrl = snapshot.Values["endpoints.public_base_url"].GetString();
        var uri = new Uri(publicBaseUrl, UriKind.Absolute);
        if (uri.Scheme == Uri.UriSchemeHttp)
        {
            // Preserve the literal spelling until the strict origin parser has checked it:
            // System.Uri alone canonicalizes IPv4 aliases that the allowlist forbids.
            var authority = publicBaseUrl.Trim()[7..].Split('/')[0];
            var hasPort = authority.StartsWith('[') ? !authority.EndsWith(']') : authority.Contains(':');
            if (!hasPort) authority += ":" + uri.Port.ToString(CultureInfo.InvariantCulture);
            if (!policy.ContainsOrigin("http://" + authority))
                throw new InvalidOperationException("The HTTP public base URL authority must be in the shared hosted-login test origins.");
        }
        return policy;
    }
}
