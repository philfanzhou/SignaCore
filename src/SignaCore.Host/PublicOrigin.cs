namespace SignaCore.Host;

/// <summary>
/// Resolves the externally reachable origin used to build discovery URLs.
/// <para>
/// The previous implementation composed <c>scheme://host:{Endpoints:Http}</c>, which produced wrong
/// URLs behind any TLS-terminating proxy: a request to <c>https://id.example.com</c> advertised
/// <c>https://id.example.com:5002/...</c>. Deployments behind a proxy set
/// <c>Endpoints:PublicBaseUrl</c>; otherwise the origin comes from the request itself, which is
/// correct for direct access. Forwarded headers are deliberately not trusted implicitly — an
/// attacker-controlled <c>X-Forwarded-Host</c> would otherwise steer clients to a foreign JWKS.
/// </para>
/// <para>
/// Since first-run setup collects the canonical public base URL and stores it in
/// <c>system_settings</c>, the configured branch is the normal one; the request-derived fallback now
/// only covers a snapshot that predates the setting.
/// </para>
/// </summary>
public static class PublicOrigin
{
    public const string ConfigurationKey = "Endpoints:PublicBaseUrl";

    public static string Resolve(HttpRequest request, IConfiguration configuration)
    {
        var configured = configuration[ConfigurationKey];
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured.Trim().TrimEnd('/');
        }

        // Request.Host already carries the port when it is not the scheme default, and PathBase
        // carries any reverse-proxy path prefix the host was told about.
        return $"{request.Scheme}://{request.Host.Value}{request.PathBase.Value}".TrimEnd('/');
    }
}
