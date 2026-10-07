using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// One authority's resolved endpoints and signing keys, taken from its Discovery document and
/// JWKS. The configured Authority's address and the document's <c>issuer</c> must denote the same
/// origin; every endpoint must be absolute HTTPS (or the allowed loopback form).
/// </summary>
internal sealed record SignaCoreAuthorityConfiguration(
    string Issuer,
    string AuthorizationEndpoint,
    string TokenEndpoint,
    string JwksUri,
    IList<SecurityKey> SigningKeys);

/// <summary>
/// Reads and caches the authority's Discovery document and JWKS. Endpoint-shaped values are never
/// hardcoded anywhere else in the package; a refresh happens at most once per interval and a
/// failed refresh is a hard failure — the package never serves a stale authority configuration to
/// keep a sign-in going.
/// </summary>
internal sealed class SignaCoreDiscoveryClient(
    System.Net.Http.IHttpClientFactory httpClientFactory,
    IOptionsMonitor<SignaCoreHostedLoginOptions> options,
    IHostEnvironment environment,
    TimeProvider timeProvider,
    ILogger<SignaCoreDiscoveryClient> logger)
{
    internal static readonly TimeSpan RefreshInterval = TimeSpan.FromHours(1);

    private sealed record CacheEntry(
        SignaCoreAuthorityConfiguration Configuration,
        DateTimeOffset ValidUntil);

    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private CacheEntry? _cached;

    /// <summary>Throws when the document is unreachable or does not validate.</summary>
    internal async Task<SignaCoreAuthorityConfiguration> GetConfigurationAsync(
        CancellationToken cancellationToken)
    {
        var cached = Volatile.Read(ref _cached);
        if (cached is { } current && current.ValidUntil > timeProvider.GetUtcNow())
        {
            return current.Configuration;
        }

        await _refreshLock.WaitAsync(cancellationToken);
        try
        {
            cached = Volatile.Read(ref _cached);
            if (cached is { } current2 && current2.ValidUntil > timeProvider.GetUtcNow())
            {
                return current2.Configuration;
            }

            var configuration = await FetchAsync(cancellationToken);
            Volatile.Write(ref _cached, new CacheEntry(
                configuration, timeProvider.GetUtcNow() + RefreshInterval));
            return configuration;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private async Task<SignaCoreAuthorityConfiguration> FetchAsync(CancellationToken cancellationToken)
    {
        var authority = options.CurrentValue.Authority!.TrimEnd('/');
        using var client = httpClientFactory.CreateClient(SignaCoreHostedLoginDefaults.HttpClientName);

        using var discoveryResponse = await client.GetAsync(
            authority + "/.well-known/openid-configuration", cancellationToken);
        discoveryResponse.EnsureSuccessStatusCode();
        using var document = await JsonDocument.ParseAsync(
            await discoveryResponse.Content.ReadAsStreamAsync(cancellationToken),
            cancellationToken: cancellationToken);
        var root = document.RootElement;

        string? issuer = null, authorizationEndpoint = null, tokenEndpoint = null, jwksUri = null;
        if (root.ValueKind == JsonValueKind.Object)
        {
            issuer = ReadOptionalString(root, "issuer");
            authorizationEndpoint = ReadOptionalString(root, "authorization_endpoint");
            tokenEndpoint = ReadOptionalString(root, "token_endpoint");
            jwksUri = ReadOptionalString(root, "jwks_uri");
        }

        if (string.IsNullOrEmpty(issuer)
            || string.IsNullOrEmpty(authorizationEndpoint)
            || string.IsNullOrEmpty(tokenEndpoint)
            || string.IsNullOrEmpty(jwksUri))
        {
            throw new SignaCoreAuthorityDocumentException(
                "The discovery document is missing a required member.");
        }

        if (!SignaCoreAuthorityUriRules.SameOrigin(options.CurrentValue.Authority, issuer))
        {
            throw new SignaCoreAuthorityDocumentException(
                "The discovery document issuer does not match the configured authority.");
        }

        var environmentName = environment.EnvironmentName;
        var allowInsecureLoopback = environmentName == Environments.Development
            || environmentName == "Testing";
        foreach (var endpoint in new[] { authorizationEndpoint, tokenEndpoint, jwksUri })
        {
            if (!SignaCoreAuthorityUriRules.IsAcceptableEndpointUri(endpoint, allowInsecureLoopback))
            {
                throw new SignaCoreAuthorityDocumentException(
                    "A discovery endpoint is not an absolute HTTPS URI.");
            }

            // Every endpoint must also sit on the verified issuer's own origin (scheme, host,
            // port — the path may differ, SignaCore publishes endpoints under the issuer's root):
            // a tampered document must not move authorization, token, or key traffic to a second
            // host the consumer never chose. There is no partial acceptance.
            if (!SignaCoreAuthorityUriRules.SameOriginTriple(issuer, endpoint))
            {
                throw new SignaCoreAuthorityDocumentException(
                    "A discovery endpoint is not same-origin with the issuer.");
            }
        }

        using var jwksResponse = await client.GetAsync(jwksUri, cancellationToken);
        jwksResponse.EnsureSuccessStatusCode();
        var jwks = JsonWebKeySet.Create(
            await jwksResponse.Content.ReadAsStringAsync(cancellationToken));
        var signingKeys = jwks.GetSigningKeys();
        if (signingKeys.Count == 0)
        {
            throw new SignaCoreAuthorityDocumentException("The authority published no signing keys.");
        }

        logger.LogDebug("SignaCore authority configuration refreshed.");

        return new SignaCoreAuthorityConfiguration(
            issuer,
            authorizationEndpoint,
            tokenEndpoint,
            jwksUri,
            signingKeys);
    }

    private static string? ReadOptionalString(JsonElement root, string member) =>
        root.TryGetProperty(member, out var value)
            && value.ValueKind == JsonValueKind.String
            && !string.IsNullOrEmpty(value.GetString())
            ? value.GetString()
            : null;
}

/// <summary>
/// The authority's Discovery document or JWKS could not be read or did not validate. The message
/// carries no document content and no configured value.
/// </summary>
internal sealed class SignaCoreAuthorityDocumentException(string message) : Exception(message);
