using System.Text.Json;
using Microsoft.Extensions.Options;
using SignaCore.Client.AspNetCore;

namespace SignaCore.ReferenceBff;

/// <summary>
/// One read of the authority's public Discovery document: the endpoint-shaped metadata the
/// sample's own surfaces need. The sign-in handshake's Discovery is the client package's; this
/// reader exists only for the surfaces the package does not own — the UserInfo integration behind
/// <c>/bff/me</c> and <c>/bff/admin</c>, and the diagnostics page — so those keep resolving every
/// endpoint from Discovery instead of hardcoding paths. It reads the document per call and
/// caches nothing; a failed or unusable document throws, and the callers map that to their own
/// bounded answers.
/// </summary>
internal sealed class BffAuthorityMetadataReader(
    System.Net.Http.IHttpClientFactory httpClientFactory,
    IOptionsMonitor<SignaCoreHostedLoginOptions> loginOptions)
{
    private const string DiscoveryDocumentPath = "/.well-known/openid-configuration";

    /// <summary>The public Discovery metadata of the configured authority.</summary>
    /// <param name="cancellationToken">Propagates the caller's cancellation.</param>
    /// <exception cref="HttpRequestException">The document could not be read.</exception>
    /// <exception cref="InvalidOperationException">The document is not a usable object.</exception>
    public async Task<BffAuthorityMetadata> ReadAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var authority = loginOptions.CurrentValue.Authority!.TrimEnd('/');
        using var client = httpClientFactory.CreateClient(BffIdentityCheckService.UserInfoClientName);
        using var response = await client.GetAsync(authority + DiscoveryDocumentPath, cancellationToken);
        response.EnsureSuccessStatusCode();

        using var document = await JsonDocument.ParseAsync(
            await response.Content.ReadAsStreamAsync(cancellationToken),
            cancellationToken: cancellationToken);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("The discovery document is not a JSON object.");
        }

        return new BffAuthorityMetadata(
            Issuer: ReadString(document.RootElement, "issuer"),
            AuthorizationEndpoint: ReadString(document.RootElement, "authorization_endpoint"),
            TokenEndpoint: ReadString(document.RootElement, "token_endpoint"),
            JwksUri: ReadString(document.RootElement, "jwks_uri"),
            UserInfoEndpoint: ReadString(document.RootElement, "userinfo_endpoint"));
    }

    private static string? ReadString(JsonElement root, string member) =>
        root.TryGetProperty(member, out var value)
            && value.ValueKind == JsonValueKind.String
            && !string.IsNullOrEmpty(value.GetString())
            ? value.GetString()
            : null;
}

/// <summary>The endpoint-shaped Discovery metadata the sample reads for its own surfaces.</summary>
internal sealed record BffAuthorityMetadata(
    string? Issuer,
    string? AuthorizationEndpoint,
    string? TokenEndpoint,
    string? JwksUri,
    string? UserInfoEndpoint);
