using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using SignaCore.Database;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host;

public class DiscoveryDocumentTests
{
    private static readonly string[] GrantTypes =
        [IdentityConstants.GrantTypeRefreshToken, IdentityConstants.GrantTypePassword, IdentityConstants.GrantTypeSms];

    /// <summary>
    /// Discovery points to the standards-conforming /oauth2/* endpoints rather than the legacy
    /// /api/auth/* endpoints because clients that consume discovery speak the standard protocol.
    /// </summary>
    [Fact]
    public void Create_BuildsEndpointsFromTheGivenOrigin()
    {
        var document = DiscoveryDocument.Create("https://id.example.com", "https://id.example.com/", GrantTypes);

        Assert.Equal("https://id.example.com/.well-known/jwks", document.JwksUri);
        Assert.Equal("https://id.example.com/oauth2/token", document.TokenEndpoint);
        Assert.Equal("https://id.example.com/oauth2/revoke", document.RevocationEndpoint);
    }

    /// <summary>
    /// grant_types_supported comes from the registered validators rather than a literal list, so this
    /// test fails if a grant is added without updating discovery. RFC 6749 §4.5 extension grants are
    /// advertised as absolute URIs.
    /// </summary>
    [Fact]
    public void Create_AdvertisesTheActualGrantTypesUnderTheirWireNames()
    {
        var document = DiscoveryDocument.Create("https://id.example.com", "https://id.example.com", GrantTypes);

        Assert.Equal(
            new[] { IdentityConstants.GrantTypePassword, IdentityConstants.GrantTypeRefreshToken, OAuthGrantTypes.Sms },
            document.GrantTypesSupported);
    }

    [Fact]
    public void Create_AdvertisesTheRegisteredClientAuthenticationMethods()
    {
        var document = DiscoveryDocument.Create("https://id.example.com", "https://id.example.com", GrantTypes);

        Assert.Equal(
            new[] { "client_secret_basic", "client_secret_post" },
            document.TokenEndpointAuthMethodsSupported);
    }

    /// <summary>No response type can be advertised without an authorization endpoint.</summary>
    [Fact]
    public void Create_DoesNotAdvertiseAnyResponseType()
    {
        var document = DiscoveryDocument.Create("https://id.example.com", "https://id.example.com", GrantTypes);

        Assert.Empty(document.ResponseTypesSupported);
    }

    [Fact]
    public void ToMetadata_UsesTheSpecifiedSnakeCaseNames()
    {
        var metadata = DiscoveryDocument
            .Create("https://id.example.com", "https://id.example.com", GrantTypes)
            .ToMetadata();

        Assert.Equal("https://id.example.com", metadata["issuer"]);
        Assert.Equal("https://id.example.com/.well-known/jwks", metadata["jwks_uri"]);
        Assert.Equal("https://id.example.com/oauth2/revoke", metadata["revocation_endpoint"]);
        Assert.Contains("grant_types_supported", metadata.Keys);
        Assert.Contains("token_endpoint_auth_methods_supported", metadata.Keys);
        Assert.Contains(IdentityConstants.ClaimClientId, (IReadOnlyList<string>)metadata["claims_supported"]);
    }

    [Fact]
    public void Resolve_WithoutConfiguration_UsesTheRequestOriginIncludingPortAndPathBase()
    {
        var request = new DefaultHttpContext().Request;
        request.Scheme = "https";
        request.Host = new HostString("id.example.com", 8443);
        request.PathBase = "/identity";

        Assert.Equal(
            "https://id.example.com:8443/identity",
            PublicOrigin.Resolve(request, Configuration()));
    }

    /// <summary>
    /// Regression: the old implementation appended Endpoints:Http and advertised an unreachable URL
    /// such as https://host:5002 when TLS terminated at a reverse proxy.
    /// </summary>
    [Fact]
    public void Resolve_DoesNotAppendTheInternalListenPort()
    {
        var request = new DefaultHttpContext().Request;
        request.Scheme = "https";
        request.Host = new HostString("id.example.com");

        var origin = PublicOrigin.Resolve(request, Configuration(("Endpoints:Http", "5002")));

        Assert.Equal("https://id.example.com", origin);
    }

    [Fact]
    public void Resolve_PrefersTheConfiguredPublicBaseUrl()
    {
        var request = new DefaultHttpContext().Request;
        request.Scheme = "http";
        request.Host = new HostString("10.0.0.5", 5002);

        var origin = PublicOrigin.Resolve(
            request,
            Configuration((PublicOrigin.ConfigurationKey, "https://id.example.com/")));

        Assert.Equal("https://id.example.com", origin);
    }

    [Fact]
    public void Resolve_TrimsConfiguredPublicBaseUrlWhitespace()
    {
        var request = new DefaultHttpContext().Request;

        var origin = PublicOrigin.Resolve(
            request,
            Configuration((PublicOrigin.ConfigurationKey, "  https://id.example.com/  ")));

        Assert.Equal("https://id.example.com", origin);
    }

    /// <summary>
    /// Forwarded headers are not implicitly trusted, so a forged X-Forwarded-Host cannot direct clients
    /// to an attacker's JWKS endpoint.
    /// </summary>
    [Fact]
    public void Resolve_IgnoresForwardedHeadersThatWereNotProcessedByTheHost()
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("id.example.com");
        context.Request.Headers["X-Forwarded-Host"] = "attacker.example.net";

        Assert.Equal("http://id.example.com", PublicOrigin.Resolve(context.Request, Configuration()));
    }

    // The rules that used to live in PublicOrigin.Validate — absolute URL, no user information,
    // query, or fragment, HTTPS outside Development — are now enforced by
    // SettingsSnapshotValidator over the whole snapshot, and are covered by its own tests. Keeping a
    // second entry point for the same rules would let the two drift apart.

    private static IConfiguration Configuration(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(item => new KeyValuePair<string, string?>(item.Key, item.Value)))
            .Build();
}
