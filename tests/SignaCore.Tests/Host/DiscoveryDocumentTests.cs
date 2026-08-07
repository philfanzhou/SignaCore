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
    /// 发现文档指向符合标准的 /oauth2/* 端点，而不是历史的 /api/auth/*——
    /// 读发现文档的客户端只会说标准协议。
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
    /// 元数据里的 grant_types_supported 来自实际注册的校验器，不是字面量：
    /// 新增一种 grant 而忘了更新文档，这条会挂。扩展 grant 按 RFC 6749 §4.5 用绝对 URI 广播。
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

    /// <summary>没有 authorization endpoint，就不能声明任何 response_type。</summary>
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
    /// 回归：旧实现把 Endpoints:Http 拼进 URL，TLS 终结在反代上时会广播
    /// https://host:5002 这种打不通的地址。
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

    /// <summary>转发头不被隐式信任：伪造 X-Forwarded-Host 不能把客户端引到别处的 JWKS。</summary>
    [Fact]
    public void Resolve_IgnoresForwardedHeadersThatWereNotProcessedByTheHost()
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("id.example.com");
        context.Request.Headers["X-Forwarded-Host"] = "attacker.example.net";

        Assert.Equal("http://id.example.com", PublicOrigin.Resolve(context.Request, Configuration()));
    }

    [Theory]
    [InlineData("not-a-url")]
    [InlineData("ftp://id.example.com")]
    public void Validate_RejectsANonHttpPublicBaseUrl(string value)
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => PublicOrigin.Validate(Configuration((PublicOrigin.ConfigurationKey, value))));

        Assert.Contains(PublicOrigin.ConfigurationKey, exception.Message);
    }

    [Fact]
    public void Validate_AcceptsAnAbsentPublicBaseUrl()
    {
        PublicOrigin.Validate(Configuration());
    }

    private static IConfiguration Configuration(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(item => new KeyValuePair<string, string?>(item.Key, item.Value)))
            .Build();
}
