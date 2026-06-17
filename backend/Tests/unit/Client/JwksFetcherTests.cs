using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace QuantumZhou.Identity.Client.Tests;

public class JwksFetcherTests
{
    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    private static (string Kid, string N, string E, RSA PrivateKey) GenerateTestKey()
    {
        var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(true);
        return (
            Kid: Guid.NewGuid().ToString(),
            N: Base64UrlEncode(parameters.Modulus!),
            E: Base64UrlEncode(parameters.Exponent!),
            PrivateKey: rsa
        );
    }

    private static string BuildJwksJson(params (string Kid, string N, string E)[] keys)
    {
        var jwksKeys = keys.Select(k => new
        {
            kty = "RSA",
            use = "sig",
            kid = k.Kid,
            alg = "RS256",
            n = k.N,
            e = k.E
        });
        return JsonSerializer.Serialize(new { keys = jwksKeys });
    }

    private static JwksFetcher CreateFetcher(string responseBody, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        var handler = new MockHttpHandler(responseBody, statusCode);
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        return new JwksFetcher("http://mock/.well-known/jwks", NullLogger<JwksFetcher>.Instance, client);
    }

    // ========== 解析正常 JWKS ==========

    [Fact]
    public async Task ParsesValidJwks_ReturnsRsaKey()
    {
        var (kid, n, e, _) = GenerateTestKey();
        var fetcher = CreateFetcher(BuildJwksJson((kid, n, e)));

        var keys = await fetcher.GetSigningKeysAsync();

        Assert.Single(keys);
        Assert.IsType<RsaSecurityKey>(keys[0]);
        Assert.Equal(kid, keys[0].KeyId);
    }

    [Fact]
    public async Task MultipleKeys_ReturnsAll()
    {
        var key1 = GenerateTestKey();
        var key2 = GenerateTestKey();
        var fetcher = CreateFetcher(BuildJwksJson(
            (key1.Kid, key1.N, key1.E),
            (key2.Kid, key2.N, key2.E)));

        var keys = await fetcher.GetSigningKeysAsync();

        Assert.Equal(2, keys.Count);
        Assert.Contains(keys, k => k.KeyId == key1.Kid);
        Assert.Contains(keys, k => k.KeyId == key2.Kid);
    }

    [Fact]
    public async Task EmptyKeysArray_ReturnsEmpty()
    {
        var json = JsonSerializer.Serialize(new { keys = Array.Empty<object>() });
        var fetcher = CreateFetcher(json);

        var keys = await fetcher.GetSigningKeysAsync();

        Assert.Empty(keys);
    }

    // ========== 错误处理 ==========

    [Fact]
    public async Task HttpError_ReturnsEmpty()
    {
        var fetcher = CreateFetcher("Internal Server Error", HttpStatusCode.InternalServerError);

        var keys = await fetcher.GetSigningKeysAsync();

        Assert.Empty(keys);
    }

    [Fact]
    public async Task InvalidJson_ReturnsEmpty()
    {
        var fetcher = CreateFetcher("{invalid json", HttpStatusCode.OK);

        var keys = await fetcher.GetSigningKeysAsync();

        Assert.Empty(keys);
    }

    [Fact]
    public async Task MissingKeysField_ReturnsEmpty()
    {
        var json = JsonSerializer.Serialize(new { not_keys = "value" });
        var fetcher = CreateFetcher(json);

        var keys = await fetcher.GetSigningKeysAsync();

        Assert.Empty(keys);
    }

    [Fact]
    public async Task MissingModulus_SkipsBadKey_KeepsGoodKey()
    {
        var key1 = GenerateTestKey();
        var jwksObj = new
        {
            keys = new object[]
            {
                new { kty = "RSA", use = "sig", kid = key1.Kid, alg = "RS256", n = key1.N, e = key1.E },
                new { kty = "RSA", use = "sig", kid = "bad-key", alg = "RS256", e = "AQAB" }
            }
        };
        var fetcher = CreateFetcher(JsonSerializer.Serialize(jwksObj));

        var keys = await fetcher.GetSigningKeysAsync();

        Assert.Single(keys);
        Assert.Equal(key1.Kid, keys[0].KeyId);
    }

    // ========== 缓存行为 ==========

    [Fact]
    public async Task CachesResult_SecondCallReturnsCached()
    {
        var (kid, n, e, _) = GenerateTestKey();
        int callCount = 0;
        var handler = new MockHttpHandler(BuildJwksJson((kid, n, e)), HttpStatusCode.OK, () => callCount++);
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        var fetcher = new JwksFetcher("http://mock/jwks", NullLogger<JwksFetcher>.Instance, client);

        var keys1 = await fetcher.GetSigningKeysAsync();
        var keys2 = await fetcher.GetSigningKeysAsync();

        Assert.Single(keys1);
        Assert.Single(keys2);
        Assert.Equal(1, callCount); // 第二次走缓存
    }

    [Fact]
    public async Task ErrorDoesNotCache_NextCallRetries()
    {
        int callCount = 0;
        var handler = new MockHttpHandler("error", HttpStatusCode.InternalServerError, () => callCount++);
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        var fetcher = new JwksFetcher("http://mock/jwks", NullLogger<JwksFetcher>.Instance, client);

        var keys1 = await fetcher.GetSigningKeysAsync();
        var keys2 = await fetcher.GetSigningKeysAsync();

        Assert.Empty(keys1);
        Assert.Empty(keys2);
        Assert.Equal(2, callCount); // 错误不缓存
    }

    [Fact]
    public async Task ClearCache_ForcesRefresh()
    {
        var (kid, n, e, _) = GenerateTestKey();
        int callCount = 0;
        var handler = new MockHttpHandler(BuildJwksJson((kid, n, e)), HttpStatusCode.OK, () => callCount++);
        var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        var fetcher = new JwksFetcher("http://mock/jwks", NullLogger<JwksFetcher>.Instance, client);

        await fetcher.GetSigningKeysAsync();
        fetcher.ClearCache();
        await fetcher.GetSigningKeysAsync();

        Assert.Equal(2, callCount);
    }

    // ========== RSA 密钥可用于验签 ==========

    [Fact]
    public async Task RsaKey_CanVerifySignature()
    {
        var (kid, n, e, privateKey) = GenerateTestKey();
        var fetcher = CreateFetcher(BuildJwksJson((kid, n, e)));

        var keys = await fetcher.GetSigningKeysAsync();
        var rsaKey = Assert.IsType<RsaSecurityKey>(keys[0]);

        var data = Encoding.UTF8.GetBytes("test data");
        var signature = privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        Assert.True(rsaKey.Rsa!.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    // ========== Mock HttpMessageHandler ==========

    private class MockHttpHandler : HttpMessageHandler
    {
        private readonly string _responseBody;
        private readonly HttpStatusCode _statusCode;
        private readonly Action? _onRequest;

        public MockHttpHandler(string responseBody, HttpStatusCode statusCode, Action? onRequest = null)
        {
            _responseBody = responseBody;
            _statusCode = statusCode;
            _onRequest = onRequest;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _onRequest?.Invoke();
            var response = new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_responseBody, Encoding.UTF8, "application/json")
            };
            return Task.FromResult(response);
        }
    }
}
