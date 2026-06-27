using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace QuantumZhou.Identity.Client.Tests;

/// <summary>
/// Tests the JWT Bearer authentication pipeline configured by <see cref="ServiceCollectionExtensions.AddIdentityClient"/>.
/// Verifies that the OnMessageReceived event correctly fetches JWKS keys via JwksFetcher
/// and the middleware uses them to validate tokens.
/// This covers the DocLibrary JWKS auth scenario (E2E doc 07) and all services
/// using AddIdentityClient, since the auth pipeline is shared infrastructure.
/// </summary>
public class JwksAuthPipelineTests : IDisposable
{
    private readonly RSA _rsa;
    private readonly string _kid;
    private readonly HttpClient _mockJwksClient;
    private readonly TestServer _server;
    private readonly HttpClient _client;

    public JwksAuthPipelineTests()
    {
        _rsa = RSA.Create(2048);
        _kid = "test-key-" + Guid.NewGuid().ToString("N");

        var jwksJson = BuildJwksJson();
        _mockJwksClient = new HttpClient(new MockJwksHandler(jwksJson))
        {
            Timeout = TimeSpan.FromSeconds(5)
        };

        _server = CreateTestServer();
        _client = _server.CreateClient();
    }

    private string BuildJwksJson()
    {
        var parameters = _rsa.ExportParameters(false);
        return JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    kid = _kid,
                    alg = "RS256",
                    n = Base64UrlEncode(parameters.Modulus!),
                    e = Base64UrlEncode(parameters.Exponent!)
                }
            }
        });
    }

    private TestServer CreateTestServer()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Identity:JwksEndpoint"] = "http://mock/jwks",
                ["Identity:JwtIssuer"] = "QuantumZhou.Identity",
                ["Identity:JwtAudience"] = "QuantumZhou.microservices",
            })
            .Build();

        var builder = new WebHostBuilder()
            .UseTestServer()
            .ConfigureServices(services =>
            {
                services.AddLogging();
                services.AddRouting();
                services.AddIdentityClient(config);

                // Override JwksFetcher with mock HttpClient that returns our test public key
                services.RemoveAll<JwksFetcher>();
                services.AddSingleton(sp =>
                {
                    var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger<JwksFetcher>();
                    return new JwksFetcher("http://mock/jwks", logger, _mockJwksClient);
                });
            })
            .Configure(app =>
            {
                app.UseRouting();
                app.UseAuthentication();
                app.UseAuthorization();
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/protected", () => "ok").RequireAuthorization();
                });
            });

        return new TestServer(builder);
    }

    private string CreateJwt(
        DateTime? expires = null,
        string? issuer = null,
        string? audience = null,
        RSA? signingKey = null)
    {
        var key = new RsaSecurityKey(signingKey ?? _rsa) { KeyId = _kid };
        var handler = new JsonWebTokenHandler();
        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer ?? "QuantumZhou.Identity",
            Audience = audience ?? "QuantumZhou.microservices",
            Expires = expires ?? DateTime.UtcNow.AddMinutes(30),
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
        });
    }

    private HttpRequestMessage CreateRequest(string? token = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/protected");
        if (token != null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
        return request;
    }

    // ========== No token ==========

    [Fact]
    public async Task NoToken_Returns401()
    {
        var response = await _client.SendAsync(CreateRequest());
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ========== Valid JWT ==========

    [Fact]
    public async Task ValidJwt_Returns200()
    {
        var token = CreateJwt();
        var response = await _client.SendAsync(CreateRequest(token));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ========== Invalid token ==========

    [Fact]
    public async Task InvalidTokenString_Returns401()
    {
        var response = await _client.SendAsync(CreateRequest("invalid.token.here"));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task TokenSignedByWrongKey_Returns401()
    {
        using var wrongKey = RSA.Create(2048);
        var token = CreateJwt(signingKey: wrongKey);
        var response = await _client.SendAsync(CreateRequest(token));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ExpiredToken_Returns401()
    {
        var token = CreateJwt(expires: DateTime.UtcNow.AddMinutes(-10));
        var response = await _client.SendAsync(CreateRequest(token));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task WrongIssuer_Returns401()
    {
        var token = CreateJwt(issuer: "wrong-issuer");
        var response = await _client.SendAsync(CreateRequest(token));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task WrongAudience_Returns401()
    {
        var token = CreateJwt(audience: "wrong-audience");
        var response = await _client.SendAsync(CreateRequest(token));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ========== Helpers ==========

    private static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    public void Dispose()
    {
        _client?.Dispose();
        _server?.Dispose();
        _mockJwksClient?.Dispose();
        _rsa?.Dispose();
    }

    private class MockJwksHandler : HttpMessageHandler
    {
        private readonly string _jwksJson;

        public MockJwksHandler(string jwksJson) => _jwksJson = jwksJson;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_jwksJson, Encoding.UTF8, "application/json")
            };
            return Task.FromResult(response);
        }
    }
}
