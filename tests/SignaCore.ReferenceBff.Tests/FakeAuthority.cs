using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace SignaCore.ReferenceBff.Tests;

/// <summary>
/// A minimal controllable OpenID Connect authority for the reference BFF's token-validation
/// contract: Discovery, JWKS, an authorize endpoint that echoes the caller's <c>state</c>, and a
/// token endpoint that mints the exact ID token the test case needs — correct, or deliberately
/// wrong in <c>iss</c>, <c>aud</c>, <c>nonce</c>, or signed by a key absent from JWKS. The
/// authority records every token request, so a test can prove that a rejected callback never
/// started an exchange.
/// </summary>
public sealed class FakeAuthority : IAsyncDisposable
{
    public const string BaseAddress = "https://idp.localhost";

    private readonly IHost _host;
    private readonly AuthorityState _state;

    private FakeAuthority(IHost host, TestServer server, AuthorityState state)
    {
        _host = host;
        Server = server;
        _state = state;
    }

    public enum TokenDefect
    {
        None,
        WrongIssuer,
        WrongAudience,
        WrongNonce,
        SigningKeyAbsentFromJwks
    }

    public TestServer Server { get; }

    public TokenDefect Defect
    {
        get => _state.Defect;
        set => _state.Defect = value;
    }

    /// <summary>Every code presented to the token endpoint, in order.</summary>
    public ConcurrentBag<string> RedeemedCodes => _state.RedeemedCodes;

    public static async Task<FakeAuthority> StartAsync()
    {
        var state = new AuthorityState();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.WebHost.UseUrls(BaseAddress);

        var app = builder.Build();

        app.MapGet("/.well-known/openid-configuration", () => Results.Json(new
        {
            issuer = BaseAddress,
            authorization_endpoint = $"{BaseAddress}/authorize",
            token_endpoint = $"{BaseAddress}/token",
            jwks_uri = $"{BaseAddress}/jwks",
            response_types_supported = new[] { "code" },
            subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" },
            code_challenge_methods_supported = new[] { "S256" }
        }));

        app.MapGet("/jwks", () =>
        {
            var parameters = state.SigningKey.Rsa.ExportParameters(false);
            return Results.Json(new
            {
                keys = new object[]
                {
                    new
                    {
                        kty = "RSA",
                        use = "sig",
                        alg = "RS256",
                        kid = state.SigningKeyId,
                        n = Base64UrlEncoder.Encode(parameters.Modulus!),
                        e = Base64UrlEncoder.Encode(parameters.Exponent!)
                    }
                }
            });
        });

        app.MapGet("/authorize", (HttpRequest http) =>
        {
            var redirectUri = http.Query["redirect_uri"].ToString();
            var redirectState = http.Query["state"].ToString();
            state.LastNonce = http.Query["nonce"].ToString();
            var separator = redirectUri.Contains('?', StringComparison.Ordinal) ? '&' : '?';
            return Results.Redirect(
                $"{redirectUri}{separator}code=fake-authority-code&state={Uri.EscapeDataString(redirectState)}&iss={BaseAddress}");
        });

        app.MapPost("/token", async (HttpContext context) =>
        {
            var form = await context.Request.ReadFormAsync(TestContext.Current.CancellationToken);
            state.RedeemedCodes.Add(form["code"].ToString());
            Results.Json(new
            {
                access_token = "opaque-access-token-material",
                token_type = "Bearer",
                expires_in = 900,
                id_token = Mint(state)
            }).ExecuteAsync(context);
        });

        await app.StartAsync(TestContext.Current.CancellationToken);
        var server = app.GetTestServer();
        server.BaseAddress = new Uri(BaseAddress);
        return new FakeAuthority(app, server, state);

        static string Mint(AuthorityState state)
        {
            var now = DateTimeOffset.UtcNow;
            var signingKey = state.Defect == TokenDefect.SigningKeyAbsentFromJwks
                ? state.UnlistedKey
                : state.SigningKey;
            var claims = new List<System.Security.Claims.Claim>
            {
                new("sub", "fake-authority-subject"),
                new("nonce", state.Defect == TokenDefect.WrongNonce
                    ? "a-nonce-that-was-never-requested"
                    : state.LastNonce)
            };
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = state.Defect == TokenDefect.WrongIssuer
                    ? "https://someone-else.example"
                    : BaseAddress,
                Audience = state.Defect == TokenDefect.WrongAudience
                    ? "a-different-client"
                    : "reference-bff",
                IssuedAt = now.UtcDateTime,
                NotBefore = now.UtcDateTime,
                Expires = now.UtcDateTime.AddMinutes(5),
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
                Subject = new System.Security.Claims.ClaimsIdentity(claims)
            };
            return new JwtSecurityTokenHandler().CreateEncodedJwt(descriptor);
        }
    }

    public HttpClient CreateClient() => Server.CreateClient();

    public async ValueTask DisposeAsync()
    {
        await _host.StopAsync(TimeSpan.FromSeconds(5));
        _host.Dispose();
    }

    private sealed class AuthorityState
    {
        public RsaSecurityKey SigningKey { get; } = CreateKey("fake-authority-signing-key");

        public RsaSecurityKey UnlistedKey { get; } = CreateKey("fake-authority-unlisted-key");

        public string SigningKeyId { get; } = "fake-authority-signing-key";

        public TokenDefect Defect { get; set; }

        public string LastNonce { get; set; } = string.Empty;

        public ConcurrentBag<string> RedeemedCodes { get; } = [];

        private static RsaSecurityKey CreateKey(string kid)
        {
            var rsa = RSA.Create(2048);
            return new RsaSecurityKey(rsa) { KeyId = kid };
        }
    }
}
