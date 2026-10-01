using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Xunit;
using Microsoft.IdentityModel.Tokens;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// A minimal controllable SignaCore-shaped authority for the client package's contract tests:
/// Discovery, JWKS, an authorize endpoint whose echo of the handshake the test can corrupt
/// (state, iss, duplicated members, an error, a reused code), and a token endpoint that mints
/// the exact ID token the test case needs — correct, or deliberately wrong in iss, aud, nonce,
/// the signing key, or the response shape (missing members, wrong token_type, non-positive
/// expires_in, a non-JSON body). Every authorize and token request is recorded, so a test can
/// prove what was and was not sent, and that a code was presented exactly once.
/// </summary>
public sealed class FakeIdentityProvider : IAsyncDisposable
{
    public const string BaseAddress = "https://idp.localhost";
    public const string DefaultSubject = "client-pack-subject";
    public const string AccessTokenMaterial = "client-pack-access-token-material";

    private readonly IHost _host;
    private readonly AuthorityState _state;

    private FakeIdentityProvider(IHost host, TestServer server, AuthorityState state)
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

    public enum TokenResponseShape
    {
        Normal,
        MissingAccessToken,
        MissingIdToken,
        WrongTokenType,
        NonPositiveExpiresIn,
        NonJsonBody
    }

    public enum AuthorizeEcho
    {
        Normal,
        TamperState,
        WrongIss,
        OmitIss,
        DuplicateState,
        DuplicateCode,
        ErrorAccessDenied,
        ReuseCode
    }

    public TestServer Server { get; }

    public TokenDefect Defect
    {
        get => _state.Defect;
        set => _state.Defect = value;
    }

    public TokenResponseShape ResponseShape
    {
        get => _state.ResponseShape;
        set => _state.ResponseShape = value;
    }

    public AuthorizeEcho Echo
    {
        get => _state.Echo;
        set => _state.Echo = value;
    }

    /// <summary>The Discovery document's issuer; corrupting it breaks the start-time issuer check.</summary>
    public string DiscoveryIssuer
    {
        get => _state.DiscoveryIssuer;
        set => _state.DiscoveryIssuer = value;
    }

    /// <summary>Every authorize request's absolute URI, in order.</summary>
    public ConcurrentQueue<Uri> AuthorizeRequests => _state.AuthorizeRequests;

    /// <summary>Every code presented to the token endpoint, in order (replays included).</summary>
    public ConcurrentQueue<string> RedeemedCodes => _state.RedeemedCodes;

    /// <summary>Every Authorization header presented to the token endpoint, in order.</summary>
    public ConcurrentQueue<string?> TokenAuthorizationHeaders => _state.TokenAuthorizationHeaders;

    /// <summary>The nonce of the most recent authorize request.</summary>
    public string LastNonce => _state.LastNonce;

    public TaskCompletionSource HoldTokenRequests()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _state.TokenGate = gate;
        _state.TokenArrived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        return gate;
    }

    public Task TokenArrived => _state.TokenArrived?.Task ?? Task.CompletedTask;

    public static async Task<FakeIdentityProvider> StartAsync()
    {
        var state = new AuthorityState();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.WebHost.UseUrls(BaseAddress);

        var app = builder.Build();

        app.MapGet("/.well-known/openid-configuration", () => Results.Json(new
        {
            issuer = state.DiscoveryIssuer,
            authorization_endpoint = $"{BaseAddress}/authorize",
            token_endpoint = $"{BaseAddress}/token",
            userinfo_endpoint = $"{BaseAddress}/userinfo",
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
            state.AuthorizeRequests.Enqueue(new Uri(BaseAddress + http.Path + http.QueryString));
            state.LastNonce = http.Query["nonce"].ToString();
            var redirectUri = http.Query["redirect_uri"].ToString();
            var redirectState = http.Query["state"].ToString();
            var separator = redirectUri.Contains('?', StringComparison.Ordinal) ? '&' : '?';
            return state.Echo switch
            {
                AuthorizeEcho.ErrorAccessDenied => Results.Redirect(
                    $"{redirectUri}{separator}error=access_denied&state={Uri.EscapeDataString(redirectState)}&iss={state.DiscoveryIssuer}"),
                AuthorizeEcho.TamperState => Results.Redirect(
                    $"{redirectUri}{separator}code=fake-code&state={Uri.EscapeDataString("tampered-" + redirectState)}&iss={state.DiscoveryIssuer}"),
                AuthorizeEcho.WrongIss => Results.Redirect(
                    $"{redirectUri}{separator}code=fake-code&state={Uri.EscapeDataString(redirectState)}&iss=https://someone-else.example"),
                AuthorizeEcho.OmitIss => Results.Redirect(
                    $"{redirectUri}{separator}code=fake-code&state={Uri.EscapeDataString(redirectState)}"),
                AuthorizeEcho.DuplicateState => Results.Redirect(
                    $"{redirectUri}{separator}code=fake-code&state={Uri.EscapeDataString(redirectState)}&state=again&iss={state.DiscoveryIssuer}"),
                AuthorizeEcho.DuplicateCode => Results.Redirect(
                    $"{redirectUri}{separator}code=first&code=second&state={Uri.EscapeDataString(redirectState)}&iss={state.DiscoveryIssuer}"),
                AuthorizeEcho.ReuseCode => Results.Redirect(
                    $"{redirectUri}{separator}code=fixed-reused-code&state={Uri.EscapeDataString(redirectState)}&iss={state.DiscoveryIssuer}"),
                _ => Results.Redirect(
                    $"{redirectUri}{separator}code=fake-authority-code&state={Uri.EscapeDataString(redirectState)}&iss={state.DiscoveryIssuer}")
            };
        });

        app.MapPost("/token", async (HttpContext context) =>
        {
            var form = await context.Request.ReadFormAsync(TestContext.Current.CancellationToken);
            var code = form["code"].ToString();
            state.RedeemedCodes.Enqueue(code);
            state.TokenAuthorizationHeaders.Enqueue(
                context.Request.Headers.Authorization.ToString());

            if (state.TokenGate is { Task.IsCompleted: false } gate)
            {
                state.TokenArrived?.TrySetResult();
                await gate.Task.WaitAsync(context.RequestAborted);
            }

            // A code is single-use, exactly as the real token endpoint answers a replay.
            if (state.Echo == AuthorizeEcho.ReuseCode && state.RedeemedCodes.Count(c => c == code) > 1)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_grant" },
                    TestContext.Current.CancellationToken);
                return;
            }

            if (state.ResponseShape == TokenResponseShape.NonJsonBody)
            {
                context.Response.StatusCode = StatusCodes.Status200OK;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{ this is not a json object",
                    TestContext.Current.CancellationToken);
                return;
            }

            var payload = new Dictionary<string, object?>
            {
                ["token_type"] = state.ResponseShape == TokenResponseShape.WrongTokenType
                    ? "mac_message"
                    : "Bearer",
                ["expires_in"] = state.ResponseShape == TokenResponseShape.NonPositiveExpiresIn
                    ? 0
                    : 900,
                ["id_token"] = Mint(state)
            };
            if (state.ResponseShape != TokenResponseShape.MissingAccessToken)
            {
                payload["access_token"] = AccessTokenMaterial;
            }

            await Results.Json(payload).ExecuteAsync(context);
        });

        app.MapGet("/userinfo", () => Results.Json(new { sub = DefaultSubject }));

        await app.StartAsync(TestContext.Current.CancellationToken);
        var server = app.GetTestServer();
        server.BaseAddress = new Uri(BaseAddress);
        return new FakeIdentityProvider(app, server, state);

        static string Mint(AuthorityState state)
        {
            if (state.ResponseShape == TokenResponseShape.MissingIdToken)
            {
                return string.Empty;
            }

            var now = DateTimeOffset.UtcNow;
            var signingKey = state.Defect == TokenDefect.SigningKeyAbsentFromJwks
                ? state.UnlistedKey
                : state.SigningKey;
            var claims = new List<Claim>
            {
                new("sub", DefaultSubject),
                new("nonce", state.Defect == TokenDefect.WrongNonce
                    ? "a-nonce-that-was-never-requested"
                    : state.LastNonce),
                new("name", "client_pack_user")
            };
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = state.Defect == TokenDefect.WrongIssuer
                    ? "https://someone-else.example"
                    : BaseAddress,
                Audience = state.Defect == TokenDefect.WrongAudience
                    ? "a-different-client"
                    : "client-pack-app",
                IssuedAt = now.UtcDateTime,
                NotBefore = now.UtcDateTime,
                Expires = now.UtcDateTime.AddMinutes(5),
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
                Subject = new ClaimsIdentity(claims)
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
        public RsaSecurityKey SigningKey { get; } = CreateKey("client-pack-signing-key");

        public RsaSecurityKey UnlistedKey { get; } = CreateKey("client-pack-unlisted-key");

        public string SigningKeyId { get; } = "client-pack-signing-key";

        public TokenDefect Defect { get; set; }

        public TokenResponseShape ResponseShape { get; set; } = TokenResponseShape.Normal;

        public AuthorizeEcho Echo { get; set; }

        public string DiscoveryIssuer { get; set; } = BaseAddress;

        public string LastNonce { get; set; } = string.Empty;

        public TaskCompletionSource? TokenGate { get; set; }

        public TaskCompletionSource? TokenArrived { get; set; }

        public ConcurrentQueue<Uri> AuthorizeRequests { get; } = [];

        public ConcurrentQueue<string> RedeemedCodes { get; } = [];

        public ConcurrentQueue<string?> TokenAuthorizationHeaders { get; } = [];

        private static RsaSecurityKey CreateKey(string kid)
        {
            var rsa = RSA.Create(2048);
            return new RsaSecurityKey(rsa) { KeyId = kid };
        }
    }
}
