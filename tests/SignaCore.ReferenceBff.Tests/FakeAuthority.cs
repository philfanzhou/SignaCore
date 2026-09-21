using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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
/// contract: Discovery, JWKS, an authorize endpoint that echoes the caller's <c>state</c>, a
/// token endpoint that mints the exact ID token the test case needs — correct, or deliberately
/// wrong in <c>iss</c>, <c>aud</c>, <c>nonce</c>, missing/duplicated <c>sub</c>, or signed by a
/// key absent from JWKS — and a UserInfo endpoint whose answer (or refusal to answer) the test
/// controls, including a deterministic hold for cancellation boundaries. The authority records
/// every token and UserInfo request, so a test can prove what was and was not called.
/// </summary>
public sealed class FakeAuthority : IAsyncDisposable
{
    public const string BaseAddress = "https://idp.localhost";
    public const string DefaultSubject = "fake-authority-subject";

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

    /// <summary>How the minted ID token carries its subject claim.</summary>
    public enum TokenSubjectMode
    {
        /// <summary>Exactly one non-empty <c>sub</c> claim (the default).</summary>
        Single,

        /// <summary>No <c>sub</c> claim at all.</summary>
        Missing,

        /// <summary>Two <c>sub</c> claims with different values.</summary>
        Duplicate
    }

    /// <summary>What the UserInfo endpoint answers.</summary>
    public enum UserInfoResponse
    {
        /// <summary>A success JSON object whose single string <c>sub</c> is <see cref="Subject"/>.</summary>
        Valid,

        /// <summary>A success JSON object carrying a different single string <c>sub</c>.</summary>
        SubjectMismatch,

        /// <summary>A success JSON object with no <c>sub</c> member.</summary>
        SubjectMissing,

        /// <summary>A success JSON object with two <c>sub</c> members.</summary>
        SubjectDuplicate,

        /// <summary>A success JSON object whose <c>sub</c> is a number.</summary>
        SubjectNonString,

        /// <summary>A success response whose body is not JSON at all.</summary>
        InvalidJson,

        /// <summary>A plain <c>500</c>.</summary>
        InternalError,

        /// <summary>A plain <c>401</c> — the upstream identity session is gone.</summary>
        Unauthorized
    }

    public TestServer Server { get; }

    public TokenDefect Defect
    {
        get => _state.Defect;
        set => _state.Defect = value;
    }

    public TokenSubjectMode SubjectMode
    {
        get => _state.SubjectMode;
        set => _state.SubjectMode = value;
    }

    /// <summary>The subject the ID token and the UserInfo endpoint assert.</summary>
    public string Subject
    {
        get => _state.Subject;
        set => _state.Subject = value;
    }

    /// <summary>Additional claims minted into the ID token (for example a generic admin claim).</summary>
    public IList<Claim> ExtraIdTokenClaims => _state.ExtraIdTokenClaims;

    public UserInfoResponse UserInfoMode
    {
        get => _state.UserInfoMode;
        set => _state.UserInfoMode = value;
    }

    /// <summary>
    /// When Discovery omits the UserInfo endpoint entirely (<c>null</c> in the document).
    /// </summary>
    public bool OmitUserInfoEndpoint
    {
        get => _state.OmitUserInfoEndpoint;
        set => _state.OmitUserInfoEndpoint = value;
    }

    /// <summary>Every code presented to the token endpoint, in order.</summary>
    public ConcurrentBag<string> RedeemedCodes => _state.RedeemedCodes;

    /// <summary>How many UserInfo requests reached the endpoint.</summary>
    public int UserInfoCalls => _state.UserInfoCalls;

    /// <summary>
    /// Holds every arriving UserInfo request on a deterministic gate until the test releases it
    /// (or the request is abandoned). Returns the gate the test controls.
    /// </summary>
    public TaskCompletionSource HoldUserInfoRequests()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _state.UserInfoGate = gate;
        _state.UserInfoArrived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        return gate;
    }

    /// <summary>
    /// Completes when a held UserInfo request has arrived and parked on the gate — the arrival
    /// evidence a test awaits before abandoning the request, instead of a timer.
    /// </summary>
    public Task UserInfoArrived => _state.UserInfoArrived?.Task ?? Task.CompletedTask;

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
            userinfo_endpoint = state.OmitUserInfoEndpoint
                ? null
                : $"{BaseAddress}/userinfo",
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
            await Results.Json(new
            {
                access_token = "opaque-access-token-material",
                token_type = "Bearer",
                expires_in = 900,
                id_token = Mint(state)
            }).ExecuteAsync(context);
        });

        app.MapGet("/userinfo", async (HttpContext context) =>
        {
            state.UserInfoCalls++;

            // The deterministic hold for cancellation tests: the request parks here until the
            // test releases the gate or the caller abandons the request.
            if (state.UserInfoGate is { Task.IsCompleted: false } gate)
            {
                state.UserInfoArrived?.TrySetResult();
                await gate.Task.WaitAsync(context.RequestAborted);
            }

            await (state.UserInfoMode switch
            {
                UserInfoResponse.Valid => Results.Json(new
                {
                    sub = state.Subject,
                    name = "Fake Authority User",
                    nickname = "fake-nickname"
                }),
                UserInfoResponse.SubjectMismatch => Results.Json(new { sub = "a-different-upstream-subject" }),
                UserInfoResponse.SubjectMissing => Results.Json(new { name = "Fake Authority User" }),
                UserInfoResponse.SubjectNonString => Results.Json(new { sub = 12345 }),
                UserInfoResponse.SubjectDuplicate => Results.Text(
                    $"{{\"sub\":\"{state.Subject}\",\"sub\":\"{state.Subject}\"}}", "application/json"),
                UserInfoResponse.InvalidJson => Results.Text("{ this is not a json object", "application/json"),
                UserInfoResponse.InternalError => Results.StatusCode(StatusCodes.Status500InternalServerError),
                UserInfoResponse.Unauthorized => Results.StatusCode(StatusCodes.Status401Unauthorized),
                _ => Results.StatusCode(StatusCodes.Status500InternalServerError)
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
            var claims = new List<Claim>();
            if (state.SubjectMode == TokenSubjectMode.Single)
            {
                claims.Add(new Claim("sub", state.Subject));
            }
            else if (state.SubjectMode == TokenSubjectMode.Duplicate)
            {
                claims.Add(new Claim("sub", state.Subject));
                claims.Add(new Claim("sub", "a-competing-subject-value"));
            }

            claims.Add(new Claim("nonce", state.Defect == TokenDefect.WrongNonce
                ? "a-nonce-that-was-never-requested"
                : state.LastNonce));
            claims.AddRange(state.ExtraIdTokenClaims);
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
        public RsaSecurityKey SigningKey { get; } = CreateKey("fake-authority-signing-key");

        public RsaSecurityKey UnlistedKey { get; } = CreateKey("fake-authority-unlisted-key");

        public string SigningKeyId { get; } = "fake-authority-signing-key";

        public TokenDefect Defect { get; set; }

        public TokenSubjectMode SubjectMode { get; set; } = TokenSubjectMode.Single;

        public string Subject { get; set; } = DefaultSubject;

        public IList<Claim> ExtraIdTokenClaims { get; } = [];

        public UserInfoResponse UserInfoMode { get; set; } = UserInfoResponse.Valid;

        public bool OmitUserInfoEndpoint { get; set; }

        public TaskCompletionSource? UserInfoGate { get; set; }

        public TaskCompletionSource? UserInfoArrived { get; set; }

        public string LastNonce { get; set; } = string.Empty;

        public ConcurrentBag<string> RedeemedCodes { get; } = [];

        public int UserInfoCalls;

        private static RsaSecurityKey CreateKey(string kid)
        {
            var rsa = RSA.Create(2048);
            return new RsaSecurityKey(rsa) { KeyId = kid };
        }
    }
}
