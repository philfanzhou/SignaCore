using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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

    public enum AccessDefect
    {
        None, Signature, Kid, MissingKid, Alg, Typ, Issuer, Audience, AdditionalAudience,
        MissingSubject, DuplicateSubject, SubjectType, SubjectMismatch, Expired, FutureNbf,
        FutureIat, MissingExp, MissingNbf, MissingIat, InvalidTime, DuplicateIssuer,
        DuplicateAudience, DuplicateExp, DuplicateNbf, DuplicateIat, NonCompact, TooLong,
        IdToken, NonAscii, MissingIssuer, MissingAudience, EmptySubject, InvalidExp, InvalidNbf, OutOfRangeTime, SingleArrayAudience
    }

    public bool SignedAccessToken { get => _state.SignedAccessToken; set => _state.SignedAccessToken = value; }
    public AccessDefect AccessTokenDefect { get => _state.AccessTokenDefect; set => _state.AccessTokenDefect = value; }
    public TimeSpan AccessLifetime { get => _state.AccessLifetime; set => _state.AccessLifetime = value; }
    public TimeSpan AccessTimeOffset { get => _state.AccessTimeOffset; set => _state.AccessTimeOffset = value; }
    public void RotateSigningKey() => _state.SigningKey = AuthorityState.CreateKey("rotated-key");

    /// <summary>The authority's own base address; defaults to <see cref="BaseAddress"/>, tests may
    /// start the fake on an explicit loopback HTTP origin instead.</summary>
    public string Base => _state.BaseAddress;

    public enum TokenResponseShape
    {
        Normal,
        MissingAccessToken,
        MissingIdToken,
        WrongTokenType,
        NonPositiveExpiresIn,
        NonJsonBody
    }

    /// <summary>The injectable endpoint shapes of the Discovery document: every non-normal shape
    /// points one or more endpoints somewhere the document must not be trusted for.</summary>
    public enum DiscoveryEndpointShape
    {
        /// <summary>Every endpoint on the authority's own origin: the trusted shape.</summary>
        Normal,

        /// <summary>The authorization endpoint on another host (still absolute HTTPS).</summary>
        AuthorizationCrossHost,

        /// <summary>The token endpoint on another host (still absolute HTTPS).</summary>
        TokenCrossHost,

        /// <summary>The JWKS URI on another host (still absolute HTTPS).</summary>
        JwksCrossHost,

        /// <summary>The authorization endpoint on the same host but a different port.</summary>
        AuthorizationCrossPort,

        /// <summary>The token endpoint as loopback HTTP — acceptable in Development by shape,
        /// but never same-origin with an HTTPS issuer.</summary>
        TokenCrossSchemeLoopback,

        /// <summary>The authorization endpoint on the same origin under a deeper path: a legal
        /// shape the same-origin rule must not reject.</summary>
        AuthorizationDeeperPath
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

    /// <summary>The injectable answer shapes of the logout preparation endpoint.</summary>
    public enum LogoutPrepareShape
    {
        /// <summary>The contract's success: one relative <c>logout_uri</c> with a fresh handle.</summary>
        Normal,

        /// <summary>An HTTP 500 — the authority failed after consuming nothing.</summary>
        HttpError,

        /// <summary>A <c>logout_uri</c> pointing at another origin: the browser must never go there.</summary>
        CrossOriginUri,

        /// <summary>A <c>logout_uri</c> with an extra query member beyond the handle.</summary>
        ExtraQueryUri,

        /// <summary>A 200 whose body has no <c>logout_uri</c> member.</summary>
        MissingUriMember,

        /// <summary>A transport failure thrown before any answer: an unreachable authority.</summary>
        Unreachable,

        /// <summary>A timeout: the response never arrives within the client's patience.</summary>
        Timeout
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

    public LogoutPrepareShape LogoutPrepare
    {
        get => _state.LogoutPrepare;
        set => _state.LogoutPrepare = value;
    }

    /// <summary>The Discovery document's endpoint shape; corrupting it breaks the endpoint
    /// trust checks without touching the document's issuer.</summary>
    public DiscoveryEndpointShape EndpointShape
    {
        get => _state.EndpointShape;
        set => _state.EndpointShape = value;
    }

    /// <summary>Every preparation request's form body, in order.</summary>
    public ConcurrentQueue<string> LogoutPrepareBodies => _state.LogoutPrepareBodies;

    /// <summary>Every preparation request's Authorization header, in order.</summary>
    public ConcurrentQueue<string?> LogoutPrepareAuthorizationHeaders =>
        _state.LogoutPrepareAuthorizationHeaders;

    /// <summary>Every logout handle the browser completion endpoint saw, in order.</summary>
    public ConcurrentQueue<string> CompletedLogoutHandles => _state.CompletedLogoutHandles;

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

    public static async Task<FakeIdentityProvider> StartAsync(
        TimeProvider? timeProvider = null,
        string? baseAddress = null)
    {
        var state = new AuthorityState(timeProvider ?? TimeProvider.System)
        {
            BaseAddress = baseAddress ?? BaseAddress
        };
        // The document's issuer defaults to the base the fake actually serves on.
        state.DiscoveryIssuer = state.BaseAddress;
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.WebHost.UseUrls(state.BaseAddress);

        var app = builder.Build();

        app.MapGet("/.well-known/openid-configuration", () =>
        {
            var authorizationEndpoint = state.EndpointShape switch
            {
                DiscoveryEndpointShape.AuthorizationCrossHost => "https://evil.example/authorize",
                DiscoveryEndpointShape.AuthorizationCrossPort => state.BaseAddress + ":8443/authorize",
                DiscoveryEndpointShape.AuthorizationDeeperPath => state.BaseAddress + "/oauth2/authorize",
                _ => state.BaseAddress + "/authorize"
            };
            var tokenEndpoint = state.EndpointShape switch
            {
                DiscoveryEndpointShape.TokenCrossHost => "https://evil.example/token",
                DiscoveryEndpointShape.TokenCrossSchemeLoopback => "http://127.0.0.1/token",
                _ => state.BaseAddress + "/token"
            };
            var jwksUri = state.EndpointShape switch
            {
                DiscoveryEndpointShape.JwksCrossHost => "https://evil.example/jwks",
                _ => state.BaseAddress + "/jwks"
            };
            return Results.Json(new
            {
                issuer = state.DiscoveryIssuer,
                authorization_endpoint = authorizationEndpoint,
                token_endpoint = tokenEndpoint,
                userinfo_endpoint = $"{state.BaseAddress}/userinfo",
                jwks_uri = jwksUri,
                response_types_supported = new[] { "code" },
                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = new[] { "RS256" },
                code_challenge_methods_supported = new[] { "S256" }
            });
        });

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
                        kid = state.SigningKey.KeyId,
                        n = Base64UrlEncoder.Encode(parameters.Modulus!),
                        e = Base64UrlEncoder.Encode(parameters.Exponent!)
                    }
                }
            });
        });

        // The same authorize handler serves both the default path and the deeper same-origin
        // path the DiscoveryEndpointShape.AuthorizationDeeperPath document publishes.
        app.MapGet("/authorize", AuthorizeHandler);
        app.MapGet("/oauth2/authorize", AuthorizeHandler);

        IResult AuthorizeHandler(HttpRequest http)
        {
            state.AuthorizeRequests.Enqueue(new Uri(state.BaseAddress + http.Path + http.QueryString));
            state.LastNonce = http.Query["nonce"].ToString();
            var normalCode = Guid.NewGuid().ToString("N");
            state.CodeNonces[normalCode] = state.LastNonce;
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
                    $"{redirectUri}{separator}code={normalCode}&state={Uri.EscapeDataString(redirectState)}&iss={state.DiscoveryIssuer}")
            };
        }

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
                ["id_token"] = Mint(state, state.CodeNonces.GetValueOrDefault(code, state.LastNonce))
            };
            if (state.ResponseShape != TokenResponseShape.MissingAccessToken)
            {
                payload["access_token"] = !state.SignedAccessToken ? AccessTokenMaterial
                    : state.AccessTokenDefect == AccessDefect.IdToken ? payload["id_token"]
                    : MintAccess(state);
            }

            await Results.Json(payload).ExecuteAsync(context);
        });

        app.MapGet("/userinfo", () => Results.Json(new { sub = DefaultSubject }));

        // The prepared-logout preparation endpoint, with the contract's success shape and the
        // injectable failure shapes the negative cases need.
        app.MapPost("/oauth2/logout/requests", async (HttpContext context) =>
        {
            var form = await context.Request.ReadFormAsync(TestContext.Current.CancellationToken);
            var body = string.Join(
                "&",
                form.OrderBy(member => member.Key, StringComparer.Ordinal)
                    .Select(member => $"{member.Key}={Uri.EscapeDataString(member.Value.ToString())}"));
            state.LogoutPrepareBodies.Enqueue(body);
            state.LogoutPrepareAuthorizationHeaders.Enqueue(
                context.Request.Headers.Authorization.ToString());

            switch (state.LogoutPrepare)
            {
                case LogoutPrepareShape.HttpError:
                    context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                    return;

                case LogoutPrepareShape.Unreachable:
                    throw new System.Net.Http.HttpRequestException("The fake authority is offline.");

                case LogoutPrepareShape.Timeout:
                    // Longer than any client patience: the caller observes a timeout, and the
                    // test controls the end of the wait through its own cancellation.
                    await Task.Delay(TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
                    break;

                default:
                    break;
            }

            var handle = NewLogoutHandle();
            var logoutUri = state.LogoutPrepare switch
            {
                LogoutPrepareShape.CrossOriginUri =>
                    $"https://evil.example/oauth2/logout?logout_handle={handle}",
                LogoutPrepareShape.ExtraQueryUri =>
                    $"/oauth2/logout?logout_handle={handle}&extra=1",
                LogoutPrepareShape.MissingUriMember => null,
                _ => $"/oauth2/logout?logout_handle={handle}"
            };
            var echoedState = form["state"].ToString();
            state.PreparedLogouts.Enqueue(
                (handle, form["post_logout_redirect_uri"].ToString(), echoedState));

            if (logoutUri is null)
            {
                await Results.Json(new { other = "member" }).ExecuteAsync(context);
                return;
            }

            context.Response.Headers.CacheControl = "no-store";
            await Results.Json(new { logout_uri = logoutUri }).ExecuteAsync(context);
        });

        // The browser completion: records the handle and redirects back to the prepared
        // post-logout URI with the stored state echoed byte-for-byte.
        app.MapGet("/oauth2/logout", (HttpRequest http) =>
        {
            var handle = http.Query["logout_handle"].ToString();
            state.CompletedLogoutHandles.Enqueue(handle);
            var prepared = state.PreparedLogouts.FirstOrDefault(entry => entry.Handle == handle);
            if (prepared.PostLogoutRedirectUri is { Length: > 0 } target)
            {
                var separator = target.Contains('?', StringComparison.Ordinal) ? '&' : '?';
                return Results.Redirect(
                    prepared.EchoedState is { Length: > 0 } echoedState
                        ? $"{target}{separator}state={Uri.EscapeDataString(echoedState)}"
                        : target);
            }

            return Results.Text("signed out at the authority", "text/html");
        });

        await app.StartAsync(TestContext.Current.CancellationToken);
        var server = app.GetTestServer();
        server.BaseAddress = new Uri(state.BaseAddress);
        return new FakeIdentityProvider(app, server, state);

        // One fresh 43-character base64url handle, exactly the completion contract's shape.
        static string NewLogoutHandle()
        {
            Span<byte> entropy = stackalloc byte[32];
            RandomNumberGenerator.Fill(entropy);
            return Convert.ToBase64String(entropy).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        static string Mint(AuthorityState state, string nonce)
        {            if (state.ResponseShape == TokenResponseShape.MissingIdToken)
            {
                return string.Empty;
            }

            var now = state.TimeProvider.GetUtcNow();
            var signingKey = state.Defect == TokenDefect.SigningKeyAbsentFromJwks
                ? state.UnlistedKey
                : state.SigningKey;
            var claims = new List<Claim>
            {
                new("sub", DefaultSubject),
                new("nonce", state.Defect == TokenDefect.WrongNonce
                    ? "a-nonce-that-was-never-requested"
                    : nonce),
                new("name", "client_pack_user")
            };
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = state.Defect == TokenDefect.WrongIssuer
                    ? "https://someone-else.example"
                    : state.BaseAddress,
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

    private static string MintAccess(AuthorityState state)
    {
        var defect = state.AccessTokenDefect;
        if (defect == AccessDefect.NonCompact) return "not-a-jwt";
        if (defect == AccessDefect.TooLong) return new string('a', 8193);
        if (defect == AccessDefect.NonAscii) return "é.a.b";
        var now = state.TimeProvider.GetUtcNow();
        var header = new Dictionary<string, object?>
        {
            ["alg"] = defect == AccessDefect.Alg ? "HS256" : "RS256",
            ["typ"] = defect == AccessDefect.Typ ? "JWT" : "at+jwt",
            ["kid"] = defect == AccessDefect.Kid ? "unknown-key" : state.SigningKey.KeyId
        };
        if (defect == AccessDefect.MissingKid) header.Remove("kid");
        var payload = new Dictionary<string, object?>
        {
            ["iss"] = defect == AccessDefect.Issuer ? "https://other.example" : state.BaseAddress,
            ["aud"] = defect == AccessDefect.SingleArrayAudience ? new[] { "client-pack-app" }
                : defect == AccessDefect.Audience ? "other-client"
                : defect == AccessDefect.AdditionalAudience ? new[] { "client-pack-app", "other-client" }
                : "client-pack-app",
            ["sub"] = defect == AccessDefect.SubjectType ? 42
                : defect == AccessDefect.SubjectMismatch ? "different-subject" : DefaultSubject,
            ["exp"] = now.Add(defect == AccessDefect.Expired ? TimeSpan.FromSeconds(-1)
                : state.AccessLifetime).ToUnixTimeSeconds(),
            ["nbf"] = now.Add(defect == AccessDefect.FutureNbf ? TimeSpan.FromMinutes(2)
                : state.AccessTimeOffset).ToUnixTimeSeconds(),
            ["iat"] = now.Add(defect == AccessDefect.FutureIat ? TimeSpan.FromMinutes(2)
                : state.AccessTimeOffset).ToUnixTimeSeconds(),
            ["role"] = "reader"
        };
        switch (defect)
        {
            case AccessDefect.MissingIssuer: payload.Remove("iss"); break;
            case AccessDefect.MissingAudience: payload.Remove("aud"); break;
            case AccessDefect.EmptySubject: payload["sub"] = ""; break;
            case AccessDefect.InvalidExp: payload["exp"] = "tomorrow"; break;
            case AccessDefect.InvalidNbf: payload["nbf"] = false; break;
            case AccessDefect.OutOfRangeTime: payload["exp"] = long.MaxValue; break;
            case AccessDefect.MissingSubject: payload.Remove("sub"); break;
            case AccessDefect.MissingExp: payload.Remove("exp"); break;
            case AccessDefect.MissingNbf: payload.Remove("nbf"); break;
            case AccessDefect.MissingIat: payload.Remove("iat"); break;
            case AccessDefect.InvalidTime: payload["iat"] = "yesterday"; break;
        }
        var json = JsonSerializer.Serialize(payload);
        var duplicate = defect switch
        {
            AccessDefect.DuplicateSubject => "sub", AccessDefect.DuplicateIssuer => "iss",
            AccessDefect.DuplicateAudience => "aud", AccessDefect.DuplicateExp => "exp",
            AccessDefect.DuplicateNbf => "nbf", AccessDefect.DuplicateIat => "iat", _ => null
        };
        if (duplicate is not null)
            json = json[..^1] + ",\"" + duplicate + "\":" + JsonSerializer.Serialize(payload[duplicate]) + "}";
        var input = Base64UrlEncoder.Encode(JsonSerializer.Serialize(header)) + "." + Base64UrlEncoder.Encode(json);
        var key = defect == AccessDefect.Signature ? state.UnlistedKey : state.SigningKey;
        var signature = key.Rsa.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return input + "." + Base64UrlEncoder.Encode(signature);
    }

    public HttpClient CreateClient() => Server.CreateClient();

    public async ValueTask DisposeAsync()
    {
        await _host.StopAsync(TimeSpan.FromSeconds(5));
        _host.Dispose();
    }

    private sealed class AuthorityState(TimeProvider timeProvider)
    {
        public TimeProvider TimeProvider { get; } = timeProvider;

        public RsaSecurityKey SigningKey { get; set; } = CreateKey("client-pack-signing-key");

        public RsaSecurityKey UnlistedKey { get; } = CreateKey("client-pack-unlisted-key");

        public bool SignedAccessToken { get; set; }
        public AccessDefect AccessTokenDefect { get; set; }
        public TimeSpan AccessLifetime { get; set; } = TimeSpan.FromMinutes(15);
        public TimeSpan AccessTimeOffset { get; set; }
        public ConcurrentDictionary<string, string> CodeNonces { get; } = new();

        public TokenDefect Defect { get; set; }

        public TokenResponseShape ResponseShape { get; set; } = TokenResponseShape.Normal;

        public AuthorizeEcho Echo { get; set; }

        public LogoutPrepareShape LogoutPrepare { get; set; }

        public DiscoveryEndpointShape EndpointShape { get; set; }

        public ConcurrentQueue<string> LogoutPrepareBodies { get; } = [];

        public ConcurrentQueue<string?> LogoutPrepareAuthorizationHeaders { get; } = [];

        public ConcurrentQueue<string> CompletedLogoutHandles { get; } = [];

        public ConcurrentQueue<(string Handle, string PostLogoutRedirectUri, string EchoedState)> PreparedLogouts { get; } = [];

        public string BaseAddress { get; set; } = FakeIdentityProvider.BaseAddress;

        public string DiscoveryIssuer { get; set; } = FakeIdentityProvider.BaseAddress;

        public string LastNonce { get; set; } = string.Empty;

        public TaskCompletionSource? TokenGate { get; set; }

        public TaskCompletionSource? TokenArrived { get; set; }

        public ConcurrentQueue<Uri> AuthorizeRequests { get; } = [];

        public ConcurrentQueue<string> RedeemedCodes { get; } = [];

        public ConcurrentQueue<string?> TokenAuthorizationHeaders { get; } = [];

        internal static RsaSecurityKey CreateKey(string kid)
        {
            var rsa = RSA.Create(2048);
            return new RsaSecurityKey(rsa) { KeyId = kid };
        }
    }
}
