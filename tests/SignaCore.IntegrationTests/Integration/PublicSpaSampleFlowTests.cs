using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Domain.Models;
using SignaCore.Host;
using SignaCore.Host.Security;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The Public SPA sample (<c>samples/SignaCore.PublicSpa</c>) end to end over a real host: the
/// sample README's management API order, then the sample's own wire format for authorize, the
/// login form, cancel, the none code exchange, UserInfo, refresh rotation, and reuse, all read
/// from the sample's registered browser Origin. Rows that <see cref="PublicCodeFlowTests"/>
/// already covers (cross-application, unregistered, and non-canonical Origins for refresh and
/// UserInfo) are not repeated here.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class PublicSpaSampleFlowTests(IdentityServerFixture fixture) : IClassFixture<IdentityServerFixture>
{
    private const string SampleOrigin = "https://spa.example.test";
    private const string RedirectUri = SampleOrigin + "/callback";
    private const string UnregisteredOrigin = "https://unregistered-spa.example.test";
    private const string SampleScope = "openid profile";
    private const string RefreshScope = "openid profile offline_access";
    private const string Password = "Public-Spa-Sample-123!";

    [Fact]
    public async Task Readme_RegistersTheSampleInOrder_ThenItsBrowserFlowIsReadableOnlyByTheSampleOrigin()
    {
        var token = TestContext.Current.CancellationToken;
        var capture = new CapturingLoggerProvider();
        using var factory = CreateCapturingHost(capture);
        using var admin = await CreateAdminClientAsync(factory, token);
        var (appId, username) = await RegisterSampleAsync(admin, token);
        using var browser = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        });
        var issuer = await ReadIssuerAsync(browser, token);
        var canaries = new List<string> { Password };

        // Cancel on the login page returns to the sample callback with access_denied, the
        // original state, and the issuer.
        var cancelled = SampleLogin.Create(SampleScope);
        canaries.Add(cancelled.Verifier);
        var cancelForm = await OpenLoginFormAsync(browser, appId, cancelled, token);
        using (var cancel = await browser.SendAsync(
                   CreateLoginPost(fields: CancelFields(cancelForm), cookieHeader: CookieHeaderFor(cancelForm)), token))
        {
            Assert.Equal(HttpStatusCode.Found, cancel.StatusCode);
            AssertLoginRedirectContentSecurityPolicy(cancel);
            Assert.Equal(
                RedirectUri
                + "?error=access_denied"
                + $"&error_description={Uri.EscapeDataString(OidcAuthorizationErrorDescriptions.AccessDenied)}"
                + $"&state={Uri.EscapeDataString(cancelled.State)}"
                + $"&iss={Uri.EscapeDataString(issuer)}",
                cancel.Headers.Location!.AbsoluteUri);
        }

        // Normal path: the rendered form admits the sample callback origin in form-action only.
        var login = SampleLogin.Create(SampleScope);
        canaries.Add(login.Verifier);
        var form = await OpenLoginFormAsync(browser, appId, login, token);
        using var completion = await browser.SendAsync(
            CreateLoginPost(fields: LoginFields(form, username, Password), cookieHeader: CookieHeaderFor(form)), token);
        Assert.Equal(HttpStatusCode.Found, completion.StatusCode);
        AssertLoginRedirectContentSecurityPolicy(completion);
        var code = ReadCallbackCode(completion, login, issuer);
        canaries.Add(code);
        var identityCookie = GetSetCookieHeader(completion, IdentitySessionDefaults.CookieName)!.Split(';')[0];

        // A wrong verifier is invalid_grant and does not consume the code.
        var wrongVerifier = SampleLogin.Create(SampleScope).Verifier;
        using (var wrong = await browser.SendAsync(ExchangeRequest(appId, code, wrongVerifier, SampleOrigin), token))
        {
            Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
            Assert.Equal("invalid_grant", await ErrorCodeAsync(wrong, token));
        }

        using var exchange = await browser.SendAsync(ExchangeRequest(appId, code, login.Verifier, SampleOrigin), token);
        Assert.Equal(HttpStatusCode.OK, exchange.StatusCode);
        AssertReadableBy(exchange, SampleOrigin);
        var issued = await exchange.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        Assert.Equal("Bearer", issued.GetProperty("token_type").GetString());
        Assert.Equal(300, issued.GetProperty("expires_in").GetInt64());
        Assert.False(issued.TryGetProperty("refresh_token", out _));
        var accessToken = issued.GetProperty("access_token").GetString()!;
        var idToken = issued.GetProperty("id_token").GetString()!;
        canaries.AddRange([accessToken, idToken]);
        Assert.Equal(appId, Assert.Single(new JwtSecurityTokenHandler().ReadJwtToken(accessToken).Audiences));
        var identity = new JwtSecurityTokenHandler().ReadJwtToken(idToken);
        Assert.Equal(issuer, identity.Issuer);
        Assert.Equal(appId, Assert.Single(identity.Audiences));
        Assert.Equal(login.Nonce, identity.Claims.Single(claim => claim.Type == "nonce").Value);

        using (var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/oauth2/userinfo"))
        {
            userInfoRequest.Headers.TryAddWithoutValidation("Origin", SampleOrigin);
            userInfoRequest.Headers.TryAddWithoutValidation("Authorization", "Bearer " + accessToken);
            using var userInfo = await browser.SendAsync(userInfoRequest, token);
            Assert.Equal(HttpStatusCode.OK, userInfo.StatusCode);
            AssertReadableBy(userInfo, SampleOrigin);
            var claims = await userInfo.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
            Assert.Equal(identity.Subject, claims.GetProperty("sub").GetString());
            Assert.Equal(username, claims.GetProperty("name").GetString());
        }

        // Wrong audience: the sample's access token validates only for its own AppId.
        var jwtHandler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var signingKeys = await ReadSigningKeysAsync(browser, token);
        Assert.Throws<SecurityTokenInvalidAudienceException>(() =>
            jwtHandler.ValidateToken(accessToken, AccessTokenParameters(issuer, "OrderService", signingKeys), out _));
        jwtHandler.ValidateToken(accessToken, AccessTokenParameters(issuer, appId, signingKeys), out _);

        // Wrong Origin: an unregistered Origin cannot read a successful Code exchange.
        var unregistered = SampleLogin.Create(SampleScope);
        canaries.Add(unregistered.Verifier);
        var unregisteredCode = await AuthorizeWithSessionAsync(browser, appId, unregistered, identityCookie, issuer, token);
        canaries.Add(unregisteredCode);
        using (var unreadable = await browser.SendAsync(
                   ExchangeRequest(appId, unregisteredCode, unregistered.Verifier, UnregisteredOrigin), token))
        {
            Assert.Equal(HttpStatusCode.OK, unreadable.StatusCode);
            AssertNotReadable(unreadable);
            var body = await unreadable.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
            canaries.AddRange([body.GetProperty("access_token").GetString()!, body.GetProperty("id_token").GetString()!]);
        }

        // README step 6, optional refresh: rotation and reuse are readable by the sample Origin.
        using (var refreshPolicy = await admin.PutAsJsonAsync($"/api/admin/apps/{appId}/oidc-policy",
                   Policy(refresh: true), token))
        {
            Assert.Equal(HttpStatusCode.OK, refreshPolicy.StatusCode);
        }

        var offline = SampleLogin.Create(RefreshScope);
        canaries.Add(offline.Verifier);
        var offlineCode = await AuthorizeWithSessionAsync(browser, appId, offline, identityCookie, issuer, token);
        canaries.Add(offlineCode);
        using var offlineExchange = await browser.SendAsync(
            ExchangeRequest(appId, offlineCode, offline.Verifier, SampleOrigin), token);
        Assert.Equal(HttpStatusCode.OK, offlineExchange.StatusCode);
        AssertReadableBy(offlineExchange, SampleOrigin);
        var offlineIssued = await offlineExchange.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        Assert.Equal(RefreshScope, offlineIssued.GetProperty("scope").GetString());
        var rootToken = offlineIssued.GetProperty("refresh_token").GetString()!;
        canaries.AddRange([rootToken, offlineIssued.GetProperty("access_token").GetString()!]);

        using var rotation = await browser.SendAsync(RefreshRequest(appId, rootToken, SampleOrigin), token);
        Assert.Equal(HttpStatusCode.OK, rotation.StatusCode);
        AssertReadableBy(rotation, SampleOrigin);
        var rotated = await rotation.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        Assert.Equal(300, rotated.GetProperty("expires_in").GetInt64());
        var childToken = rotated.GetProperty("refresh_token").GetString()!;
        Assert.NotEqual(rootToken, childToken);
        canaries.AddRange([childToken, rotated.GetProperty("access_token").GetString()!]);

        using (var reuse = await browser.SendAsync(RefreshRequest(appId, rootToken, SampleOrigin), token))
        {
            Assert.Equal(HttpStatusCode.BadRequest, reuse.StatusCode);
            AssertReadableBy(reuse, SampleOrigin);
            Assert.Equal("invalid_grant", await ErrorCodeAsync(reuse, token));
        }

        Assert.NotEmpty(capture.Messages);
        foreach (var message in capture.Messages)
        {
            foreach (var canary in canaries)
            {
                Assert.DoesNotContain(canary, message, StringComparison.Ordinal);
            }
        }
    }

    [Theory]
    [InlineData("plain")]
    [InlineData(null)]
    public async Task WrongPkce_IsRejectedAtAuthorizeBeforeTheLoginPage(string? method)
    {
        var token = TestContext.Current.CancellationToken;
        using var factory = CreateCapturingHost(new CapturingLoggerProvider());
        using var admin = await CreateAdminClientAsync(factory, token);
        var (appId, _) = await RegisterSampleAsync(admin, token);
        using var browser = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            HandleCookies = false
        });

        var login = SampleLogin.Create(SampleScope);
        var parameters = AuthorizeParameters(appId, login)
            .Where(pair => method is not null || pair.Key != "code_challenge")
            .Select(pair => pair.Key == "code_challenge_method" && method is not null
                ? new KeyValuePair<string, string>(pair.Key, method)
                : pair);
        using var authorize = await browser.GetAsync(AuthorizeUrl(parameters), token);

        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var location = authorize.Headers.Location!;
        Assert.StartsWith(RedirectUri + "?", location.AbsoluteUri, StringComparison.Ordinal);
        var callback = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("invalid_request", callback["error"].ToString());
        Assert.Equal(login.State, callback["state"].ToString());
        Assert.False(callback.ContainsKey("code"));
    }

    /// <summary>
    /// The sample README's registration steps 2–7 in order, including the two fixed failures of
    /// enabling Code before the audience and the redirect exist.
    /// </summary>
    private static async Task<(string AppId, string Username)> RegisterSampleAsync(
        HttpClient admin, CancellationToken token)
    {
        using var create = await admin.PostAsJsonAsync("/api/admin/apps",
            new { appName = "Public SPA sample", callbackUrl = (string?)null, ttlSeconds = 0, clientType = "Public" },
            token);
        Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        var created = await create.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token);
        var appId = created.GetProperty("appId").GetString()!;
        Assert.Equal(JsonValueKind.Null, created.GetProperty("appSecret").ValueKind);
        var route = $"/api/admin/apps/{appId}";

        using (var premature = await admin.PutAsJsonAsync(route + "/oidc-policy", Policy(refresh: false), token))
        {
            Assert.Equal(HttpStatusCode.BadRequest, premature.StatusCode);
            Assert.Contains("Authorization Code flow requires a per-application audience.",
                await premature.Content.ReadAsStringAsync(token), StringComparison.Ordinal);
        }

        using (var audience = await admin.PutAsJsonAsync(route + "/audience-mode", new { mode = "PerApplication" }, token))
        {
            Assert.Equal(HttpStatusCode.OK, audience.StatusCode);
        }

        using (var premature = await admin.PutAsJsonAsync(route + "/oidc-policy", Policy(refresh: false), token))
        {
            Assert.Equal(HttpStatusCode.BadRequest, premature.StatusCode);
            Assert.Contains("Authorization Code flow requires at least one redirect URI.",
                await premature.Content.ReadAsStringAsync(token), StringComparison.Ordinal);
        }

        using (var redirect = await admin.PostAsJsonAsync(route + "/oidc/redirect-uris",
                   new { kind = "Redirect", uris = new[] { RedirectUri } }, token))
        {
            Assert.Equal(HttpStatusCode.OK, redirect.StatusCode);
        }

        using (var origins = await admin.PutAsJsonAsync(route + "/oidc/allowed-origins",
                   new { origins = new[] { SampleOrigin } }, token))
        {
            Assert.Equal(HttpStatusCode.OK, origins.StatusCode);
        }

        using (var enabled = await admin.PutAsJsonAsync(route + "/oidc-policy", Policy(refresh: false), token))
        {
            Assert.Equal(HttpStatusCode.OK, enabled.StatusCode);
        }

        using (var readback = await admin.GetAsync(route + "/oidc", token))
        {
            Assert.Equal(HttpStatusCode.OK, readback.StatusCode);
            var raw = await readback.Content.ReadAsStringAsync(token);
            Assert.DoesNotContain("ecret", raw, StringComparison.Ordinal);
            var oidc = JsonDocument.Parse(raw).RootElement;
            Assert.Equal("Public", oidc.GetProperty("clientType").GetString());
            Assert.True(oidc.GetProperty("allowAuthorizationCode").GetBoolean());
            Assert.Equal(SampleOrigin, Assert.Single(oidc.GetProperty("allowedOrigins").EnumerateArray()).GetString());
        }

        using (var listed = await admin.GetAsync("/api/admin/apps", token))
        {
            Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
            var item = (await listed.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token))
                .EnumerateArray().Single(app => app.GetProperty("appId").GetString() == appId);
            Assert.DoesNotContain("ecret", item.GetRawText(), StringComparison.Ordinal);
        }

        var username = $"spa_sample_{Guid.NewGuid():N}";
        using (var user = await admin.PostAsJsonAsync("/api/admin/users", new
               {
                   username, password = Password, displayName = (string?)null, remark = (string?)null,
                   nickname = (string?)null
               }, token))
        {
            Assert.Equal(HttpStatusCode.OK, user.StatusCode);
        }

        return (appId, username);
    }

    private static object Policy(bool refresh) => new
    {
        clientType = "Public",
        allowAuthorizationCode = true,
        allowedScopes = refresh ? new[] { "openid", "profile", "offline_access" } : new[] { "openid", "profile" },
        allowRefreshToken = refresh,
        identitySessionMaxAgeSeconds = refresh ? 3600 : (int?)null
    };

    private WebApplicationFactory<Program> CreateCapturingHost(CapturingLoggerProvider capture) =>
        fixture.WithTestServices(services =>
        {
            services.RemoveAll<ILoggerFactory>();
            // The shipped levels: SignaCore at Information, framework categories at Warning.
            services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
            {
                logging.AddProvider(capture);
                logging.SetMinimumLevel(LogLevel.Information);
                logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
                logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);
            }));
        });

    private static async Task<HttpClient> CreateAdminClientAsync(
        WebApplicationFactory<Program> factory, CancellationToken token)
    {
        // The management cookie is Secure, so the admin client addresses the test server over https.
        var admin = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost") });
        using var login = new HttpRequestMessage(HttpMethod.Post, "/management/v1/session/login")
        {
            Content = JsonContent.Create(new
            {
                username = IdentityServerFixture.AdminUsername,
                password = IdentityServerFixture.AdminPassword
            })
        };
        login.Headers.TryAddWithoutValidation("X-ServiceMantle-Request", "1");
        using var response = await admin.SendAsync(login, token);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        return admin;
    }

    private static async Task<string> ReadIssuerAsync(HttpClient browser, CancellationToken token)
    {
        var discovery = await browser.GetFromJsonAsync<JsonElement>("/.well-known/openid-configuration", token);
        return discovery.GetProperty("issuer").GetString()!;
    }

    private static async Task<SecurityKey[]> ReadSigningKeysAsync(HttpClient browser, CancellationToken token)
    {
        var jwks = await browser.GetFromJsonAsync<JsonElement>("/.well-known/jwks", token);
        return jwks.GetProperty("keys").EnumerateArray()
            .Select(key => (SecurityKey)new RsaSecurityKey(new RSAParameters
            {
                Modulus = Base64UrlEncoder.DecodeBytes(key.GetProperty("n").GetString()!),
                Exponent = Base64UrlEncoder.DecodeBytes(key.GetProperty("e").GetString()!)
            })
            { KeyId = key.GetProperty("kid").GetString() })
            .ToArray();
    }

    private static TokenValidationParameters AccessTokenParameters(
        string issuer, string audience, SecurityKey[] keys) => new()
    {
        ValidIssuer = issuer,
        ValidAudience = audience,
        IssuerSigningKeys = keys,
        ValidateLifetime = true
    };

    /// <summary>Drives authorize → login GET and returns the rendered form's session values.</summary>
    private static async Task<LoginSession> OpenLoginFormAsync(
        HttpClient browser, string appId, SampleLogin login, CancellationToken token)
    {
        using var authorize = await browser.GetAsync(AuthorizeUrl(AuthorizeParameters(appId, login)), token);
        Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
        var location = new Uri(new Uri("https://local.test"), authorize.Headers.Location!);
        var handle = QueryHelpers.ParseQuery(location.Query)["login_handle"].ToString();
        Assert.NotEmpty(handle);

        using var form = await browser.GetAsync($"/oauth2/login?login_handle={handle}", token);
        Assert.Equal(HttpStatusCode.OK, form.StatusCode);
        AssertLoginSecurityHeaders(form, ExpectedFormContentSecurityPolicy(SampleOrigin));
        var html = await form.Content.ReadAsStringAsync(token);
        var antiforgery = Regex.Match(html, "name=\"__RequestVerificationToken\" value=\"([^\"]*)\"").Groups[1].Value;
        Assert.NotEmpty(antiforgery);
        var cookie = GetSetCookieHeader(form, CookieName);
        Assert.NotNull(cookie);
        return new LoginSession(handle, CookieValueFromHeader(cookie!, CookieName), antiforgery);
    }

    private static async Task<string> AuthorizeWithSessionAsync(
        HttpClient browser, string appId, SampleLogin login, string identityCookie, string issuer,
        CancellationToken token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, AuthorizeUrl(AuthorizeParameters(appId, login)));
        request.Headers.TryAddWithoutValidation("Cookie", identityCookie);
        using var response = await browser.SendAsync(request, token);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        return ReadCallbackCode(response, login, issuer);
    }

    private static string ReadCallbackCode(HttpResponseMessage response, SampleLogin login, string issuer)
    {
        var location = response.Headers.Location!;
        Assert.StartsWith(RedirectUri + "?", location.AbsoluteUri, StringComparison.Ordinal);
        Assert.Equal(string.Empty, location.Fragment);
        var callback = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal(login.State, callback["state"].ToString());
        Assert.Equal(issuer, callback["iss"].ToString());
        Assert.False(callback.ContainsKey("error"));
        var code = callback["code"].ToString();
        Assert.NotEmpty(code);
        return code;
    }

    /// <summary>The sample's authorize parameters, in the order public-client.js appends them.</summary>
    private static IEnumerable<KeyValuePair<string, string>> AuthorizeParameters(string appId, SampleLogin login) =>
    [
        new("response_type", "code"),
        new("client_id", appId),
        new("redirect_uri", RedirectUri),
        new("scope", login.Scope),
        new("state", login.State),
        new("nonce", login.Nonce),
        new("code_challenge", login.Challenge),
        new("code_challenge_method", "S256")
    ];

    /// <summary>Encodes like the browser's URLSearchParams: form encoding, spaces as '+'.</summary>
    private static string AuthorizeUrl(IEnumerable<KeyValuePair<string, string>> parameters) =>
        "/oauth2/authorize?" + string.Join('&',
            parameters.Select(pair => $"{WebUtility.UrlEncode(pair.Key)}={WebUtility.UrlEncode(pair.Value)}"));

    private static HttpRequestMessage ExchangeRequest(string appId, string code, string verifier, string origin)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
        {
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "authorization_code"),
                new("client_id", appId),
                new("code", code),
                new("redirect_uri", RedirectUri),
                new KeyValuePair<string, string>("code_verifier", verifier)
            ])
        };
        request.Headers.TryAddWithoutValidation("Origin", origin);
        return request;
    }

    private static HttpRequestMessage RefreshRequest(string appId, string refreshToken, string origin)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/oauth2/token")
        {
            Content = new FormUrlEncodedContent(
            [
                new("grant_type", "refresh_token"),
                new("client_id", appId),
                new KeyValuePair<string, string>("refresh_token", refreshToken)
            ])
        };
        request.Headers.TryAddWithoutValidation("Origin", origin);
        return request;
    }

    private static async Task<string?> ErrorCodeAsync(HttpResponseMessage response, CancellationToken token) =>
        (await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: token))
        .GetProperty("error").GetString();

    private static void AssertReadableBy(HttpResponseMessage response, string origin)
    {
        Assert.Equal(origin, Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
        Assert.Contains("Origin", response.Headers.Vary);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"));
        Assert.Contains("no-store", response.Headers.CacheControl!.ToString());
    }

    private static void AssertNotReadable(HttpResponseMessage response)
    {
        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
        Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"));
        Assert.Contains("no-store", response.Headers.CacheControl!.ToString());
    }

    /// <summary>One sample login transaction: 32 random bytes each for state, nonce, and verifier.</summary>
    private sealed record SampleLogin(string Scope, string State, string Nonce, string Verifier, string Challenge)
    {
        public static SampleLogin Create(string scope)
        {
            var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
            return new SampleLogin(
                scope,
                Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32)),
                Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32)),
                verifier,
                Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
        }
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly Lock _lock = new();
        private readonly List<string> _messages = [];

        public IReadOnlyList<string> Messages
        {
            get
            {
                lock (_lock)
                {
                    return _messages.ToArray();
                }
            }
        }

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(CapturingLoggerProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                lock (owner._lock)
                {
                    owner._messages.Add(formatter(state, exception) + exception);
                }
            }
        }
    }
}
