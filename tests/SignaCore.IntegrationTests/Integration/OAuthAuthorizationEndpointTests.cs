using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Web;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// Wire contract of <c>GET /oauth2/authorize</c>. The endpoint takes attacker-controlled URL input,
/// so these tests assert the two properties that matter before any protocol detail: an unverified
/// client or redirect URI never produces a <c>Location</c>, and the local answer is the same for
/// every reason it could have been rejected.
/// <para>
/// This slice issues no authorization code, so a fully valid request is answered locally as well.
/// </para>
/// </summary>
public class OAuthAuthorizationEndpointTests : IClassFixture<IdentityServerFixture>
{
    private const string InteractiveAppId = "authorize-contract-app";
    private const string InactiveAppId = "authorize-inactive-app";
    private const string NonInteractiveAppId = "authorize-plain-app";
    private const string RegisteredUri = "https://bff.authorize.test/callback";
    private const string RegisteredUriWithQuery = "https://bff.authorize.test/cb?tenant=blue";
    private const string PostLogoutUri = "https://bff.authorize.test/signed-out";

    private const string CanaryState = "canary-state-abcdefghij";
    private const string CanaryNonce = "canary-nonce-abcdefghij";
    private const string CanaryChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static readonly SemaphoreSlim SeedLock = new(1, 1);
    private static bool _seeded;

    private readonly IdentityServerFixture _fixture;

    public OAuthAuthorizationEndpointTests(IdentityServerFixture fixture)
    {
        _fixture = fixture;
    }

    // ---- Stage 1: parameter cardinality ----

    [Theory]
    [InlineData("client_id")]
    [InlineData("redirect_uri")]
    public async Task DuplicateTrustParameter_IsALocalErrorWithNoLocation(string name)
    {
        var response = await GetAsync(Valid().Duplicate(name));

        await AssertLocalErrorAsync(response);
    }

    [Fact]
    public async Task DuplicateClientIdAndRedirectUri_IsALocalErrorWithNoLocation()
    {
        var response = await GetAsync(Valid().Duplicate("client_id").Duplicate("redirect_uri"));

        await AssertLocalErrorAsync(response);
    }

    // ---- Stage 2: current application ----

    /// <summary>
    /// Unknown, inactive, and non-interactive clients must be indistinguishable: the response is
    /// compared byte for byte, not merely by status code.
    /// </summary>
    [Fact]
    public async Task UnknownInactiveAndNonInteractiveClients_ProduceIdenticalLocalResponses()
    {
        var unknown = await GetAsync(Valid().With("client_id", "no-such-client"));
        var inactive = await GetAsync(Valid().With("client_id", InactiveAppId));
        var nonInteractive = await GetAsync(Valid().With("client_id", NonInteractiveAppId));
        var unmatchedUri = await GetAsync(Valid().With("redirect_uri", "https://attacker.test/callback"));

        var bodies = new List<string>();
        foreach (var response in new[] { unknown, inactive, nonInteractive, unmatchedUri })
        {
            bodies.Add(await AssertLocalErrorAsync(response));
        }

        Assert.All(bodies, body => Assert.Equal(bodies[0], body));
    }

    // ---- Stage 3: exact registered redirect URI ----

    [Theory]
    [InlineData("https://bff.authorize.test/callback/")]
    [InlineData("https://bff.authorize.test/CALLBACK")]
    [InlineData("https://bff.authorize.test:443/callback")]
    [InlineData("https://bff.authorize.test/callback?x=1")]
    [InlineData("https://bff.authorize.test.attacker.test/callback")]
    [InlineData("https://bff.authorize.test/signed-out")]
    public async Task RedirectUriThatIsNotTheRegisteredString_IsALocalErrorThatNeverEchoesIt(string submitted)
    {
        var response = await GetAsync(Valid().With("redirect_uri", submitted));

        var body = await AssertLocalErrorAsync(response);
        Assert.DoesNotContain(submitted, body, StringComparison.Ordinal);
        Assert.DoesNotContain("attacker.test", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingRedirectUri_IsALocalError()
    {
        await AssertLocalErrorAsync(await GetAsync(Valid().Without("redirect_uri")));
    }

    // ---- Stage 4: protocol errors reach the verified destination ----

    [Theory]
    [InlineData(null)]
    [InlineData("token")]
    public async Task InvalidResponseType_RedirectsWithUnsupportedResponseType(string? responseType)
    {
        var query = responseType is null
            ? Valid().Without("response_type")
            : Valid().With("response_type", responseType);

        var parameters = AssertSafeRedirect(await GetAsync(query));

        Assert.Equal(OAuthErrorCodes.UnsupportedResponseType, parameters["error"]);
        Assert.Equal(CanaryState, parameters["state"]);
        Assert.Equal(Issuer, parameters["iss"]);
        Assert.False(string.IsNullOrWhiteSpace(parameters["error_description"]));
    }

    [Theory]
    [InlineData("profile")]
    [InlineData("openid unknown_scope")]
    [InlineData("openid openid")]
    [InlineData("openid offline_access")]
    public async Task InvalidScope_RedirectsWithInvalidScope(string scope)
    {
        var parameters = AssertSafeRedirect(await GetAsync(Valid().With("scope", scope)));

        Assert.Equal(OAuthErrorCodes.InvalidScope, parameters["error"]);
        Assert.Equal(CanaryState, parameters["state"]);
    }

    [Fact]
    public async Task OverlongScope_RedirectsWithInvalidScope()
    {
        var parameters = AssertSafeRedirect(
            await GetAsync(Valid().With("scope", "openid " + new string('a', 200))));

        Assert.Equal(OAuthErrorCodes.InvalidScope, parameters["error"]);
    }

    [Theory]
    [InlineData("state", null)]
    [InlineData("state", "short")]
    [InlineData("nonce", null)]
    [InlineData("nonce", "short")]
    public async Task InvalidStateOrNonce_RedirectsWithInvalidRequest(string name, string? value)
    {
        var query = value is null ? Valid().Without(name) : Valid().With(name, value);

        var parameters = AssertSafeRedirect(await GetAsync(query));

        Assert.Equal(OAuthErrorCodes.InvalidRequest, parameters["error"]);
        if (name == "state")
        {
            Assert.Null(parameters["state"]);
        }
    }

    [Theory]
    [InlineData("code_challenge_method", null)]
    [InlineData("code_challenge_method", "plain")]
    [InlineData("code_challenge_method", "S512")]
    [InlineData("code_challenge", null)]
    [InlineData("code_challenge", "tooshort")]
    [InlineData("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c.")]
    [InlineData("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c~")]
    [InlineData("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c=")]
    public async Task InvalidPkce_RedirectsWithInvalidRequest(string name, string? value)
    {
        var query = value is null ? Valid().Without(name) : Valid().With(name, value);

        var parameters = AssertSafeRedirect(await GetAsync(query));

        Assert.Equal(OAuthErrorCodes.InvalidRequest, parameters["error"]);
    }

    [Theory]
    [InlineData("prompt", "login", OAuthErrorCodes.InvalidRequest)]
    [InlineData("max_age", "0", OAuthErrorCodes.InvalidRequest)]
    [InlineData("acr_values", "urn:example", OAuthErrorCodes.InvalidRequest)]
    [InlineData("response_mode", "form_post", OAuthErrorCodes.InvalidRequest)]
    [InlineData("request", "eyJhbGciOiJub25lIn0", OAuthErrorCodes.RequestNotSupported)]
    [InlineData("request_uri", "https://attacker.test/req", OAuthErrorCodes.RequestUriNotSupported)]
    [InlineData("registration", "{}", OAuthErrorCodes.RegistrationNotSupported)]
    public async Task RejectedField_RedirectsWithItsOwnError(string name, string value, string expectedError)
    {
        var parameters = AssertSafeRedirect(await GetAsync(Valid().With(name, value)));

        Assert.Equal(expectedError, parameters["error"]);
        Assert.Equal(CanaryState, parameters["state"]);
    }

    [Fact]
    public async Task UnknownField_IsIgnoredAndDoesNotChangeTheOutcome()
    {
        var response = await GetAsync(Valid().With("ui_locales", "en-US").With("display", "page"));

        Assert.Equal(HttpStatusCode.NotImplemented, response.StatusCode);
        AssertBrowserSecurityHeaders(response);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task DuplicateProtocolField_RedirectsWithInvalidRequest()
    {
        var parameters = AssertSafeRedirect(await GetAsync(Valid().Duplicate("scope")));

        Assert.Equal(OAuthErrorCodes.InvalidRequest, parameters["error"]);
    }

    // ---- Ordering counter-proof ----

    /// <summary>
    /// Both requests are invalid twice: once at a stage that decides redirect trust and once at a
    /// later protocol stage. If the implementation ever evaluated the protocol field first, these
    /// would answer with a 302 to an unverified destination.
    /// </summary>
    [Fact]
    public async Task UnmatchedRedirectUriWithInvalidScope_IsLocalRatherThanARedirect()
    {
        var response = await GetAsync(Valid()
            .With("redirect_uri", "https://attacker.test/callback")
            .With("scope", "openid unknown_scope"));

        await AssertLocalErrorAsync(response);
    }

    [Fact]
    public async Task UnknownClientWithInvalidState_IsLocalRatherThanARedirect()
    {
        var response = await GetAsync(Valid()
            .With("client_id", "no-such-client")
            .With("state", "short"));

        await AssertLocalErrorAsync(response);
    }

    // ---- Response shape ----

    [Theory]
    [InlineData("Mixed.Case~With-All_Unreserved.0123456789")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("~.-_State0123456789abc")]
    public async Task ValidState_IsEchoedByteForByte(string state)
    {
        var parameters = AssertSafeRedirect(
            await GetAsync(Valid().With("state", state).With("response_type", "token")));

        Assert.Equal(state, parameters["state"]);
    }

    /// <summary>A registered URI that already carries a query keeps it and gains the error fields.</summary>
    [Fact]
    public async Task RegisteredUriWithAQuery_KeepsItAndAppendsTheErrorFields()
    {
        var response = await GetAsync(Valid()
            .With("redirect_uri", RegisteredUriWithQuery)
            .With("response_type", "token"));

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith(RegisteredUriWithQuery + "&", location, StringComparison.Ordinal);
        var parameters = HttpUtility.ParseQueryString(new Uri(location).Query);
        Assert.Equal("blue", parameters["tenant"]);
        Assert.Equal(OAuthErrorCodes.UnsupportedResponseType, parameters["error"]);
    }

    [Fact]
    public async Task ValidRequest_IsAnsweredLocallyBecauseTheFlowIsNotActivated()
    {
        var response = await GetAsync(Valid());

        Assert.Equal(HttpStatusCode.NotImplemented, response.StatusCode);
        Assert.Null(response.Headers.Location);
        AssertBrowserSecurityHeaders(response);
    }

    [Fact]
    public async Task EveryResponse_CarriesTheBrowserSecurityHeaders()
    {
        var local = await GetAsync(Valid().With("client_id", "no-such-client"));
        var redirected = await GetAsync(Valid().With("response_type", "token"));
        var accepted = await GetAsync(Valid());

        foreach (var response in new[] { local, redirected, accepted })
        {
            AssertBrowserSecurityHeaders(response);
        }
    }

    [Fact]
    public async Task PostToTheAuthorizationEndpoint_IsNotSupported()
    {
        using var http = _fixture.CreateNonRedirectingHttpClient();
        await SeedAsync();

        var response = await http.PostAsync(
            "/oauth2/authorize",
            new FormUrlEncodedContent(new Dictionary<string, string>()),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
    }

    // ---- Sensitive values and audit ----

    /// <summary>
    /// Drives every failure family with recognisable values and then reads back what the endpoint
    /// persisted. The redirect URL is allowed to carry <c>state</c> — that is the whole point of a
    /// safe redirect — but nothing durable may.
    /// </summary>
    [Fact]
    public async Task RecognisableSensitiveValues_DoNotReachAuditRecords()
    {
        await GetAsync(Valid().With("response_type", "token"));
        await GetAsync(Valid().With("scope", "openid unknown_scope"));
        await GetAsync(Valid().With("client_id", "no-such-client"));
        await GetAsync(Valid().With("redirect_uri", "https://attacker.test/callback?secret=leak"));
        await GetAsync(Valid());

        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var records = await dbContext.AuditLogs
            .AsNoTracking()
            .Where(log => log.Action.StartsWith("oidc.authorize"))
            .ToListAsync(TestContext.Current.CancellationToken);

        Assert.NotEmpty(records);
        foreach (var record in records)
        {
            var serialized = string.Join(
                '',
                record.Action,
                record.TargetType,
                record.TargetId,
                record.ActorName,
                record.Description,
                record.BeforeSnapshot,
                record.AfterSnapshot,
                record.CorrelationId);

            Assert.DoesNotContain(CanaryState, serialized, StringComparison.Ordinal);
            Assert.DoesNotContain(CanaryNonce, serialized, StringComparison.Ordinal);
            Assert.DoesNotContain(CanaryChallenge, serialized, StringComparison.Ordinal);
            Assert.DoesNotContain("attacker.test", serialized, StringComparison.Ordinal);
            Assert.DoesNotContain("secret=leak", serialized, StringComparison.Ordinal);
            Assert.DoesNotContain(RegisteredUri, serialized, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// A local rejection has no registered subject to audit, so unauthenticated traffic cannot grow
    /// the audit table. The counter in <c>AuthMetrics</c> carries that volume instead.
    /// </summary>
    [Fact]
    public async Task LocallyRejectedRequests_WriteNoAuditRecord()
    {
        using var scope = _fixture.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var before = await dbContext.AuditLogs
            .CountAsync(log => log.Action.StartsWith("oidc.authorize"), TestContext.Current.CancellationToken);

        await GetAsync(Valid().With("client_id", "another-missing-client"));

        var after = await dbContext.AuditLogs
            .CountAsync(log => log.Action.StartsWith("oidc.authorize"), TestContext.Current.CancellationToken);
        Assert.Equal(before, after);
    }

    // ---- Regression: the capability is not advertised ----

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-authorization-server")]
    public async Task DiscoveryDocuments_DoNotAdvertiseTheAuthorizationEndpoint(string path)
    {
        using var http = _fixture.CreateHttpClient();

        var document = await http.GetFromJsonAsync<JsonElement>(
            path,
            TestContext.Current.CancellationToken);

        Assert.False(document.TryGetProperty("authorization_endpoint", out _));
        Assert.False(document.TryGetProperty("code_challenge_methods_supported", out _));
        Assert.Empty(document.GetProperty("response_types_supported").EnumerateArray());
        var grantTypes = document.GetProperty("grant_types_supported")
            .EnumerateArray()
            .Select(value => value.GetString())
            .ToList();
        Assert.DoesNotContain("authorization_code", grantTypes);
    }

    private string Issuer => _fixture.Services.GetRequiredService<JwtOptions>().Issuer;

    private static void AssertBrowserSecurityHeaders(HttpResponseMessage response)
    {
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Contains("no-cache", response.Headers.Pragma.ToString(), StringComparison.Ordinal);
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
    }

    private static async Task<string> AssertLocalErrorAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.False(response.Headers.Contains("Location"));
        AssertBrowserSecurityHeaders(response);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain("href", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(CanaryState, body, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryNonce, body, StringComparison.Ordinal);
        Assert.DoesNotContain(CanaryChallenge, body, StringComparison.Ordinal);
        return body;
    }

    private System.Collections.Specialized.NameValueCollection AssertSafeRedirect(
        HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        AssertBrowserSecurityHeaders(response);

        var location = response.Headers.Location!;
        Assert.StartsWith(RegisteredUri + "?", location.ToString(), StringComparison.Ordinal);
        var parameters = HttpUtility.ParseQueryString(location.Query);
        Assert.Equal(Issuer, parameters["iss"]);
        return parameters;
    }

    private async Task<HttpResponseMessage> GetAsync(QueryBuilder query)
    {
        await SeedAsync();
        using var http = _fixture.CreateNonRedirectingHttpClient();
        return await http.GetAsync("/oauth2/authorize" + query.Build(), TestContext.Current.CancellationToken);
    }

    private static QueryBuilder Valid()
    {
        return new QueryBuilder()
            .With("response_type", "code")
            .With("client_id", InteractiveAppId)
            .With("redirect_uri", RegisteredUri)
            .With("scope", "openid profile")
            .With("state", CanaryState)
            .With("nonce", CanaryNonce)
            .With("code_challenge", CanaryChallenge)
            .With("code_challenge_method", "S256");
    }

    private async Task SeedAsync()
    {
        await SeedLock.WaitAsync(TestContext.Current.CancellationToken);
        try
        {
            if (_seeded)
            {
                return;
            }

            using var scope = _fixture.Services.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();

            var interactive = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = InteractiveAppId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword("authorize-contract-secret"),
                AppName = "Authorize Contract App",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.PerApplication,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = "openid profile",
                AllowRefreshToken = false
            };
            interactive.RedirectUris =
            [
                Registration(interactive.Id, RedirectUriKind.Redirect, RegisteredUri),
                Registration(interactive.Id, RedirectUriKind.Redirect, RegisteredUriWithQuery),
                Registration(interactive.Id, RedirectUriKind.PostLogout, PostLogoutUri)
            ];

            var inactive = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = InactiveAppId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword("authorize-inactive-secret"),
                AppName = "Authorize Inactive App",
                IsActive = false,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.PerApplication,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = true,
                AllowedScopes = "openid profile"
            };
            inactive.RedirectUris =
            [
                Registration(inactive.Id, RedirectUriKind.Redirect, RegisteredUri)
            ];

            var nonInteractive = new AppRegistrationEntity
            {
                Id = Guid.NewGuid(),
                AppId = NonInteractiveAppId,
                AppSecretHash = BCrypt.Net.BCrypt.HashPassword("authorize-plain-secret"),
                AppName = "Authorize Plain App",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow,
                AudienceMode = AudienceMode.Shared,
                ClientType = OidcClientType.Confidential,
                AllowAuthorizationCode = false,
                AllowedScopes = "openid"
            };

            dbContext.AppRegistrations.AddRange(interactive, inactive, nonInteractive);
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
            _seeded = true;
        }
        finally
        {
            SeedLock.Release();
        }
    }

    private static AppRedirectUriEntity Registration(Guid appId, RedirectUriKind kind, string uri)
    {
        return new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = appId,
            Kind = kind,
            CanonicalUri = uri
        };
    }

    private sealed class QueryBuilder
    {
        private readonly List<KeyValuePair<string, string>> _values = [];

        public QueryBuilder With(string name, string value)
        {
            _values.RemoveAll(pair => pair.Key == name);
            _values.Add(new KeyValuePair<string, string>(name, value));
            return this;
        }

        public QueryBuilder Without(string name)
        {
            _values.RemoveAll(pair => pair.Key == name);
            return this;
        }

        /// <summary>Repeats a parameter with its existing value, so duplicates match exactly.</summary>
        public QueryBuilder Duplicate(string name)
        {
            var existing = _values.First(pair => pair.Key == name);
            _values.Add(existing);
            return this;
        }

        public string Build()
        {
            return "?" + string.Join(
                '&',
                _values.Select(pair =>
                    $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
        }
    }
}
