using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Domain.Services;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

/// <summary>
/// The <c>PS-13</c> interactive access token constructor as a pure function: the exact header and
/// payload shape, the single-string AppId audience with no shared-audience fallback, the captured
/// instant with the fixed 15-minute lifetime, the reserved-claim policy against enrichment
/// injection, the serialized-length bound as the only failure, the precondition programming
/// errors whose messages carry no input value, and the per-call <c>kid</c> of <c>EV-16</c>.
/// </summary>
public sealed class InteractiveAccessTokenFactoryTests
{
    private const string Issuer = "https://issuer.example";
    private const string SharedAudience = "SignaCore.Services";
    private const string ClientId = "interactive-client";
    private const string AuthMethod = IdentityConstants.AuthMethodPassword;
    private const string CanonicalScope = "openid profile";
    private const string DisplayName = "Test User";
    private const string Nickname = "tester";

    /// <summary>
    /// A whole-second instant captured at test start, so the fixed validation parameters see a
    /// live token (nbf reached, exp 15 minutes away) while the expected iat/nbf/exp stay exact.
    /// </summary>
    private static readonly DateTimeOffset Now =
        DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());

    private static JwtOptions CreateJwtOptions() => new()
    {
        Issuer = Issuer,
        Audience = SharedAudience,
        TokenExpirationHours = 2
    };

    private static RsaSecurityKey CreateKey(string keyId = "test-key-id") =>
        new(System.Security.Cryptography.RSA.Create(2048)) { KeyId = keyId };

    private static InteractiveAccessTokenFactory CreateFactory(ILogger<InteractiveAccessTokenFactory>? logger = null) =>
        new(CreateJwtOptions(), logger ?? NullLogger<InteractiveAccessTokenFactory>.Instance);

    private static InteractiveAccessTokenDescriptor CreateDescriptor(
        Guid? accountId = null,
        string? clientId = ClientId,
        Guid? sessionId = null,
        string? authMethod = AuthMethod,
        string? scope = CanonicalScope,
        string? displayName = DisplayName,
        string? nickname = Nickname,
        IReadOnlyList<Claim>? enrichmentClaims = null) =>
        new(
            accountId ?? Guid.NewGuid(),
            clientId!,
            sessionId ?? Guid.NewGuid(),
            authMethod!,
            scope!,
            displayName,
            nickname,
            enrichmentClaims ?? []);

    private static InteractiveAccessTokenResult.Issued CreateIssued(
        InteractiveAccessTokenDescriptor? descriptor = null,
        RsaSecurityKey? key = null,
        ILogger<InteractiveAccessTokenFactory>? logger = null)
    {
        var result = CreateFactory(logger).Create(
            descriptor ?? CreateDescriptor(),
            key ?? CreateKey(),
            Now);
        return Assert.IsType<InteractiveAccessTokenResult.Issued>(result);
    }

    private static JsonElement ReadPayload(string token)
    {
        var payloadSegment = token.Split('.')[1];
        return JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(payloadSegment)).RootElement.Clone();
    }

    // ---- Scenario 1 + acceptance 1/2: the exact header and payload ----

    [Fact]
    public void Create_ProducesTheExactPs13HeaderAndPayload()
    {
        var descriptor = CreateDescriptor();
        var key = CreateKey();
        var issued = CreateIssued(descriptor, key);

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(issued.AccessToken);

        // Header: exactly alg, kid, typ — nothing else.
        Assert.Equal(
            ["alg", "kid", "typ"],
            jwt.Header.Keys.OrderBy(name => name, StringComparer.Ordinal));
        Assert.Equal(SecurityAlgorithms.RsaSha256, jwt.Header.Alg);
        Assert.Equal(key.KeyId, jwt.Header.Kid);
        Assert.Equal(JwtTokenService.AccessTokenType, jwt.Header.Typ);

        // Payload: exactly the bound claim set plus the two given basic claims.
        var payload = ReadPayload(issued.AccessToken);
        var expectedNames = new[]
        {
            "iss", "aud", "nbf", "exp", "iat", "jti",
            "sub", "client_id", "sid", "auth_method", "scope", "name", "nickname"
        };
        Assert.Equal(
            expectedNames.OrderBy(name => name, StringComparer.Ordinal),
            payload.EnumerateObject().Select(property => property.Name)
                .OrderBy(name => name, StringComparer.Ordinal));

        Assert.Equal(Issuer, payload.GetProperty("iss").GetString());
        // The audience is the single application AppId as one JSON string, never an array and
        // never the deployment-wide shared audience.
        Assert.Equal(JsonValueKind.String, payload.GetProperty("aud").ValueKind);
        Assert.Equal(ClientId, payload.GetProperty("aud").GetString());
        Assert.NotEqual(SharedAudience, payload.GetProperty("aud").GetString());

        var expectedIat = Now.ToUnixTimeSeconds();
        Assert.Equal(expectedIat, payload.GetProperty("iat").GetInt64());
        Assert.Equal(expectedIat, payload.GetProperty("nbf").GetInt64());
        Assert.Equal(
            expectedIat + IdentityConstants.InteractiveAccessTokenLifetimeSeconds,
            payload.GetProperty("exp").GetInt64());

        Assert.Equal(descriptor.AccountId.ToString("D"), payload.GetProperty("sub").GetString());
        Assert.Equal(ClientId, payload.GetProperty("client_id").GetString());
        Assert.Equal(descriptor.SessionId.ToString("D"), payload.GetProperty("sid").GetString());
        Assert.Equal(AuthMethod, payload.GetProperty("auth_method").GetString());
        Assert.Equal(CanonicalScope, payload.GetProperty("scope").GetString());
        Assert.Equal(DisplayName, payload.GetProperty("name").GetString());
        Assert.Equal(Nickname, payload.GetProperty("nickname").GetString());

        // The returned id and expiry are the jti and exp of the token.
        Assert.Equal(Guid.Parse(payload.GetProperty("jti").GetString()!), issued.TokenId);
        Assert.Equal(
            DateTimeOffset.FromUnixTimeSeconds(
                expectedIat + IdentityConstants.InteractiveAccessTokenLifetimeSeconds),
            issued.ExpiresAt);
    }

    [Fact]
    public void Create_OmitsNameAndNickname_WhenNotGiven_AndVaryTheJtiPerCall()
    {
        var issued = CreateIssued(CreateDescriptor(displayName: null, nickname: null));
        var payload = ReadPayload(issued.AccessToken);
        Assert.False(payload.TryGetProperty("name", out _));
        Assert.False(payload.TryGetProperty("nickname", out _));

        var second = CreateIssued();
        Assert.NotEqual(issued.TokenId, second.TokenId);
    }

    [Fact]
    public void Create_ProducesATokenTheAtJwtValidationAccepts()
    {
        var key = CreateKey();
        var issued = CreateIssued(key: key);

        var principal = new JwtSecurityTokenHandler().ValidateToken(
            issued.AccessToken,
            new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = Issuer,
                ValidateAudience = true,
                ValidAudience = ClientId,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidTypes = [JwtTokenService.AccessTokenType]
            },
            out _);
        Assert.NotNull(principal);
    }

    // ---- Scenario 2 + acceptance 3: type and audience confusion fail ----

    [Fact]
    public void TheSameToken_FailsValidation_AsAPlainJwtOrUnderTheSharedAudience()
    {
        var key = CreateKey();
        var issued = CreateIssued(key: key);
        var handler = new JwtSecurityTokenHandler();

        Assert.Throws<SecurityTokenInvalidTypeException>(() => handler.ValidateToken(
            issued.AccessToken,
            new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = Issuer,
                ValidateAudience = true,
                ValidAudience = ClientId,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidTypes = ["JWT"]
            },
            out _));

        Assert.Throws<SecurityTokenInvalidAudienceException>(() => handler.ValidateToken(
            issued.AccessToken,
            new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = Issuer,
                ValidateAudience = true,
                ValidAudience = SharedAudience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidTypes = [JwtTokenService.AccessTokenType]
            },
            out _));
    }

    // ---- Scenario 3 + acceptance 4: the reserved-claim policy ----

    [Fact]
    public void EnrichmentClaims_CannotReplaceBoundClaims_AndSurviveInInputOrder()
    {
        const string canary = "injected-canary-value";
        var descriptor = CreateDescriptor(enrichmentClaims:
        [
            new Claim("SUB", canary),
            new Claim("AUD", canary),
            new Claim("scope", canary),
            new Claim("sid", canary),
            new Claim("jti", canary),
            new Claim("Nonce", canary),
            new Claim("exp", canary),
            new Claim("IAT", canary),
            new Claim("auth_time", canary),
            new Claim("role", "admin"),
            new Claim("role", "OrderService"),
            new Claim(IdentityConstants.ClaimPermission, "users.read"),
            new Claim("department", "canary-department"),
        ]);
        var capture = new CapturingLogger();
        var issued = CreateIssued(descriptor, logger: capture);
        var payload = ReadPayload(issued.AccessToken);

        // Every bound claim exists exactly once with the constructor's value; the injected
        // canary reaches none of them, and the dropped nonce/auth_time never appear.
        Assert.Equal(JsonValueKind.String, payload.GetProperty("aud").ValueKind);
        Assert.Equal(ClientId, payload.GetProperty("aud").GetString());
        Assert.Equal(descriptor.AccountId.ToString("D"), payload.GetProperty("sub").GetString());
        Assert.Equal(descriptor.SessionId.ToString("D"), payload.GetProperty("sid").GetString());
        Assert.Equal(CanonicalScope, payload.GetProperty("scope").GetString());
        Assert.Equal(issued.TokenId.ToString("D"), payload.GetProperty("jti").GetString());
        Assert.Equal(Now.ToUnixTimeSeconds(), payload.GetProperty("iat").GetInt64());
        Assert.Equal(
            Now.ToUnixTimeSeconds() + IdentityConstants.InteractiveAccessTokenLifetimeSeconds,
            payload.GetProperty("exp").GetInt64());
        Assert.False(payload.TryGetProperty("nonce", out _));
        Assert.False(payload.TryGetProperty("auth_time", out _));
        var serializedPayload = payload.GetRawText();
        Assert.DoesNotContain(canary, serializedPayload, StringComparison.Ordinal);

        // The non-reserved enrichment survives in input order: the duplicate role becomes one
        // ordered array, then Permission, then the custom claim.
        var enrichmentNames = payload.EnumerateObject()
            .Select(property => property.Name)
            .Where(name => name is "role" or "Permission" or "department")
            .ToList();
        Assert.Equal(["role", "Permission", "department"], enrichmentNames);
        Assert.Equal(
            ["admin", "OrderService"],
            payload.GetProperty("role").EnumerateArray()
                .Select(value => value.GetString()));
        Assert.Equal("users.read", payload.GetProperty("Permission").GetString());
        Assert.Equal("canary-department", payload.GetProperty("department").GetString());

        // The warning states only the dropped count — nine reserved types were injected.
        var warning = Assert.Single(capture.Messages);
        Assert.Contains("9", warning, StringComparison.Ordinal);
        Assert.DoesNotContain(canary, warning, StringComparison.Ordinal);
        Assert.DoesNotContain("department", warning, StringComparison.Ordinal);
        Assert.DoesNotContain(issued.AccessToken[..32], warning, StringComparison.Ordinal);
    }

    // ---- Scenario 4 + acceptance 5: the serialized-length bound ----

    [Fact]
    public void AnOversizedToken_FailsClosed_AtTheBoundary()
    {
        var key = CreateKey();
        var factory = CreateFactory();

        InteractiveAccessTokenResult CreateWithFiller(int fillerLength) =>
            factory.Create(
                CreateDescriptor(enrichmentClaims:
                    [new Claim("ext_data", new string('a', fillerLength))]),
                key,
                Now);

        // The serialized length is monotonic in the filler, so the boundary is a binary search:
        // the largest passing filler issues a token of at most the bound, and one more step
        // refuses issuance.
        var low = 0;
        var high = 20_000;
        Assert.IsType<InteractiveAccessTokenResult.Issued>(CreateWithFiller(low));
        Assert.IsType<InteractiveAccessTokenResult.ExceedsMaximumLength>(CreateWithFiller(high));
        while (high - low > 3)
        {
            var middle = (low + high) / 2;
            if (CreateWithFiller(middle) is InteractiveAccessTokenResult.Issued)
            {
                low = middle;
            }
            else
            {
                high = middle;
            }
        }

        var boundary = Assert.IsType<InteractiveAccessTokenResult.Issued>(CreateWithFiller(low));
        Assert.True(boundary.AccessToken.Length <= IdentityConstants.InteractiveTokenMaxSerializedLength);
        Assert.True(
            boundary.AccessToken.Length > IdentityConstants.InteractiveTokenMaxSerializedLength - 8,
            "The boundary token should sit at the bound, not far below it.");
        Assert.IsType<InteractiveAccessTokenResult.ExceedsMaximumLength>(CreateWithFiller(high));

        // The documented oversized shape from the readiness prototype also fails, and neither
        // the failure nor the log carries a token fragment or a claim value.
        var oversizedCapture = new CapturingLogger();
        var oversized = CreateFactory(oversizedCapture).Create(
            CreateDescriptor(enrichmentClaims: Enumerable
                .Range(0, 100)
                .Select(_ => new Claim(
                    IdentityConstants.ClaimPermission,
                    new string('p', 256)))
                .ToList()),
            key,
            Now);
        Assert.IsType<InteractiveAccessTokenResult.ExceedsMaximumLength>(oversized);
        Assert.All(oversizedCapture.Messages, message =>
        {
            Assert.DoesNotContain("ext_data", message, StringComparison.Ordinal);
            Assert.DoesNotContain(new string('p', 32), message, StringComparison.Ordinal);
        });
    }

    // ---- Scenario 5 + acceptance 6: precondition programming errors ----

    [Fact]
    public void Preconditions_Throw_WithMessagesThatCarryNoInputValue()
    {
        var key = CreateKey();
        var factory = CreateFactory();

        void AssertRejects(InteractiveAccessTokenDescriptor descriptor, string canary)
        {
            var exception = Assert.ThrowsAny<ArgumentException>(() =>
                factory.Create(descriptor, key, Now));
            Assert.DoesNotContain(canary, exception.Message, StringComparison.Ordinal);
        }

        // The canary sits in the offending field where a value exists, and in the display name
        // for the empty-field violations, so no message can echo either back.
        AssertRejects(
            CreateDescriptor(accountId: Guid.Empty, displayName: "CANARY-DISPLAY"),
            "CANARY-DISPLAY");
        AssertRejects(
            CreateDescriptor(sessionId: Guid.Empty, displayName: "CANARY-DISPLAY"),
            "CANARY-DISPLAY");
        AssertRejects(
            CreateDescriptor(clientId: string.Empty, displayName: "CANARY-DISPLAY"),
            "CANARY-DISPLAY");
        AssertRejects(
            CreateDescriptor(authMethod: string.Empty, displayName: "CANARY-DISPLAY"),
            "CANARY-DISPLAY");
        AssertRejects(CreateDescriptor(scope: "CANARY-SCOPE"), "CANARY-SCOPE");
        AssertRejects(CreateDescriptor(scope: "profile openid"), "profile openid");
        AssertRejects(CreateDescriptor(scope: "profile"), "profile");
        AssertRejects(CreateDescriptor(scope: "openid unknown_scope"), "unknown_scope");
        AssertRejects(CreateDescriptor(scope: "openid openid"), "openid openid");
        AssertRejects(CreateDescriptor(scope: "openid ", displayName: "CANARY-DISPLAY"), "openid ");

        Assert.ThrowsAny<ArgumentException>(() =>
            factory.Create(CreateDescriptor(), CreateKey(string.Empty), Now));

        Assert.Throws<ArgumentNullException>(() => factory.Create(null!, key, Now));
        Assert.Throws<ArgumentNullException>(() =>
            factory.Create(CreateDescriptor(), null!, Now));
    }

    [Fact]
    public void TheFullCanonicalScope_IsAccepted()
    {
        var issued = CreateIssued(CreateDescriptor(scope: "openid profile offline_access"));
        var payload = ReadPayload(issued.AccessToken);
        Assert.Equal("openid profile offline_access", payload.GetProperty("scope").GetString());
    }

    // ---- Scenario 6 + acceptance 7: EV-16 key rotation ----

    [Fact]
    public void EachCallCarriesTheKidOfTheKeyItWasGiven()
    {
        var firstKey = CreateKey("rotated-key-one");
        var secondKey = CreateKey("rotated-key-two");

        var first = CreateIssued(key: firstKey);
        var second = CreateIssued(key: secondKey);

        var handler = new JwtSecurityTokenHandler();
        Assert.Equal("rotated-key-one", handler.ReadJwtToken(first.AccessToken).Header.Kid);
        Assert.Equal("rotated-key-two", handler.ReadJwtToken(second.AccessToken).Header.Kid);

        // Each token validates under its own key and fails under the other.
        foreach (var (token, own, other) in new[]
                 {
                     (first.AccessToken, firstKey, secondKey),
                     (second.AccessToken, secondKey, firstKey)
                 })
        {
            Assert.NotNull(handler.ValidateToken(
                token,
                CreateValidationParameters(own),
                out _));
            Assert.ThrowsAny<SecurityTokenException>(() => handler.ValidateToken(
                token,
                CreateValidationParameters(other),
                out _));
        }

        static TokenValidationParameters CreateValidationParameters(RsaSecurityKey key) => new()
        {
            ValidateIssuer = true,
            ValidIssuer = Issuer,
            ValidateAudience = true,
            ValidAudience = ClientId,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidTypes = [JwtTokenService.AccessTokenType]
        };
    }

    private sealed class CapturingLogger : ILogger<InteractiveAccessTokenFactory>
    {
        private readonly List<string> _messages = [];

        public IReadOnlyList<string> Messages => _messages;

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            _messages.Add(formatter(state, exception));
    }
}
