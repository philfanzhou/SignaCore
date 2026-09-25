using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using SignaCore.Host;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

public sealed partial class OidcMultiInstanceAcceptanceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TokenMatrix_DiscoveryValidationAndUserInfo_AgreeAcrossInstances(bool swap)
    {
        using var logs = new CapturingLoggerProvider();
        using var loggerFactory = LoggerFactory.Create(builder => builder.SetMinimumLevel(LogLevel.Information)
            .AddFilter("Microsoft.AspNetCore", LogLevel.Warning)
            .AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning).AddProvider(logs));
        void Configure(IServiceCollection services)
        {
            services.RemoveAll<ILoggerFactory>();
            services.AddSingleton<ILoggerFactory>(loggerFactory);
        }
        using var first = CreateInstance(configureTestServices: Configure);
        using var second = CreateInstance(configureTestServices: Configure);
        var a = swap ? second : first;
        var b = swap ? first : second;
        // Login setup belongs to the separate login matrix. The diagnostic contract here
        // covers code-issued tokens, Discovery, and UserInfo, including rejected inputs.
        var cookie = await LoginOnInstanceAsync(a);
        var diagnosticStart = logs.Messages.Count;
        var tokens = await MatrixTokensAsync(a, b, cookie);
        var discovery = await GetDiscoveryAsync(a);
        foreach (var host in new[] { a, b })
        {
            using var http = NonRedirectingClient(host);
            foreach (var path in new[] { "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server" })
            {
                var actual = await http.GetFromJsonAsync<JsonElement>(path, TestContext.Current.CancellationToken);
                Assert.True(JsonElement.DeepEquals(discovery, actual), "Discovery documents differ.");
            }
            var published = await http.GetFromJsonAsync<JsonElement>(new Uri(discovery.GetProperty("jwks_uri").GetString()!).PathAndQuery,
                TestContext.Current.CancellationToken);
            AssertNoPrivateMaterial(published);
            Assert.True(JsonElement.DeepEquals(await GetJwksAsync(a), published), "Published JWKS differ.");
        }
        Assert.Equal(new[] { "RS256" }, discovery.GetProperty("id_token_signing_alg_values_supported").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(new[] { "S256" }, discovery.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(x => x.GetString()));
        Assert.Equal(new[] { "code" }, discovery.GetProperty("response_types_supported").EnumerateArray().Select(x => x.GetString()));
        Assert.Contains("authorization_code", discovery.GetProperty("grant_types_supported").EnumerateArray().Select(x => x.GetString()));
        var parameters = await MatrixValidationAsync(b, "JWT");
        Assert.True(AcceptsIdToken(tokens.Id, parameters, tokens.Access, requireSuccess: true), "The standard client rejected the issued ID token.");
        var id = new JwtSecurityTokenHandler().ReadJwtToken(tokens.Id);
        var key = a.Services.GetRequiredService<IKeyManager>().GetCurrentKey();
        using var alienRsa = RSA.Create(2048);
        var alien = new RsaSecurityKey(alienRsa) { KeyId = key.KeyId };
        var canaries = new List<string> { tokens.Id, tokens.Access, LoginUser, LoginPassword, ClientSecret };
        foreach (var variant in new[] { "issuer", "signature", "kid", "expired", "future", "nonce", "audience", "type" })
        {
            var mutation = MutateMatrixToken(tokens.Id, variant == "signature" ? alien : key, variant);
            canaries.Add(mutation);
            Assert.False(AcceptsIdToken(mutation, parameters, tokens.Access), "ID-token validation accepted the " + variant + " mutation.");
        }
        var otherClient = parameters.Clone();
        otherClient.ValidAudience = "other-client";
        Assert.False(AcceptsIdToken(tokens.Id, otherClient, tokens.Access), "An ID token crossed client audiences.");
        Assert.False(AcceptsIdToken(tokens.Access, parameters, tokens.Access), "An access token impersonated an ID token.");
        foreach (var host in new[] { a, b })
        {
            using var profile = await MatrixUserInfoAsync(host, tokens.Access);
            Assert.Equal(HttpStatusCode.OK, profile.StatusCode);
            var body = await profile.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
            Assert.True(id.Subject == body.GetProperty("sub").GetString(), "ID token and UserInfo subjects differ.");
            Assert.Contains("name", body.EnumerateObject().Select(x => x.Name));
            Assert.All(body.EnumerateObject(), property => Assert.Contains(property.Name, new[] { "sub", "name", "nickname" }));
            foreach (var variant in new[] { "issuer", "signature", "expired", "audience", "client", "type" })
            {
                var mutation = MutateMatrixToken(tokens.Access, variant == "signature" ? alien : key, variant);
                canaries.Add(mutation);
                using var rejected = await MatrixUserInfoAsync(host, mutation);
                await AssertMatrixUserInfoRejectedAsync(rejected);
            }
            using var impersonation = await MatrixUserInfoAsync(host, tokens.Id);
            await AssertMatrixUserInfoRejectedAsync(impersonation);
        }
        // SC-11 intersects the originally granted scope with current application policy.
        using (var scope = a.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            (await db.AppRegistrations.SingleAsync(x => x.AppId == SuccessAppId, TestContext.Current.CancellationToken)).AllowedScopes = "openid";
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }
        foreach (var host in new[] { a, b })
        {
            using var response = await MatrixUserInfoAsync(host, tokens.Access);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
            Assert.Equal(new[] { "sub" }, body.EnumerateObject().Select(x => x.Name));
        }
        Assert.Contains(logs.Messages, line => line.Contains("UserInfo request rejected. Reason=token_validation", StringComparison.Ordinal));
        Assert.Contains(logs.Messages, line => line.Contains("Reason=audience_binding", StringComparison.Ordinal));
        Assert.True(canaries.All(value => logs.Messages.Skip(diagnosticStart).All(line => !line.Contains(value, StringComparison.Ordinal))),
            "A sensitive canary appeared in product diagnostics.");
    }

    [Fact]
    public async Task TokenMatrix_RotatedKeysRemainVerifiable_AndSignatureBypassIsDetected()
    {
        using var a = CreateInstance();
        using var b = CreateInstance();
        var cookie = await LoginOnInstanceAsync(a);
        var before = await MatrixTokensAsync(a, b, cookie);
        using (var scope = a.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var active = await db.SecurityKeys.SingleAsync(x => x.IsActive, TestContext.Current.CancellationToken);
            active.ExpiresAt = DateTimeOffset.UtcNow.AddDays(1);
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }
        await a.Services.GetRequiredService<IKeyManager>().RotateKeyAsync(TestContext.Current.CancellationToken);
        await b.Services.GetRequiredService<IKeyManager>().RefreshKeysAsync(TestContext.Current.CancellationToken);
        var after = await MatrixTokensAsync(b, a, cookie);
        Assert.NotEqual(new JwtSecurityTokenHandler().ReadJwtToken(before.Id).Header.Kid,
            new JwtSecurityTokenHandler().ReadJwtToken(after.Id).Header.Kid);
        var shared = await MatrixValidationAsync(b, "JWT");
        Assert.True(AcceptsIdToken(before.Id, shared, before.Access), "Retained key rejected the old ID token.");
        Assert.True(AcceptsIdToken(after.Id, shared, after.Access), "Peer JWKS rejected the rotated ID token.");
        using var isolated = CreateInstance(_isolatedBootstrapFilePath);
        var disconnected = await MatrixValidationAsync(isolated, "JWT");
        void MustReject(TokenValidationParameters validation) => Assert.False(AcceptsIdToken(after.Id, validation, after.Access),
            "Disconnected signing authority accepted the token.");
        MustReject(disconnected);
        var unsafeValidation = disconnected.Clone();
        unsafeValidation.SignatureValidator = (raw, _) => new JwtSecurityTokenHandler().ReadJwtToken(raw);
        unsafeValidation.ValidateIssuerSigningKey = false;
        Assert.Throws<Xunit.Sdk.FalseException>(() => MustReject(unsafeValidation));
    }

    private async Task<(string Id, string Access)> MatrixTokensAsync(WebApplicationFactory<Program> issuer,
        WebApplicationFactory<Program> redeemer, string cookie)
    {
        var code = ExtractQueryValue(await AuthorizeWithIdentityCookieAsync(issuer, BuildSuccessAuthorizeUrl(), cookie), "code");
        using var http = NonRedirectingClient(redeemer);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes(SuccessAppId + ":" + ClientSecret)));
        using var response = await http.PostAsync("/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["code"] = code,
            ["redirect_uri"] = SuccessRegisteredUri, ["code_verifier"] = CodeVerifier
        }), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        return (body.GetProperty("id_token").GetString()!, body.GetProperty("access_token").GetString()!);
    }

    private static async Task<TokenValidationParameters> MatrixValidationAsync(WebApplicationFactory<Program> host, string type) => new()
    {
        ValidIssuer = (await GetDiscoveryAsync(host)).GetProperty("issuer").GetString(), ValidAudience = SuccessAppId,
        IssuerSigningKeys = (await GetJwksAsync(host)).GetProperty("keys").EnumerateArray().Select(x => new JsonWebKey(x.GetRawText())).ToArray(),
        ValidAlgorithms = [SecurityAlgorithms.RsaSha256], ValidTypes = [type], ValidateIssuerSigningKey = true,
        TryAllIssuerSigningKeys = false, ClockSkew = TimeSpan.Zero
    };

    private static bool AcceptsIdToken(string raw, TokenValidationParameters parameters, string accessToken, bool requireSuccess = false)
    {
        try
        {
            new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(raw, parameters, out var validated);
            new OpenIdConnectProtocolValidator { RequireTimeStampInNonce = false }.ValidateTokenResponse(new OpenIdConnectProtocolValidationContext
            {
                ClientId = SuccessAppId, Nonce = SuccessNonce, ValidatedIdToken = (JwtSecurityToken)validated,
                ProtocolMessage = new OpenIdConnectMessage { IdToken = raw, AccessToken = accessToken }
            });
            return true;
        }
        catch (Exception error) when (error is SecurityTokenException or OpenIdConnectProtocolException or ArgumentException)
        {
            // Never attach validator exceptions (which can contain tokens/claims) to diagnostics.
            if (requireSuccess) Assert.Fail("Validator rejection: " + error.GetType().Name + " " + System.Text.RegularExpressions.Regex.Match(error.Message, @"IDX\d+").Value);
            return false;
        }
    }

    private static string MutateMatrixToken(string raw, SecurityKey key, string variant)
    {
        var original = new JwtSecurityTokenHandler().ReadJwtToken(raw);
        var payload = JwtPayload.Deserialize(original.Payload.SerializeToJson());
        var header = new JwtHeader(new SigningCredentials(key, SecurityAlgorithms.RsaSha256)) { ["typ"] = original.Header.Typ };
        switch (variant)
        {
            case "issuer": payload["iss"] = "https://other-issuer.test"; break;
            case "kid": header["kid"] = "unknown-key"; break;
            case "expired": payload["exp"] = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds(); payload.Remove("nbf"); break;
            case "future": payload["nbf"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(); break;
            case "nonce": payload["nonce"] = "another-nonce"; break;
            case "audience": payload["aud"] = "other-client"; break;
            case "client": payload["client_id"] = "other-client"; break;
            case "type": header["typ"] = "other-token"; break;
        }
        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(header, payload));
    }

    private static async Task<HttpResponseMessage> MatrixUserInfoAsync(WebApplicationFactory<Program> host, string token)
    {
        using var http = NonRedirectingClient(host);
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await http.GetAsync("/oauth2/userinfo", TestContext.Current.CancellationToken);
    }

    private static async Task AssertMatrixUserInfoRejectedAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        Assert.Contains("error=\"invalid_token\"", response.Headers.WwwAuthenticate.ToString(), StringComparison.Ordinal);
        Assert.False(body.TryGetProperty("sub", out _));
        Assert.False(body.TryGetProperty("name", out _));
    }
}
