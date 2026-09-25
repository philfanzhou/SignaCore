using System.Net;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Host;
using Xunit;
using static SignaCore.Tests.Integration.OAuthLoginTestSupport;

namespace SignaCore.Tests.Integration;

public sealed partial class OidcMultiInstanceAcceptanceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuthorizationMatrix_TrustAndProtocolStages_AgreeAfterSwappingInstances(bool swap)
    {
        var capture = new CapturingLoggerProvider();
        using var first = CreateInstance(configureTestServices: services => MatrixLogger(services, capture));
        using var second = CreateInstance(configureTestServices: services => MatrixLogger(services, capture));
        var a = swap ? second : first;
        var b = swap ? first : second;
        var cookie = await LoginOnInstanceAsync(a);
        using var client = NonRedirectingClient(b);
        var ct = TestContext.Current.CancellationToken;
        string? localBody = null;
        var invalidUris = new[]
        {
            "https://bff.success.test/callback/", "https://BFF.success.test/callback?canary=success-redirect",
            "https://bff.success.test/CALLBACK?canary=success-redirect",
            "https://bff.success.test:443/callback?canary=success-redirect",
            "https://bff.success.test:8443/callback?canary=success-redirect",
            "https://bff.success.test/%63allback?canary=success-redirect",
            "https://bff.success.test/callback?canary=other", "https://untrusted.example/callback",
            "https://bff.success.test.attacker.example/callback", "//untrusted.example/callback", ""
        };
        foreach (var uri in invalidUris)
        {
            using var response = await client.SendAsync(AuthorizeGet(ChangeAuthorization("redirect_uri", uri), cookie), ct);
            var body = await AssertAuthorizationLocalAsync(response);
            localBody ??= body;
            Assert.Equal(localBody, body);
        }
        foreach (var clientId in new string?[] { null, "", "unknown-matrix-client" })
        {
            using var response = await client.SendAsync(AuthorizeGet(ChangeAuthorization("client_id", clientId), cookie), ct);
            Assert.Equal(localBody, await AssertAuthorizationLocalAsync(response));
        }
        foreach (var field in new[] { "client_id", "redirect_uri" })
        {
            var query = QueryHelpers.ParseQuery(new Uri("https://localhost" + BuildSuccessAuthorizeUrl()).Query);
            using var response = await client.SendAsync(AuthorizeGet(BuildSuccessAuthorizeUrl() + "&" + field + "=" + Uri.EscapeDataString(query[field].ToString()), cookie), ct);
            await AssertAuthorizationLocalAsync(response);
        }

        var protocol = new (string Field, string? Value, string Error)[]
        {
            ("response_type", null, "unsupported_response_type"), ("response_type", "token", "unsupported_response_type"),
            ("state", null, "invalid_request"), ("state", "short", "invalid_request"),
            ("state", new string('a', 129), "invalid_request"),
            ("nonce", null, "invalid_request"), ("nonce", "invalid+nonce", "invalid_request"),
            ("scope", null, "invalid_scope"), ("scope", "profile", "invalid_scope"),
            ("scope", "openid openid", "invalid_scope"), ("scope", "openid unknown", "invalid_scope"),
            ("code_challenge", null, "invalid_request"), ("code_challenge", new string('.', 43), "invalid_request"),
            ("code_challenge", SuccessChallenge + "=", "invalid_request"),
            ("code_challenge_method", null, "invalid_request"), ("code_challenge_method", "plain", "invalid_request"),
            ("code_challenge_method", "s256", "invalid_request")
        };
        foreach (var (field, value, error) in protocol)
        {
            using var response = await client.SendAsync(AuthorizeGet(ChangeAuthorization(field, value), cookie), ct);
            AssertAuthorizationRedirect(response, error, field == "state" ? null : SuccessState);
            var body = await response.Content.ReadAsStringAsync(ct);
            Assert.False(body.Contains(SuccessNonce, StringComparison.Ordinal), "Protocol error body echoed a nonce.");
        }
        // Caller-controlled issuer input cannot replace the response issuer (RFC 9207 binding).
        using var mixed = await client.SendAsync(AuthorizeGet(
            ChangeAuthorization("response_type", "token") + "&iss=https%3A%2F%2Funtrusted.example", cookie), ct);
        AssertAuthorizationRedirect(mixed, "unsupported_response_type", SuccessState);
        var expectedIssuer = (await GetDiscoveryAsync(a)).GetProperty("issuer").GetString();
        Assert.Equal(expectedIssuer, QueryHelpers.ParseQuery(mixed.Headers.Location!.Query)["iss"].ToString());

        var canaries = new[] { SuccessState, SuccessNonce, SuccessChallenge, cookie, LoginPassword, ClientSecret };
        Assert.NotEmpty(capture.Messages);
        foreach (var line in capture.Messages)
        foreach (var value in canaries)
            Assert.False(line.Contains(value, StringComparison.Ordinal), "Authorization stage log contained a canary.");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AuthorizationMatrix_TamperedContinuationFailsOnTheOtherInstance(bool swap)
    {
        using var first = CreateInstance();
        using var second = CreateInstance();
        var a = swap ? second : first;
        var b = swap ? first : second;
        using var aClient = NonRedirectingClient(a);
        var login = await BeginSuccessLoginViaAuthorizeAsync(a.Services, aClient);
        using var bClient = NonRedirectingClient(b);
        var changed = (login.Handle[0] == 'A' ? "B" : "A") + login.Handle[1..];
        using var response = await bClient.GetAsync("/oauth2/login?login_handle=" + changed, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.False(body.Contains(login.Handle, StringComparison.Ordinal));
        Assert.False(body.Contains(SuccessRegisteredUri, StringComparison.Ordinal));
        // Rejection did not consume the original cross-instance continuation.
        using var original = await bClient.GetAsync("/oauth2/login?login_handle=" + login.Handle, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
    }

    [Fact]
    public async Task AuthorizationMatrix_NegativeSelfCheck_DetectsDisabledRedirectTrust()
    {
        // Fault exists only in an isolated test deployment, never in the normal A/B services.
        using var unsafeHost = CreateInstance(_isolatedBootstrapFilePath!, services =>
        {
            services.RemoveAll<IOidcAuthorizationRequestValidator>();
            services.AddSingleton<IOidcAuthorizationRequestValidator, UnsafeRedirectValidator>();
        });
        using var client = NonRedirectingClient(unsafeHost);
        using var response = await client.GetAsync(ChangeAuthorization("redirect_uri", "https://untrusted.example/callback"), TestContext.Current.CancellationToken);
        await Assert.ThrowsAnyAsync<Xunit.Sdk.XunitException>(() => AssertAuthorizationLocalAsync(response));
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
    }

    private static string ChangeAuthorization(string field, string? value)
    {
        var query = QueryHelpers.ParseQuery(new Uri("https://localhost" + BuildSuccessAuthorizeUrl()).Query)
            .ToDictionary(pair => pair.Key, pair => (string?)pair.Value.ToString());
        if (value is null) query.Remove(field); else query[field] = value;
        return QueryHelpers.AddQueryString("/oauth2/authorize", query);
    }

    private static async Task<string> AssertAuthorizationLocalAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        return await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
    }

    private static void AssertAuthorizationRedirect(HttpResponseMessage response, string error, string? state)
    {
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        var location = response.Headers.Location!;
        Assert.Equal(new Uri(SuccessRegisteredUri).GetLeftPart(UriPartial.Path), location.GetLeftPart(UriPartial.Path));
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal(error, query["error"].ToString());
        if (state is null) Assert.False(query.ContainsKey("state"));
        else Assert.Equal(state, query["state"].ToString());
        Assert.False(query.ContainsKey("code"));
        Assert.False(query.ContainsKey("nonce"));
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
    }

    private static void MatrixLogger(IServiceCollection services, CapturingLoggerProvider capture)
    {
        services.RemoveAll<ILoggerFactory>();
        services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
        {
            logging.AddProvider(capture);
            logging.SetMinimumLevel(LogLevel.Information);
            // Match the product's production category levels (not the sample BFF's policy).
            logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
            logging.AddFilter("Microsoft.EntityFrameworkCore", LogLevel.Warning);
        }));
    }

    private sealed class UnsafeRedirectValidator : IOidcAuthorizationRequestValidator
    {
        public Task<OidcAuthorizationValidationResult> ValidateAsync(OidcAuthorizationParameters parameters, CancellationToken cancellationToken) =>
            Task.FromResult<OidcAuthorizationValidationResult>(new OidcAuthorizationValidationResult.RedirectRejection(
                SuccessAppId, Guid.NewGuid(), parameters.Single("redirect_uri")!, "invalid_request", "Invalid request.", null));
    }
}
