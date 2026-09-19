extern alias BffSample;

using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SignaCore.Host;
using Xunit;

namespace SignaCore.ReferenceBff.Tests;

/// <summary>
/// The reference BFF against the real SignaCore host: the full Authorization Code + PKCE login
/// over the real authorize and login-form endpoints, the Discovery-driven endpoint resolution,
/// and the proof that SignaCore credentials never transit the BFF.
/// </summary>
public sealed class ReferenceBffSignInTests(SignaCoreHostFixture fixture)
    : IClassFixture<SignaCoreHostFixture>
{
    [Fact]
    public async Task Login_CompletesOverTheRealSignaCoreFlow_AndEstablishesTheLocalSession()
    {
        using var authorityClient = fixture.Host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(SignaCoreHostFixture.Authority)
        });
        using var bff = BffTestServer.Create(
            SignaCoreHostFixture.Authority,
            SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            authorityClient);
        using var browser = BffTestServer.CreateBrowser(fixture.Host, bff);

        // 1. The BFF challenge redirects to SignaCore's authorize endpoint with state, nonce,
        //    and the S256 challenge of a fresh verifier.
        using var challenge = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/login"));
        using var challengeResponse = await browser.SendOnBffAsync(challenge, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, challengeResponse.StatusCode);
        var authorizeUrl = challengeResponse.Headers.Location!.ToString();
        Assert.StartsWith(SignaCoreHostFixture.Authority + "/oauth2/authorize", authorizeUrl, StringComparison.Ordinal);
        Assert.Contains("code_challenge=", authorizeUrl, StringComparison.Ordinal);
        Assert.Contains("code_challenge_method=S256", authorizeUrl, StringComparison.Ordinal);
        Assert.Contains("state=", authorizeUrl, StringComparison.Ordinal);
        Assert.Contains("nonce=", authorizeUrl, StringComparison.Ordinal);

        // 2. SignaCore sends the browser to its login form.
        using var authorize = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.IdentityBase, authorizeUrl));
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(authorize, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, authorizeResponse.StatusCode);
        var loginHandlePath = authorizeResponse.Headers.Location!.ToString();
        Assert.StartsWith("/oauth2/login?login_handle=", loginHandlePath, StringComparison.Ordinal);

        // 3. The credentials go straight to SignaCore's login endpoint; the response redirects
        //    back to the BFF callback with the code and the byte-for-byte state.
        using var login = await SignaCoreLoginDriver.PostCredentialsAsync(
            browser,
            loginHandlePath,
            SignaCoreHostFixture.Username,
            SignaCoreHostFixture.Password,
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, login.StatusCode);
        var callbackUrl = login.Headers.Location!.ToString();
        Assert.StartsWith(SignaCoreHostFixture.RedirectUri, callbackUrl);
        Assert.Contains("code=", callbackUrl, StringComparison.Ordinal);
        Assert.Contains("state=", callbackUrl, StringComparison.Ordinal);

        // 4. The BFF callback validates the correlation cookie and state, redeems the code over
        //    the backchannel, validates the ID token (iss, signature via JWKS, exp/iat, nonce,
        //    aud), and establishes the local session.
        using var callback = new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl));
        using var callbackResponse = await browser.SendOnBffAsync(callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal("/", callbackResponse.Headers.Location!.ToString());

        using var home = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/"));
        using var homeResponse = await browser.SendOnBffAsync(home, TestContext.Current.CancellationToken);
        homeResponse.EnsureSuccessStatusCode();
        var body = await homeResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("Signed in", body, StringComparison.Ordinal);

        // 5. SignaCore credentials never transit the BFF: the password appears only on the
        //    SignaCore login POST, never on any BFF request.
        Assert.DoesNotContain(
            browser.BffRequests.SelectMany(request =>
                new[] { request.Body, request.Request.RequestUri!.QueryAndFragment() }),
            value => value.Contains(SignaCoreHostFixture.Password, StringComparison.Ordinal));
        Assert.Contains(
            browser.IdentityServerRequests,
            request => request.Body.Contains(SignaCoreHostFixture.Password, StringComparison.Ordinal)
                || request.Body.Contains(Uri.EscapeDataString(SignaCoreHostFixture.Password), StringComparison.Ordinal));
    }

    [Fact]
    public async Task Diagnostics_ReportTheDiscoveryResolvedEndpoints_NotHardcodedPaths()
    {
        using var authorityClient = fixture.Host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(SignaCoreHostFixture.Authority)
        });
        using var bff = BffTestServer.Create(
            SignaCoreHostFixture.Authority,
            SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            authorityClient);
        using var browser = BffTestServer.CreateBrowser(fixture.Host, bff);

        // Sign in once (the diagnostics page requires the local session).
        using var challenge = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/login"));
        using var challengeResponse = await browser.SendOnBffAsync(challenge, TestContext.Current.CancellationToken);
        var authorizeUrl = challengeResponse.Headers.Location!.ToString();
        using var authorize = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.IdentityBase, authorizeUrl));
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(authorize, TestContext.Current.CancellationToken);
        using var login = await SignaCoreLoginDriver.PostCredentialsAsync(
            browser,
            authorizeResponse.Headers.Location!.ToString(),
            SignaCoreHostFixture.Username,
            SignaCoreHostFixture.Password,
            TestContext.Current.CancellationToken);
        using var callback = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, login.Headers.Location!.PathAndQuery));
        using var callbackResponse = await browser.SendOnBffAsync(callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);

        using var diagnostics = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/diagnostics"));
        using var diagnosticsResponse = await browser.SendOnBffAsync(diagnostics, TestContext.Current.CancellationToken);
        diagnosticsResponse.EnsureSuccessStatusCode();
        var body = await diagnosticsResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        // Every endpoint value comes from the Discovery document of the authority under test.
        Assert.Contains(
            $"{SignaCoreHostFixture.Authority}/oauth2/authorize",
            body,
            StringComparison.Ordinal);
        Assert.Contains(
            $"{SignaCoreHostFixture.Authority}/oauth2/token",
            body,
            StringComparison.Ordinal);
        Assert.Contains("jwks_uri", body, StringComparison.Ordinal);
        Assert.Contains("issuer:", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnIncompleteConfiguration_FailsAtStartupWithAClearMessage()
    {
        using var authorityClient = fixture.Host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(SignaCoreHostFixture.Authority)
        });
        using var bff = new WebApplicationFactory<BffSample.Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ReferenceBff:Authority", SignaCoreHostFixture.Authority);
            builder.UseSetting("ReferenceBff:ClientId", SignaCoreHostFixture.ClientId);
            builder.UseSetting("ReferenceBff:RedirectUri", SignaCoreHostFixture.RedirectUri);
            // The committed appsettings.json carries a non-empty placeholder; the empty value
            // here overrides it, so the secret is genuinely missing.
            builder.UseSetting("ReferenceBff:ClientSecret", "");
        });

        // The startup validation refuses the incomplete configuration with a clear message;
        // through the test host the failure surfaces when the server is first brought up. The
        // message names the missing key and echoes no configured value.
        var exception = await Assert.ThrowsAnyAsync<OptionsValidationException>(async () =>
        {
            using var client = bff.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://bff.localhost"),
                AllowAutoRedirect = false
            });
            using var response = await client.GetAsync("/bff/login", TestContext.Current.CancellationToken);
        });
        Assert.Contains(
            "ReferenceBff:ClientSecret is required.",
            exception.Message,
            StringComparison.Ordinal);
        Assert.DoesNotContain(SignaCoreHostFixture.ClientId, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnUnreachableAuthority_AnswersTheFirstLoginWithABoundedNonSensitiveError()
    {
        // A backchannel that reaches nothing: the authority host has no server behind it.
        using var deadBackchannel = new HttpClient
        {
            BaseAddress = new Uri("https://dead-authority.example.test")
        };
        using var bff = BffTestServer.Create(
            "https://dead-authority.example.test",
            SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            deadBackchannel);
        using var browser = BffTestServer.CreateBrowser(fixture.Host, bff);

        using var challenge = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/login"));
        using var response = await browser.SendOnBffAsync(challenge, TestContext.Current.CancellationToken);

        // The bounded error page, not a raw exception and not a silent run.
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(
            "/error?reason=authority_unreachable",
            response.Headers.Location!.ToString());
        using var error = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/error?reason=authority_unreachable"));
        using var errorResponse = await browser.SendOnBffAsync(error, TestContext.Current.CancellationToken);
        errorResponse.EnsureSuccessStatusCode();
        var body = await errorResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("unreachable", body, StringComparison.Ordinal);
        Assert.DoesNotContain(SignaCoreHostFixture.ClientSecret, body, StringComparison.Ordinal);
    }
}

file static class UriExtensions
{
    public static string QueryAndFragment(this Uri uri) => uri.Query + uri.Fragment;
}
