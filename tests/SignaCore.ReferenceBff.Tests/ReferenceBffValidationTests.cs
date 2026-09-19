extern alias BffSample;

using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SignaCore.ReferenceBff.Tests;

/// <summary>
/// The reference BFF's ID-token and handshake validation against a controllable authority: the
/// standard validations (<c>iss</c>, signature via JWKS, <c>aud</c>, <c>nonce</c>) and the
/// state/correlation gate. Every defect fails the sign-in, never starts a token exchange when
/// the handshake is broken, and never establishes a local session.
/// </summary>
public sealed class ReferenceBffValidationTests
{
    private const string ClientId = "reference-bff";

    [Fact]
    public async Task ACorrectResponse_EstablishesTheLocalSession()
    {
        await using var authority = await FakeAuthority.StartAsync();
        using var backchannel = authority.CreateClient();
        await using var bff = CreateBff(backchannel);
        using var browser = CreateBrowser(bff, authority.Server.CreateHandler());

        var final = await DriveSignInAsync(browser);
        Assert.Equal(new Uri(browser.BffBase, "/"), final.Uri);
        Assert.Contains("Signed in", final.Body, StringComparison.Ordinal);
        Assert.Equal("fake-authority-subject", final.Subject);
        Assert.NotEmpty(authority.RedeemedCodes);
    }

    [Theory]
    [InlineData(FakeAuthority.TokenDefect.WrongIssuer)]
    [InlineData(FakeAuthority.TokenDefect.WrongAudience)]
    [InlineData(FakeAuthority.TokenDefect.WrongNonce)]
    [InlineData(FakeAuthority.TokenDefect.SigningKeyAbsentFromJwks)]
    public async Task ADefectiveIdToken_FailsTheSignInWithoutALocalSession(
        FakeAuthority.TokenDefect defect)
    {
        await using var authority = await FakeAuthority.StartAsync();
        authority.Defect = defect;
        using var backchannel = authority.CreateClient();
        await using var bff = CreateBff(backchannel);
        using var browser = CreateBrowser(bff, authority.Server.CreateHandler());

        var final = await DriveSignInAsync(browser);

        // The bounded error page: the defect detail never reaches the browser, and the sample
        // establishes no local session for the failed principal.
        Assert.Contains("could not complete", final.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("Signed in", final.Body, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.OK, final.Response.StatusCode);
    }

    [Fact]
    public async Task ATamperedState_FailsTheCallbackWithoutAnyTokenExchange()
    {
        await using var authority = await FakeAuthority.StartAsync();
        using var backchannel = authority.CreateClient();
        await using var bff = CreateBff(backchannel);
        using var browser = CreateBrowser(bff, authority.Server.CreateHandler());

        var callbackUrl = await BeginSignInAndGetCallbackUrlAsync(browser);
        var tampered = TamperState(callbackUrl);

        using var callback = new HttpRequestMessage(HttpMethod.Get, new Uri(tampered));
        using var callbackResponse = await browser.SendOnBffAsync(callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.StartsWith("/error", callbackResponse.Headers.Location!.ToString(), StringComparison.Ordinal);

        await AssertNoExchangeAndNoSessionAsync(authority, browser);
    }

    [Fact]
    public async Task AMissingCorrelationCookie_FailsTheCallbackWithoutAnyTokenExchange()
    {
        await using var authority = await FakeAuthority.StartAsync();
        using var backchannel = authority.CreateClient();
        await using var bff = CreateBff(backchannel);
        using var browser = CreateBrowser(bff, authority.Server.CreateHandler());

        var callbackUrl = await BeginSignInAndGetCallbackUrlAsync(browser);

        // The correlation cookie is dropped before the callback arrives — exactly what a CSRF
        // or session-fixation attempt looks like to the handshake.
        browser.DropAllBffCookies();

        using var callback = new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl));
        using var callbackResponse = await browser.SendOnBffAsync(callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.StartsWith("/error", callbackResponse.Headers.Location!.ToString(), StringComparison.Ordinal);

        await AssertNoExchangeAndNoSessionAsync(authority, browser);
    }

    // ---- Driving ----

    private static WebApplicationFactory<BffSample.Program> CreateBff(HttpClient backchannel) =>
        BffTestServer.Create(
            FakeAuthority.BaseAddress,
            ClientId,
            "reference-bff-test-secret",
            SignaCoreHostFixture.RedirectUri,
            backchannel);

    private static CrossServerBrowser CreateBrowser(
        WebApplicationFactory<BffSample.Program> bff,
        HttpMessageHandler authorityHandler) =>
        // The SignaCore host is not part of the fake-authority scenarios; the same browser shape
        // is reused with the fake authority serving the identity role.
        BffTestServer.CreateBrowserOverAuthority(
            bff, authorityHandler, new Uri(FakeAuthority.BaseAddress));

    private static async Task<(HttpResponseMessage Response, Uri Uri, string Body, string Subject)> DriveSignInAsync(
        CrossServerBrowser browser)
    {
        var callbackUrl = await BeginSignInAndGetCallbackUrlAsync(browser);
        using var callback = new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl));
        using var callbackResponse = await browser.SendOnBffAsync(callback, TestContext.Current.CancellationToken);
        var next = callbackResponse.Headers.Location?.ToString() ?? "/";
        using var finalRequest = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, next));
        using var final = await browser.SendOnBffAsync(finalRequest, TestContext.Current.CancellationToken);
        var body = await final.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var subject = body.Contains("Signed in", StringComparison.Ordinal)
            ? ExtractSubject(body)
            : string.Empty;
        return (final, new Uri(browser.BffBase, next), body, subject);
    }

    private static async Task<string> BeginSignInAndGetCallbackUrlAsync(CrossServerBrowser browser)
    {
        using var challenge = new HttpRequestMessage(HttpMethod.Get, new Uri(browser.BffBase, "/bff/login"));
        using var challengeResponse = await browser.SendOnBffAsync(challenge, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, challengeResponse.StatusCode);

        // The fake authority answers the authorize request with the immediate callback redirect.
        using var authorize = new HttpRequestMessage(
            HttpMethod.Get,
            new Uri(browser.IdentityBase, challengeResponse.Headers.Location!.PathAndQuery));
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(authorize, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, authorizeResponse.StatusCode);
        return authorizeResponse.Headers.Location!.ToString();
    }

    private static string TamperState(string callbackUrl)
    {
        var uri = new Uri(callbackUrl);
        var query = uri.Query.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(member => member.StartsWith("state=", StringComparison.Ordinal)
                ? "state=" + Uri.EscapeDataString("tampered-" + Guid.NewGuid().ToString("N"))
                : member);
        var builder = new UriBuilder(uri) { Query = string.Join("&", query) };
        return builder.Uri.ToString();
    }

    private static async Task AssertNoExchangeAndNoSessionAsync(
        FakeAuthority authority,
        CrossServerBrowser browser)
    {
        // No code was ever presented: the handshake failed before the exchange.
        Assert.Empty(authority.RedeemedCodes);
        // And no BFF session cookie was issued.
        Assert.DoesNotContain(
            browser.BffRequests,
            request => request.Request.Headers.TryGetValues("Cookie", out var cookies)
                && cookies.Any(cookie => cookie.Contains("signacore-bff-session", StringComparison.Ordinal)));
    }

    private static string ExtractSubject(string html)
    {
        var marker = "Subject: ";
        var start = html.IndexOf(marker, StringComparison.Ordinal);
        if (start < 0)
        {
            return string.Empty;
        }

        start += marker.Length;
        var end = html.IndexOf("</p>", start, StringComparison.Ordinal);
        return html[start..end];
    }

}
