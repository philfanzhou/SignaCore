extern alias ConsumerApp;

using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The logout-return cookie's name derivation under browser cookie prefixes: a
/// <c>__Host-</c>-prefixed session cookie name must not leak its prefix into the derived name —
/// <c>__Host-</c> demands Path=/, the return cookie is scoped to the logout endpoints — so the
/// package derives <c>__Secure-&lt;rest&gt;-logout-return</c> instead, and the whole prepared
/// logout and return chain works with that name. Every other session name keeps the
/// byte-for-byte historical derivation.
/// </summary>
public sealed class ClientLogoutHostPrefixCookieTests
{
    private const string ClientId = "client-pack-app";
    private const string ClientSecret = "client-pack-test-secret";
    private const string HostSessionName = "__Host-orders.AdminSession";
    private const string DerivedName = "__Secure-orders.AdminSession-logout-return";

    private static async Task<(WebApplicationFactory<ConsumerApp.Program> Consumer, CrossServerBrowser Browser)>
        SignInAsync(FakeIdentityProvider authority, string sessionCookieName)
    {
        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler(),
            postLogoutRedirectUri: SignaCoreHostFixture.PostLogoutRedirectUri,
            configureTestServices: services => services
                .PostConfigure<SignaCoreHostedLoginOptions>(options =>
                    options.SessionCookieName = sessionCookieName));
        var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));

        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start"));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        using var authorize = new HttpRequestMessage(
            HttpMethod.Get, startResponse.Headers.Location!);
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(
            authorize, TestContext.Current.CancellationToken);
        using var callback = new HttpRequestMessage(
            HttpMethod.Get, authorizeResponse.Headers.Location!);
        using var callbackResponse = await browser.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal("/", callbackResponse.Headers.Location!.ToString());
        return (consumer, browser);
    }

    private static async Task<string> FetchCsrfTokenAsync(CrossServerBrowser browser)
    {
        using var csrf = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/csrf"));
        using var response = await browser.SendOnConsumerAsync(
            csrf, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return JsonSerializer.Deserialize<JsonElement>(body).GetProperty("token").GetString()!;
    }

    [Fact]
    public async Task AHostPrefixedSessionName_DerivesASecureLogoutReturnCookie_AndCompletesTheChain()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await SignInAsync(authority, HostSessionName);
        await using var _ = consumer;
        using var __ = browser;

        var token = await FetchCsrfTokenAsync(browser);
        using var logout = new HttpRequestMessage(
            HttpMethod.Post, new Uri(browser.ConsumerBase, "/auth/logout"));
        logout.Headers.TryAddWithoutValidation(SignaCoreHostedLoginDefaults.AntiforgeryHeaderName, token);
        using var logoutResponse = await browser.SendOnConsumerAsync(
            logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, logoutResponse.StatusCode);

        // The derived name carries no __Host- prefix (which would be refused for this path) and
        // instead keeps the __Secure- browser guarantee: Secure only, path allowed.
        Assert.True(logoutResponse.Headers.TryGetValues("Set-Cookie", out var cookies));
        var setCookie = Assert.Single(cookies, cookie => cookie.Contains("logout-return=", StringComparison.Ordinal));
        Assert.StartsWith(DerivedName + "=", setCookie, StringComparison.Ordinal);
        Assert.DoesNotContain(
            SignaCoreHostedLoginDefaults.HostCookiePrefix,
            setCookie[..setCookie.IndexOf('=')],
            StringComparison.Ordinal);
        Assert.Contains("path=/auth/logout", setCookie, StringComparison.Ordinal);
        Assert.Contains("secure", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);

        // The authority completes and returns the browser; the package consumes the one-time
        // state through the new name and finishes the cookie.
        using var completion = new HttpRequestMessage(
            HttpMethod.Get, logoutResponse.Headers.Location!);
        using var completionResponse = await browser.SendOnIdentityServerAsync(
            completion, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, completionResponse.StatusCode);
        using var landing = new HttpRequestMessage(
            HttpMethod.Get, completionResponse.Headers.Location!);
        using var landingResponse = await browser.SendOnConsumerAsync(
            landing, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, landingResponse.StatusCode);
        Assert.Equal("/signed-out", landingResponse.Headers.Location!.ToString());

        Assert.True(landingResponse.Headers.TryGetValues("Set-Cookie", out var deleted));
        var deleteCookie = Assert.Single(
            deleted, cookie => cookie.StartsWith(DerivedName + "=", StringComparison.Ordinal));
        Assert.Contains("expires=Thu, 01 Jan 1970", deleteCookie, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("orders-session", "orders-session-logout-return")]
    [InlineData(SignaCoreHostedLoginDefaults.SessionCookieName,
        SignaCoreHostedLoginDefaults.SessionCookieName + "-logout-return")]
    [InlineData("__host-orders.AdminSession", "__host-orders.AdminSession-logout-return")]
    [InlineData("__Host-", "__Secure--logout-return")]
    public async Task EveryOtherSessionName_KeepsTheByteForByteHistoricalDerivation(
        string sessionName,
        string expected)
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await SignInAsync(authority, sessionName);
        await using var _ = consumer;
        using var __ = browser;

        var token = await FetchCsrfTokenAsync(browser);
        using var logout = new HttpRequestMessage(
            HttpMethod.Post, new Uri(browser.ConsumerBase, "/auth/logout"));
        logout.Headers.TryAddWithoutValidation(SignaCoreHostedLoginDefaults.AntiforgeryHeaderName, token);
        using var logoutResponse = await browser.SendOnConsumerAsync(
            logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, logoutResponse.StatusCode);
        Assert.True(logoutResponse.Headers.TryGetValues("Set-Cookie", out var cookies));
        Assert.Contains(cookies, cookie => cookie.StartsWith(
            expected + "=", StringComparison.Ordinal));
    }
}
