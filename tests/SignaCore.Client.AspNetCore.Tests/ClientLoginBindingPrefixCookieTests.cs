extern alias ConsumerApp;

using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The login-binding cookie's name derivation under browser cookie prefixes, in the default
/// HTTPS profile. A <c>__Host-</c>-prefixed session cookie name must not leak its prefix into
/// the binding cookie's name — the binding cookie is scoped to the callback path while
/// <c>__Host-</c> demands Path=/, so every real browser would refuse the naive name and the
/// sign-in could never complete. The package derives <c>__Secure-&lt;rest&gt;-login-binding.
/// &lt;state&gt;</c> instead — the same prefix-safe derivation the logout-return cookie already
/// uses — and the whole sign-in completes with that name. Every other session name keeps the
/// byte-for-byte historical derivation. (The in-memory test browser does not enforce prefix
/// rules; the derivation is asserted directly.)
/// </summary>
public sealed class ClientLoginBindingPrefixCookieTests
{
    private const string ClientId = "client-pack-app";
    private const string ClientSecret = "client-pack-test-secret";
    private const string HostSessionName = "__Host-orders.AdminSession";
    private const string DerivedPrefix = "__Secure-orders.AdminSession-login-binding.";

    private static async Task<WebApplicationFactory<ConsumerApp.Program>> CreateConsumerAsync(
        FakeIdentityProvider authority, string sessionCookieName) =>
        ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler(),
            configureTestServices: services => services
                .PostConfigure<SignaCoreHostedLoginOptions>(options =>
                    options.SessionCookieName = sessionCookieName));

    private static async Task<(HttpResponseMessage StartResponse, CrossServerBrowser Browser)>
        StartSignInAsync(FakeIdentityProvider authority, string sessionCookieName)
    {
        var consumer = await CreateConsumerAsync(authority, sessionCookieName);
        var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));
        var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start"));
        var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        return (startResponse, browser);
    }

    private static async Task CompleteSignInAsync(CrossServerBrowser browser, HttpResponseMessage startResponse)
    {
        using var authorize = new HttpRequestMessage(
            HttpMethod.Get, startResponse.Headers.Location!);
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(
            authorize, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, authorizeResponse.StatusCode);
        using var callback = new HttpRequestMessage(
            HttpMethod.Get, authorizeResponse.Headers.Location!);
        using var callbackResponse = await browser.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal("/", callbackResponse.Headers.Location!.ToString());
    }

    private static void AssertBindingCookieShape(HttpResponseMessage startResponse, string expectedNamePrefix)
    {
        Assert.True(startResponse.Headers.TryGetValues("Set-Cookie", out var cookies));
        var binding = Assert.Single(
            cookies, cookie => cookie.Contains("-login-binding.", StringComparison.Ordinal));
        Assert.StartsWith(expectedNamePrefix, binding, StringComparison.Ordinal);
        var name = binding[..binding.IndexOf('=')];
        Assert.DoesNotContain(
            SignaCoreHostedLoginDefaults.HostCookiePrefix, name, StringComparison.Ordinal);
        Assert.Contains("path=/auth/callback", binding, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", binding, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", binding, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AHostPrefixedSessionName_DerivesASecureLoginBindingCookie_AndCompletesSignIn()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (startResponse, browser) = await StartSignInAsync(authority, HostSessionName);
        using var _ = startResponse;
        using var __ = browser;

        // The prefix-safe derivation: __Host- cannot survive on a callback-scoped cookie, so the
        // binding name carries the __Secure- prefix instead, and the Secure attribute backs it.
        AssertBindingCookieShape(startResponse, DerivedPrefix);
        Assert.Contains("secure", Assert.Single(
            startResponse.Headers.GetValues("Set-Cookie"),
            cookie => cookie.Contains("-login-binding.", StringComparison.Ordinal)),
            StringComparison.OrdinalIgnoreCase);

        // The callback reads and finishes the binding under the derived name: the whole sign-in
        // completes — impossible with the naive __Host--prefixed name in a prefix-enforcing
        // browser, and still correct in this in-memory one.
        await CompleteSignInAsync(browser, startResponse);
    }

    [Theory]
    [InlineData("orders-session", "orders-session-login-binding.")]
    [InlineData(SignaCoreHostedLoginDefaults.SessionCookieName,
        SignaCoreHostedLoginDefaults.SessionCookieName + "-login-binding.")]
    [InlineData("__Secure-orders.AdminSession", "__Secure-orders.AdminSession-login-binding.")]
    [InlineData("__host-orders.AdminSession", "__host-orders.AdminSession-login-binding.")]
    public async Task EveryOtherSessionName_KeepsTheByteForByteHistoricalDerivation(
        string sessionName, string expectedPrefix)
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (startResponse, browser) = await StartSignInAsync(authority, sessionName);
        using var _ = startResponse;
        using var __ = browser;

        AssertBindingCookieShape(startResponse, expectedPrefix);
        await CompleteSignInAsync(browser, startResponse);
    }
}
