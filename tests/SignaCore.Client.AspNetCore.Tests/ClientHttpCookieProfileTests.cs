extern alias ConsumerApp;

using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The cookie profile matrix of a plain-HTTP deployment, in the Production environment with no
/// opt-in list (ADR 0008): the whole sign-in, session, CSRF, and prepared logout chain runs over
/// plain HTTP — Discovery's endpoints resolve on the plain-http origin — and every carrier
/// cookie (session, login binding, logout return, antiforgery) is written, read, and finished
/// under its plain-HTTP profile: no Secure attribute, no cookie-name prefix, unchanged
/// HttpOnly/SameSite/Path scope. The protocol semantics (single-use state, browser binding,
/// one-time code, CSRF validation) are exactly the HTTPS ones.
/// </summary>
public sealed class ClientHttpCookieProfileTests
{
    private const string ClientId = "client-pack-app";
    private const string ClientSecret = "client-pack-test-secret";
    private const string Authority = "http://192.168.55.10:5002";
    private const string ConsumerOrigin = "http://192.168.55.10:5020";
    private const string RedirectUri = ConsumerOrigin + "/auth/callback";
    private const string PostLogoutRedirectUri = ConsumerOrigin + "/auth/logout/return";
    private const string SessionName = SignaCoreHostedLoginDefaults.SessionCookieName;
    private const string BindingPrefix = SessionName + "-login-binding.";
    private const string LogoutReturnName = SessionName + "-logout-return";

    private static async Task<(WebApplicationFactory<ConsumerApp.Program> Consumer, CrossServerBrowser Browser)>
        CreatePlainHttpAppAsync(FakeIdentityProvider authority)
    {
        // No opt-in list: the plain-http Authority and RedirectUri are accepted as configured.
        var consumer = ConsumerAppTestServer.Create(
            Authority,
            ClientId,
            ClientSecret,
            RedirectUri,
            authority.Server.CreateHandler(),
            postLogoutRedirectUri: PostLogoutRedirectUri,
            environment: "Production");
        var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer,
            authority.Server.CreateHandler(),
            new Uri(Authority),
            new Uri(ConsumerOrigin));
        return (consumer, browser);
    }

    private static async Task<HttpResponseMessage> SignInAsync(CrossServerBrowser browser)
    {
        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start?returnUrl=/dashboard"));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, startResponse.StatusCode);

        // The login-binding cookie: plain derived name, no Secure attribute, callback path scope.
        Assert.True(startResponse.Headers.TryGetValues("Set-Cookie", out var startCookies));
        var binding = Assert.Single(
            startCookies, cookie => cookie.StartsWith(BindingPrefix, StringComparison.Ordinal));
        Assert.DoesNotContain("secure", binding, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", binding, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", binding, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/auth/callback", binding, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            SignaCoreHostedLoginDefaults.HostCookiePrefix,
            binding[..binding.IndexOf('=')],
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            SignaCoreHostedLoginDefaults.SecureCookiePrefix,
            binding[..binding.IndexOf('=')],
            StringComparison.Ordinal);

        // The plain-http authority is admitted as configured: the authorize redirect targets
        // its HTTP discovery endpoints.
        var authorizeUrl = startResponse.Headers.Location!.ToString();
        Assert.StartsWith(Authority + "/authorize", authorizeUrl, StringComparison.Ordinal);

        using var authorize = new HttpRequestMessage(HttpMethod.Get, authorizeUrl);
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(
            authorize, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, authorizeResponse.StatusCode);

        // The callback finishes the one-time binding cookie and writes the session cookie under
        // the plain-HTTP profile.
        using var callback = new HttpRequestMessage(
            HttpMethod.Get, authorizeResponse.Headers.Location!);
        var callbackResponse = await browser.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal("/dashboard", callbackResponse.Headers.Location!.ToString());
        Assert.True(callbackResponse.Headers.TryGetValues("Set-Cookie", out var callbackCookies));
        var session = Assert.Single(
            callbackCookies, cookie => cookie.StartsWith(SessionName + "=", StringComparison.Ordinal));
        Assert.DoesNotContain("secure", session, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", session, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", session, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", session, StringComparison.OrdinalIgnoreCase);
        var finishedBinding = Assert.Single(
            callbackCookies, cookie => cookie.StartsWith(BindingPrefix, StringComparison.Ordinal));
        Assert.Contains("expires=Thu, 01 Jan 1970", finishedBinding, StringComparison.Ordinal);
        return callbackResponse;
    }

    private static async Task<string> FetchCsrfTokenAsync(CrossServerBrowser browser)
    {
        using var csrf = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/csrf"));
        using var response = await browser.SendOnConsumerAsync(
            csrf, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // The antiforgery cookie of the plain-HTTP profile: no Secure attribute, everything else
        // unchanged.
        Assert.True(response.Headers.TryGetValues("Set-Cookie", out var cookies));
        var antiforgery = Assert.Single(cookies);
        Assert.Contains(".AspNetCore.Antiforgery.", antiforgery, StringComparison.Ordinal);
        Assert.DoesNotContain("secure", antiforgery, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", antiforgery, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", antiforgery, StringComparison.OrdinalIgnoreCase);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return JsonSerializer.Deserialize<JsonElement>(body).GetProperty("token").GetString()!;
    }

    [Fact]
    public async Task ThePlainHttpProfile_ServesTheWholeSurfaceWithUnsecuredScopedCookies()
    {
        await using var authority = await FakeIdentityProvider.StartAsync(baseAddress: Authority);
        var (consumer, browser) = await CreatePlainHttpAppAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        using var callbackResponse = await SignInAsync(browser);

        // The protected consumer route answers from the server-side session over plain HTTP.
        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var dashboardResponse = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, dashboardResponse.StatusCode);

        using var session = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/session"));
        using var sessionResponse = await browser.SendOnConsumerAsync(
            session, TestContext.Current.CancellationToken);
        var sessionBody = await sessionResponse.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken);
        Assert.Contains("\"authenticated\":true", sessionBody, StringComparison.Ordinal);

        // The CSRF boundary still gates the unsafe logout method, and the prepared logout and its
        // return complete with the plain-derived, unsecured correlation cookie.
        var token = await FetchCsrfTokenAsync(browser);
        using var logout = new HttpRequestMessage(
            HttpMethod.Post, new Uri(browser.ConsumerBase, "/auth/logout"));
        logout.Headers.TryAddWithoutValidation(SignaCoreHostedLoginDefaults.AntiforgeryHeaderName, token);
        using var logoutResponse = await browser.SendOnConsumerAsync(
            logout, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, logoutResponse.StatusCode);
        Assert.True(logoutResponse.Headers.TryGetValues("Set-Cookie", out var logoutCookies));
        var logoutReturn = Assert.Single(
            logoutCookies, cookie => cookie.StartsWith(LogoutReturnName + "=", StringComparison.Ordinal));
        Assert.DoesNotContain("secure", logoutReturn, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/auth/logout", logoutReturn, StringComparison.OrdinalIgnoreCase);
        var deletedSession = Assert.Single(
            logoutCookies, cookie => cookie.StartsWith(SessionName + "=", StringComparison.Ordinal));
        Assert.Contains("expires=Thu, 01 Jan 1970", deletedSession, StringComparison.Ordinal);

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
        var finishedReturn = Assert.Single(
            deleted, cookie => cookie.StartsWith(LogoutReturnName + "=", StringComparison.Ordinal));
        Assert.Contains("expires=Thu, 01 Jan 1970", finishedReturn, StringComparison.Ordinal);

        // The session is gone: the session endpoint answers the fixed expired body.
        using var after = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/session"));
        using var afterResponse = await browser.SendOnConsumerAsync(
            after, TestContext.Current.CancellationToken);
        var afterBody = await afterResponse.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken);
        Assert.Contains("\"authenticated\":false", afterBody, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AStructurallyIllegalHttpAuthority_IsStillRejectedAtStartup()
    {
        await using var authority = await FakeIdentityProvider.StartAsync(baseAddress: Authority);
        using var consumer = ConsumerAppTestServer.Create(
            Authority + "/identity",
            ClientId,
            ClientSecret,
            RedirectUri,
            authority.Server.CreateHandler(),
            environment: "Production");
        var exception = Assert.ThrowsAny<Exception>(() => consumer.CreateClient());
        var text = exception.ToString();
        for (var inner = exception; inner is not null; inner = inner.InnerException)
        {
            text += Environment.NewLine + inner.Message;
        }

        Assert.Contains("SignaCoreHostedLoginOptions.Authority", text, StringComparison.Ordinal);
    }
}
