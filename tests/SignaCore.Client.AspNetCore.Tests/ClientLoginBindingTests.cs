extern alias ConsumerApp;

using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The login transaction's browser binding: the start endpoint sets a callback-scoped cookie —
/// one per pending state — carrying a random binding value, and the callback must present both
/// the pending state and that cookie before anything is trusted. Every failure — a missing
/// cookie, a wrong value, or another browser's injected state — answers the same bounded
/// state-mismatch reason as an unknown state, so an injected authorization response from another
/// browser cannot complete a session (login CSRF). The binding value never reaches a log line
/// or a response body.
/// </summary>
public sealed class ClientLoginBindingTests
{
    private const string ClientId = "client-pack-app";
    private static string BindingCookieBase =>
        SignaCoreHostedLoginDefaults.SessionCookieName + SignaCoreHostedLoginDefaults.LoginBindingCookieSuffix;

    private static async Task<(WebApplicationFactory<ConsumerApp.Program> Consumer, CrossServerBrowser Browser)>
        CreateAsync(
            FakeIdentityProvider authority,
            TimeProvider? timeProvider = null,
            ILoggerProvider? loggerProvider = null)
    {
        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            "client-pack-test-secret",
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler(),
            timeProvider: timeProvider,
            loggerProvider: loggerProvider);
        var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));
        return (consumer, browser);
    }

    /// <summary>Starts a sign-in and returns the authority's immediate callback URL.</summary>
    private static async Task<string> BeginSignInAsync(CrossServerBrowser browser)
    {
        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start"));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, startResponse.StatusCode);
        using var authorize = new HttpRequestMessage(
            HttpMethod.Get, startResponse.Headers.Location!);
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(
            authorize, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, authorizeResponse.StatusCode);
        return authorizeResponse.Headers.Location!.ToString();
    }

    /// <summary>Finds the binding cookie's full Set-Cookie entry of one response, if any.</summary>
    private static string? BindingSetCookie(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var cookies))
        {
            return null;
        }

        return cookies.FirstOrDefault(cookie => cookie.StartsWith(
            BindingCookieBase + ".", StringComparison.Ordinal));
    }

    private static (string Name, string Value) ParseCookie(string setCookie)
    {
        var equals = setCookie.IndexOf('=');
        Assert.True(equals > 0);
        var name = setCookie[..equals];
        var value = setCookie[(equals + 1)..].Split(';', StringSplitOptions.TrimEntries)[0];
        return (name, value);
    }

    /// <summary>Extracts the pending state from an immediate callback URL.</summary>
    private static string StateOf(string callbackUrl)
    {
        var query = callbackUrl[callbackUrl.IndexOf('?')..];
        foreach (var member in query.TrimStart('?').Split('&'))
        {
            var pair = member.Split('=', 2);
            if (pair[0] == "state")
            {
                return Uri.UnescapeDataString(pair[1]);
            }
        }

        throw new InvalidOperationException("The callback URL carried no state.");
    }

    /// <summary>A browser with no cookie container: every cookie must be attached by hand, so a
    /// test can play an attacker's browser holding exactly the cookies it chooses.</summary>
    private static HttpClient CreateCookielessClient(WebApplicationFactory<ConsumerApp.Program> consumer) =>
        new(consumer.Server.CreateHandler()) { BaseAddress = new Uri("https://bff.localhost") };

    [Fact]
    public async Task AStartedSignIn_SetsABindingCookieScopedToTheCallbackPath_AndRemovesItOnCompletion()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start"));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, startResponse.StatusCode);
        var bindingSetCookie = BindingSetCookie(startResponse);
        Assert.NotNull(bindingSetCookie);
        Assert.Contains("path=/auth/callback", bindingSetCookie, StringComparison.Ordinal);
        Assert.Contains("secure", bindingSetCookie, StringComparison.Ordinal);
        Assert.Contains("httponly", bindingSetCookie, StringComparison.Ordinal);
        Assert.Contains("samesite=lax", bindingSetCookie, StringComparison.OrdinalIgnoreCase);
        var (bindingName, bindingValue) = ParseCookie(bindingSetCookie!);
        // The cookie is named per pending state and carries a fresh random value.
        Assert.StartsWith(BindingCookieBase + ".", bindingName, StringComparison.Ordinal);
        Assert.NotEqual(BindingCookieBase + ".", bindingName);
        Assert.False(string.IsNullOrEmpty(bindingValue));

        // The full chain completes with the binding cookie replayed by the shared container.
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
        var finishedCookie = BindingSetCookie(callbackResponse);
        Assert.NotNull(finishedCookie);
        var (finishedName, finishedValue) = ParseCookie(finishedCookie!);
        Assert.Equal(bindingName, finishedName);
        Assert.Equal(string.Empty, finishedValue);
        Assert.Contains("expires=Thu, 01 Jan 1970", finishedCookie, StringComparison.Ordinal);

        using var dashboard = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/dashboard"));
        using var dashboardResponse = await browser.SendOnConsumerAsync(
            dashboard, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, dashboardResponse.StatusCode);
    }

    [Fact]
    public async Task TwoConcurrentSignInStarts_KeepIndependentBindings()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        // Two tabs of one browser start sign-ins concurrently: two distinct binding cookies.
        var firstCookie = await StartAndReadBindingCookieAsync(browser);
        var secondCookie = await StartAndReadBindingCookieAsync(browser);
        Assert.NotEqual(firstCookie.Name, secondCookie.Name);

        // Both cookies replay on the callback path, and each handshake consumes its own. The
        // fabricated code is redeemed upstream; the failure — an ID token whose nonce belongs
        // to no pending handshake — proves the binding and the state were both accepted, so the
        // first tab's handshake never trips over the second tab's binding cookie.
        using var callback = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, $"/auth/callback?code=first&state={StateFromCookieName(firstCookie.Name)}&iss={FakeIdentityProvider.BaseAddress}"));
        using var callbackResponse = await browser.SendOnConsumerAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.DoesNotContain(
            "reason=state_mismatch",
            callbackResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.Contains(
            "reason=invalid_token",
            callbackResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.Single(authority.RedeemedCodes);
        return;

        static string StateFromCookieName(string name) => name[(name.LastIndexOf('.') + 1)..];
    }

    private static async Task<(string Name, string Value)> StartAndReadBindingCookieAsync(
        CrossServerBrowser browser)
    {
        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start"));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        var setCookie = BindingSetCookie(startResponse);
        Assert.NotNull(setCookie);
        return ParseCookie(setCookie!);
    }

    [Fact]
    public async Task ACallbackWithoutTheBindingCookie_IsRejectedLikeAStateMismatch_AndConsumesTheState()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;

        var callbackUrl = await BeginSignInAsync(browser);

        // The attacker's browser — no cookies at all — presents the victim's callback URL.
        using var attacker = CreateCookielessClient(consumer);
        using var injected = new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl));
        using var injectedResponse = await attacker.SendAsync(
            injected, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, injectedResponse.StatusCode);
        Assert.Contains(
            "reason=state_mismatch",
            injectedResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        var finished = BindingSetCookie(injectedResponse);
        Assert.NotNull(finished);
        Assert.Equal(string.Empty, ParseCookie(finished!).Value);
        Assert.Empty(authority.RedeemedCodes);

        // The state was consumed by the injected attempt: the victim's own retry cannot succeed.
        using var retry = new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl));
        using var retryResponse = await browser.SendOnConsumerAsync(
            retry, TestContext.Current.CancellationToken);
        Assert.Contains(
            "reason=state_mismatch",
            retryResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.Empty(authority.RedeemedCodes);
    }

    [Fact]
    public async Task ACallbackWithAWrongBindingValue_IsRejectedLikeAStateMismatch()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;

        var callbackUrl = await BeginSignInAsync(browser);
        var bindingName = BindingCookieBase + "." + StateOf(callbackUrl);

        using var attacker = CreateCookielessClient(consumer);
        using var wrongValue = new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl));
        wrongValue.Headers.TryAddWithoutValidation("Cookie", $"{bindingName}=not-the-binding-value");
        using var wrongValueResponse = await attacker.SendAsync(
            wrongValue, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, wrongValueResponse.StatusCode);
        Assert.Contains(
            "reason=state_mismatch",
            wrongValueResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.Empty(authority.RedeemedCodes);
    }

    [Fact]
    public async Task AnInjectedStateWithTheAttackersOwnBindingCookie_IsRejected()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;

        // The victim starts a sign-in; the callback URL (and its state) is now known.
        var victimCallbackUrl = await BeginSignInAsync(browser);

        // The attacker starts a sign-in of their own and harvests their binding cookie.
        using var attackerBrowser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));
        using var _2 = attackerBrowser;
        var (attackerBindingName, attackerBindingValue) = await StartAndReadBindingCookieAsync(attackerBrowser);
        Assert.False(string.IsNullOrEmpty(attackerBindingValue));

        // The attacker's browser carries its own binding cookie but the victim's state.
        using var attacker = CreateCookielessClient(consumer);
        using var forged = new HttpRequestMessage(HttpMethod.Get, new Uri(victimCallbackUrl));
        forged.Headers.TryAddWithoutValidation(
            "Cookie", $"{attackerBindingName}={attackerBindingValue}");
        using var forgedResponse = await attacker.SendAsync(
            forged, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, forgedResponse.StatusCode);
        Assert.Contains(
            "reason=state_mismatch",
            forgedResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.Empty(authority.RedeemedCodes);
    }

    [Fact]
    public async Task AnExpiredPendingSignIn_FailsEvenWithTheCorrectBindingCookie()
    {
        var clock = new ManualTimeProvider();
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateAsync(authority, timeProvider: clock);
        await using var _ = consumer;

        var (bindingName, bindingValue, callbackUrl) = await BeginAndReadBindingAsync(browser);

        // Past the pending sign-in's five-minute lifetime the handshake is dead; even the
        // correct binding cookie cannot revive it, and the answer is the same fixed failure.
        clock.Advance(TimeSpan.FromMinutes(6));
        using var client = CreateCookielessClient(consumer);
        using var callback = new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl));
        callback.Headers.TryAddWithoutValidation("Cookie", $"{bindingName}={bindingValue}");
        using var callbackResponse = await client.SendAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Contains(
            "reason=state_mismatch",
            callbackResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.Empty(authority.RedeemedCodes);
    }

    /// <summary>Drives one start and authorize; returns the binding cookie of that exact
    /// handshake together with the authority's immediate callback URL.</summary>
    private static async Task<(string Name, string Value, string CallbackUrl)> BeginAndReadBindingAsync(
        CrossServerBrowser browser)
    {
        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start"));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        var setCookie = BindingSetCookie(startResponse);
        Assert.NotNull(setCookie);
        var cookie = ParseCookie(setCookie!);
        using var authorize = new HttpRequestMessage(
            HttpMethod.Get, startResponse.Headers.Location!);
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(
            authorize, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Found, authorizeResponse.StatusCode);
        return (cookie.Name, cookie.Value, authorizeResponse.Headers.Location!.ToString());
    }

    [Fact]
    public async Task AFullPendingStore_RejectsWithoutWritingABindingCookie()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        // Fill the bounded pending-sign-in store: the first Capacity starts succeed.
        HttpResponseMessage last = new(HttpStatusCode.OK);
        for (var i = 0; i <= PendingSignInCapacity; i++)
        {
            last.Dispose();
            using var start = new HttpRequestMessage(
                HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start"));
            last = await browser.SendOnConsumerAsync(start, TestContext.Current.CancellationToken);
            if (i < PendingSignInCapacity)
            {
                Assert.Equal(HttpStatusCode.Found, last.StatusCode);
                Assert.StartsWith(
                    "https://idp.localhost/authorize",
                    last.Headers.Location!.ToString(),
                    StringComparison.Ordinal);
            }
        }

        // The capacity-plus-first start fails closed and writes no binding cookie.
        Assert.Equal(HttpStatusCode.Found, last.StatusCode);
        Assert.StartsWith("/auth/signin-failed", last.Headers.Location!.ToString(), StringComparison.Ordinal);
        Assert.Contains(
            "reason=session_store_full",
            last.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.Null(BindingSetCookie(last));
        last.Dispose();
    }

    private const int PendingSignInCapacity = 1_000;

    [Fact]
    public async Task TwoConcurrentCallbacks_WithTheSameState_ProduceExactlyOneSuccess()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        var callbackUrl = await BeginSignInAsync(browser);

        using var first = new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl));
        using var second = new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl));
        var firstTask = browser.SendOnConsumerAsync(first, TestContext.Current.CancellationToken);
        var secondTask = browser.SendOnConsumerAsync(second, TestContext.Current.CancellationToken);
        var responses = await Task.WhenAll(firstTask, secondTask);

        // Exactly one completion succeeds; the other answers the bounded state-mismatch reason.
        var outcomes = responses.Select(response =>
            response.StatusCode == HttpStatusCode.Found
            && response.Headers.Location!.ToString() == "/" ? "success" : "mismatch")
            .OrderBy(x => x, StringComparer.Ordinal).ToArray();
        Assert.Equal(["mismatch", "success"], outcomes);
        Assert.All(responses, response =>
            Assert.Equal(string.Empty, ParseCookie(BindingSetCookie(response)!).Value));
        Assert.Single(authority.RedeemedCodes);
    }

    [Fact]
    public async Task NoBindingValueEverReachesALogLineOrAResponseBody()
    {
        var loggerProvider = new CapturingLoggerProvider();
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateAsync(authority, loggerProvider: loggerProvider);
        await using var _ = consumer;
        using var __ = browser;

        var (bindingName, bindingValue, callbackUrl) = await BeginAndReadBindingAsync(browser);
        Assert.StartsWith(BindingCookieBase + ".", bindingName, StringComparison.Ordinal);

        // A rejected callback with the attacker's binding value neither signs in nor leaks any
        // binding material. The request goes through a cookieless client so the shared
        // container cannot silently add the genuine cookie beside the attacker's value.
        using var client = CreateCookielessClient(consumer);
        using var callback = new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl));
        callback.Headers.TryAddWithoutValidation("Cookie", $"{bindingName}=an-attacker-chosen-value");
        using var callbackResponse = await client.SendAsync(
            callback, TestContext.Current.CancellationToken);
        Assert.Contains(
            "reason=state_mismatch",
            callbackResponse.Headers.Location!.ToString(),
            StringComparison.Ordinal);

        var body = await callbackResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain(bindingValue, body, StringComparison.Ordinal);
        foreach (var line in loggerProvider.Lines)
        {
            Assert.DoesNotContain(bindingValue, line, StringComparison.Ordinal);
            Assert.DoesNotContain("an-attacker-chosen-value", line, StringComparison.Ordinal);
        }
    }
}
