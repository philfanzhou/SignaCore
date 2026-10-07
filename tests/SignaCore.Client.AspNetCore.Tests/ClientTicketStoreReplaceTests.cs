extern alias ConsumerApp;

using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The replacement semantics of <see cref="ITicketStore.ReplaceAsync"/>: a fresh sign-in swaps
/// the new ticket in and the previous session key out in one operation, an unknown, empty, or
/// null old key degrades to a plain store, a full store refuses the whole replacement without
/// touching the previous session, the default interface implementation is store-then-remove, and
/// concurrent replacements of one old key never leave the old key alive beside a new one.
/// </summary>
public sealed class ClientTicketStoreReplaceTests
{
    private const string ClientId = "client-pack-app";
    private static readonly string ExpiredBody =
        """{"authenticated":false,"requiresReauthentication":true,"displayName":null,"authorization":null}""";

    private static SignaCoreSessionTicket NewTicket(DateTimeOffset? expires = null) => new(
        new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "replace-subject")], "test")),
        DateTimeOffset.UtcNow,
        expires ?? DateTimeOffset.UtcNow.AddMinutes(15),
        "access-material",
        "id-material");

    private static string? SessionCookieValue(HttpResponseMessage response)
    {
        Assert.True(response.Headers.TryGetValues("Set-Cookie", out var cookies));
        foreach (var cookie in cookies)
        {
            if (cookie.StartsWith(SignaCoreHostedLoginDefaults.SessionCookieName + "=", StringComparison.Ordinal))
            {
                return cookie[(SignaCoreHostedLoginDefaults.SessionCookieName.Length + 1)..]
                    .Split(';', StringSplitOptions.TrimEntries)[0];
            }
        }

        return null;
    }

    private static async Task<(WebApplicationFactory<ConsumerApp.Program> Consumer, CrossServerBrowser Browser)>
        CreateAsync(
            FakeIdentityProvider authority,
            Action<IServiceCollection>? configure = null)
    {
        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            ClientId,
            "client-pack-test-secret",
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler(),
            configureTestServices: configure);
        var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));
        return (consumer, browser);
    }

    /// <summary>Drives one complete fake-authority sign-in; the shared container keeps the
    /// session cookie of the last completed sign-in.</summary>
    private static async Task<HttpResponseMessage> SignInAsync(CrossServerBrowser browser)
    {
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
        return await browser.SendOnConsumerAsync(callback, TestContext.Current.CancellationToken);
    }

    private static async Task<string> SessionBodyAsync(
        WebApplicationFactory<ConsumerApp.Program> consumer,
        string? cookieValue)
    {
        using var client = new HttpClient(consumer.Server.CreateHandler())
        {
            BaseAddress = new Uri("https://bff.localhost")
        };
        using var request = new HttpRequestMessage(HttpMethod.Get, "/auth/session");
        if (!string.IsNullOrEmpty(cookieValue))
        {
            request.Headers.TryAddWithoutValidation(
                "Cookie", $"{SignaCoreHostedLoginDefaults.SessionCookieName}={cookieValue}");
        }

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        return await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task TheInMemoryStore_ReplacesTheOldKeyAtomically()
    {
        var store = new InMemoryTicketStore();
        var first = await store.StoreAsync(NewTicket(), CancellationToken.None);
        Assert.NotNull(first);

        var second = await store.ReplaceAsync(first, NewTicket(), CancellationToken.None);
        Assert.NotNull(second);
        Assert.NotEqual(first, second);

        // The old key is gone the moment the new one exists; nothing of the old ticket survives.
        Assert.Null(await store.RetrieveAsync(first!, CancellationToken.None));
        var replaced = await store.RetrieveAsync(second!, CancellationToken.None);
        Assert.NotNull(replaced);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("a-key-that-was-never-stored")]
    public async Task TheInMemoryStore_DegradesAnUnusableOldKey_ToAPlainStore(string? oldKey)
    {
        var store = new InMemoryTicketStore();
        var key = await store.ReplaceAsync(oldKey, NewTicket(), CancellationToken.None);
        Assert.NotNull(key);
        Assert.NotNull(await store.RetrieveAsync(key!, CancellationToken.None));
    }

    [Fact]
    public async Task AFullInMemoryStore_RefusesTheReplacement_WithoutTouchingTheOldTicket()
    {
        var store = new InMemoryTicketStore();
        // Fill the default 10_000-slot store; the live ticket under test is the last one stored.
        string? live = null;
        for (var i = 0; i < 10_000; i++)
        {
            live = await store.StoreAsync(NewTicket(), CancellationToken.None);
        }

        Assert.NotNull(live);
        Assert.Null(await store.ReplaceAsync(live, NewTicket(), CancellationToken.None));

        // The refused replacement changed nothing: the previous session is still alive.
        Assert.NotNull(await store.RetrieveAsync(live!, CancellationToken.None));
    }

    [Fact]
    public async Task ConcurrentReplacementsOfOneOldKey_NeverLeaveTheOldKeyAlive()
    {
        var store = new InMemoryTicketStore();
        var oldKey = await store.StoreAsync(NewTicket(), CancellationToken.None);
        Assert.NotNull(oldKey);

        var replacements = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ =>
            store.ReplaceAsync(oldKey, NewTicket(), CancellationToken.None)));

        // Every replacement either succeeded with its own new key or failed closed; the old key
        // is dead the moment any of them landed, and every reported new key resolves.
        Assert.All(replacements, key => Assert.True(key is null || key != oldKey));
        Assert.Null(await store.RetrieveAsync(oldKey!, CancellationToken.None));
        foreach (var key in replacements.Where(key => key is not null))
        {
            Assert.NotNull(await store.RetrieveAsync(key!, CancellationToken.None));
        }
    }

    /// <summary>A custom store that only implements the four original members, exactly like the
    /// stores consumers registered before the replacement API existed.</summary>
    private sealed class LegacyStyleStore : ITicketStore
    {
        private readonly InMemoryTicketStore _inner = new();
        public List<string> Calls { get; } = [];

        public Task<string?> StoreAsync(SignaCoreSessionTicket ticket, CancellationToken cancellationToken)
        {
            Calls.Add("store");
            return _inner.StoreAsync(ticket, cancellationToken);
        }

        public Task<SignaCoreSessionTicket?> RetrieveAsync(string key, CancellationToken cancellationToken) =>
            _inner.RetrieveAsync(key, cancellationToken);

        public Task RemoveAsync(string key, CancellationToken cancellationToken)
        {
            Calls.Add("remove:" + (key.Length == 0 ? "<empty>" : key));
            return _inner.RemoveAsync(key, cancellationToken);
        }

        public int RemoveExpired(CancellationToken cancellationToken) =>
            _inner.RemoveExpired(cancellationToken);
    }

    [Fact]
    public async Task TheDefaultImplementation_IsStoreThenRemove_AndSkipsRemoveForANullOldKey()
    {
        LegacyStyleStore legacy = new();
        // The default interface body is reachable only through the interface itself — exactly
        // how the package's callback calls it on a consumer store that does not override it.
        ITicketStore store = legacy;
        var withOld = await store.ReplaceAsync("old-key", NewTicket(), CancellationToken.None);
        Assert.NotNull(withOld);
        // The default body stored first, then removed the old key; the caller saw one result.
        Assert.Equal(["store", "remove:old-key"], legacy.Calls);

        legacy.Calls.Clear();
        var withoutOld = await store.ReplaceAsync(null, NewTicket(), CancellationToken.None);
        Assert.NotNull(withoutOld);
        Assert.Equal(["store"], legacy.Calls);
    }

    [Fact]
    public async Task AReSignIn_RevokesThePreviousSessionImmediately()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateAsync(authority);
        await using var _ = consumer;
        using var __ = browser;

        using var first = await SignInAsync(browser);
        Assert.Equal("/", first.Headers.Location!.ToString());
        var firstKey = SessionCookieValue(first);
        Assert.False(string.IsNullOrEmpty(firstKey));

        // The same browser signs in again: the callback carries the old session cookie, and the
        // new cookie replaces it in the same response.
        using var second = await SignInAsync(browser);
        Assert.Equal("/", second.Headers.Location!.ToString());
        var secondKey = SessionCookieValue(second);
        Assert.False(string.IsNullOrEmpty(secondKey));
        Assert.NotEqual(firstKey, secondKey);

        // The old key is revoked the moment the new session exists; the new key answers.
        Assert.Equal(ExpiredBody, await SessionBodyAsync(consumer, firstKey));
        Assert.Contains(
            "\"authenticated\":true",
            await SessionBodyAsync(consumer, secondKey),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task AReSignInOnAFullStore_FailsClosed_AndKeepsThePreviousSession()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var (consumer, browser) = await CreateAsync(
            authority,
            configure: services => services
                .PostConfigure<SignaCoreHostedLoginOptions>(options => options.TicketCapacity = 1));
        await using var _ = consumer;
        using var __ = browser;

        using var first = await SignInAsync(browser);
        var firstKey = SessionCookieValue(first);
        Assert.False(string.IsNullOrEmpty(firstKey));

        // The store's single slot holds the live session: the replacement is refused as a whole
        // and the previous session is untouched.
        using var second = await SignInAsync(browser);
        Assert.Equal(HttpStatusCode.Found, second.StatusCode);
        Assert.Contains(
            "reason=session_store_full",
            second.Headers.Location!.ToString(),
            StringComparison.Ordinal);

        Assert.Contains(
            "\"authenticated\":true",
            await SessionBodyAsync(consumer, firstKey),
            StringComparison.Ordinal);
    }
}
