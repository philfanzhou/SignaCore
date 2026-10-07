extern alias ConsumerApp;

using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using SignaCore.Client.AspNetCore;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The Discovery trust boundary: the authorization, token, and JWKS endpoints must sit on the
/// verified issuer's own origin — scheme, host, and port — before anything is trusted. A
/// tampered document that points any endpoint at a second host (even a legal HTTPS one), a
/// different port, or a loopback HTTP origin the shape rules otherwise allow is rejected with
/// the existing closed failure paths: sign-in shows authority_unreachable, nothing is cached,
/// and the next refresh fetches fresh. Same-origin documents whose endpoints carry deeper paths
/// stay accepted, and a loopback Testing authority with every endpoint on its own origin works.
/// </summary>
public sealed class ClientDiscoverySameOriginTests
{
    private const string ClientId = "client-pack-app";

    private static WebApplicationFactory<ConsumerApp.Program> CreateConsumer(
        FakeIdentityProvider authority,
        string authorityAddress) =>
        ConsumerAppTestServer.Create(
            authorityAddress,
            ClientId,
            "client-pack-test-secret",
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler());

    private static async Task<HttpResponseMessage> StartSignInAsync(
        WebApplicationFactory<ConsumerApp.Program> consumer,
        string consumerBase = "https://bff.localhost")
    {
        using var client = new HttpClient(consumer.Server.CreateHandler())
        {
            BaseAddress = new Uri(consumerBase)
        };
        using var start = new HttpRequestMessage(HttpMethod.Get, "/auth/start");
        var response = await client.SendAsync(start, TestContext.Current.CancellationToken);
        return response;
    }

    private static async Task AssertStartRejectedAsync(
        WebApplicationFactory<ConsumerApp.Program> consumer)
    {
        using var response = await StartSignInAsync(consumer);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.StartsWith(
            "/auth/signin-failed",
            response.Headers.Location!.ToString(),
            StringComparison.Ordinal);
        Assert.Contains(
            "reason=authority_unreachable",
            response.Headers.Location!.ToString(),
            StringComparison.Ordinal);
    }

    private static async Task<HttpResponseMessage> DriveFullSignInAsync(
        FakeIdentityProvider authority,
        WebApplicationFactory<ConsumerApp.Program> consumer)
    {
        var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(authority.Base));
        using var _ = browser;
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

    [Fact]
    public async Task ASameOriginDocument_WithDeeperEndpointPaths_IsAccepted()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.EndpointShape = FakeIdentityProvider.DiscoveryEndpointShape.AuthorizationDeeperPath;
        using var consumer = CreateConsumer(authority, FakeIdentityProvider.BaseAddress);
        await using var _ = consumer;

        // The whole chain runs against the deeper-path same-origin endpoints.
        using var callbackResponse = await DriveFullSignInAsync(authority, consumer);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal("/", callbackResponse.Headers.Location!.ToString());
    }

    [Theory]
    [InlineData(FakeIdentityProvider.DiscoveryEndpointShape.AuthorizationCrossHost)]
    [InlineData(FakeIdentityProvider.DiscoveryEndpointShape.TokenCrossHost)]
    [InlineData(FakeIdentityProvider.DiscoveryEndpointShape.JwksCrossHost)]
    [InlineData(FakeIdentityProvider.DiscoveryEndpointShape.AuthorizationCrossPort)]
    [InlineData(FakeIdentityProvider.DiscoveryEndpointShape.TokenCrossSchemeLoopback)]
    public async Task AnyCrossOriginEndpoint_IsRejectedWithTheClosedAuthorityFailure(
        FakeIdentityProvider.DiscoveryEndpointShape shape)
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        authority.EndpointShape = shape;
        using var consumer = CreateConsumer(authority, FakeIdentityProvider.BaseAddress);
        await using var _ = consumer;

        await AssertStartRejectedAsync(consumer);

        // The rejected document was never cached: repairing it makes the very next start work,
        // proving no partial configuration was served and the refresh fetches fresh.
        authority.EndpointShape = FakeIdentityProvider.DiscoveryEndpointShape.Normal;
        using var callbackResponse = await DriveFullSignInAsync(authority, consumer);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal("/", callbackResponse.Headers.Location!.ToString());
    }

    [Fact]
    public async Task ALoopbackTestingAuthority_WithSameOriginLoopbackEndpoints_IsAccepted()
    {
        // The controlled clock also drives the package's Discovery cache refresh interval.
        var clock = new ManualTimeProvider();
        // The authority mints on the same clock the consumer validates with; a split clock
        // could stamp an iat the consumer's "now" sees as future.
        await using var authority = await FakeIdentityProvider.StartAsync(
            clock, baseAddress: "http://127.0.0.1:5099");
        var consumer = ConsumerAppTestServer.Create(
            "http://127.0.0.1:5099",
            ClientId,
            "client-pack-test-secret",
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler(),
            timeProvider: clock);
        await using var _ = consumer;

        // Development/Testing accept the explicit loopback HTTP origin, and every endpoint of
        // the document shares that origin, so the same-origin rule keeps the loopback flow alive.
        using var callbackResponse = await DriveFullSignInAsync(authority, consumer);
        Assert.Equal(HttpStatusCode.Found, callbackResponse.StatusCode);
        Assert.Equal("/", callbackResponse.Headers.Location!.ToString());

        // A loopback authority whose token endpoint jumps to another host is rejected once the
        // cached configuration has aged past the refresh interval — the next refresh fetches
        // the tampered document and refuses it; the loopback shape exception never widens the
        // origin boundary.
        authority.EndpointShape = FakeIdentityProvider.DiscoveryEndpointShape.TokenCrossHost;
        clock.Advance(TimeSpan.FromHours(1).Add(TimeSpan.FromSeconds(1)));
        await AssertStartRejectedAsync(consumer);
    }
}
