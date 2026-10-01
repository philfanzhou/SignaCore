extern alias ConsumerApp;

using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SignaCore.Client.AspNetCore.Tests;

/// <summary>
/// The cancellation boundary of the callback: when the browser abandons a sign-in while the code
/// redemption is parked upstream, the cancellation propagates, no session is written, and no
/// half-decided state survives — the next request is simply unauthenticated.
/// </summary>
public sealed class ClientCancellationTests
{
    [Fact]
    public async Task AnAbandonedCallback_WritesNoSessionAndNoHalfState()
    {
        await using var authority = await FakeIdentityProvider.StartAsync();
        var gate = authority.HoldTokenRequests();

        var consumer = ConsumerAppTestServer.Create(
            FakeIdentityProvider.BaseAddress,
            "client-pack-app",
            "client-pack-test-secret",
            SignaCoreHostFixture.RedirectUri,
            authority.Server.CreateHandler());
        await using var _ = consumer;
        using var browser = ConsumerAppTestServer.CreateBrowserOverAuthority(
            consumer, authority.Server.CreateHandler(), new Uri(FakeIdentityProvider.BaseAddress));

        // Drive to the callback URL, then present it while the authority's token endpoint parks.
        using var start = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/start"));
        using var startResponse = await browser.SendOnConsumerAsync(
            start, TestContext.Current.CancellationToken);
        using var authorize = new HttpRequestMessage(
            HttpMethod.Get, startResponse.Headers.Location!);
        using var authorizeResponse = await browser.SendOnIdentityServerAsync(
            authorize, TestContext.Current.CancellationToken);
        var callbackUrl = authorizeResponse.Headers.Location!.ToString();

        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        // xUnit1051: the request's own token is the test's subject — cancelling it is the case.
#pragma warning disable xUnit1051
        var callbackTask = browser.SendOnConsumerAsync(
            new HttpRequestMessage(HttpMethod.Get, new Uri(callbackUrl)), cancellation.Token);
#pragma warning restore xUnit1051
        await authority.TokenArrived.WaitAsync(TimeSpan.FromSeconds(10));

        // The caller abandons the request mid-redemption.
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => callbackTask);
        gate.SetResult();

        // No session was written for the abandoned request, and the code was presented exactly
        // once — the abandoned attempt did not retry.
        using var session = new HttpRequestMessage(
            HttpMethod.Get, new Uri(browser.ConsumerBase, "/auth/session"));
        using var sessionResponse = await browser.SendOnConsumerAsync(
            session, TestContext.Current.CancellationToken);
        Assert.Equal(
            """{"authenticated":false,"requiresReauthentication":true,"displayName":null,"authorization":null}""",
            await sessionResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Single(authority.RedeemedCodes);
    }
}
