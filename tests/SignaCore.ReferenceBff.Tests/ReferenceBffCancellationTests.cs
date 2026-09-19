extern alias BffSample;

using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Xunit;

namespace SignaCore.ReferenceBff.Tests;

/// <summary>
/// The outbound-cancellation contract of the reference BFF: the Discovery, JWKS, and
/// token-exchange calls of the OIDC handler observe the request's cancellation, so an abandoned
/// sign-in aborts the backchannel instead of running to completion detached.
/// </summary>
public sealed class ReferenceBffCancellationTests(SignaCoreHostFixture fixture)
    : IClassFixture<SignaCoreHostFixture>
{
    [Fact]
    public async Task CancellingTheLogin_AbortsThePendingDiscoveryCall()
    {
        var blocking = new BlockingBackchannelHandler();
        using var backchannel = new HttpClient(blocking)
        {
            BaseAddress = new Uri("https://blocking-authority.example.test")
        };
        using var bff = BffTestServer.Create(
            "https://blocking-authority.example.test",
            SignaCoreHostFixture.ClientId,
            SignaCoreHostFixture.ClientSecret,
            SignaCoreHostFixture.RedirectUri,
            backchannel);

        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var client = bff.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://bff.localhost"),
            AllowAutoRedirect = false
        });
        using var request = new HttpRequestMessage(HttpMethod.Get, "/bff/login");

        var operation = client.SendAsync(request, cancellation.Token);
        // Give the pipeline time to reach the blocked Discovery call, then abandon it.
        await Task.Delay(TimeSpan.FromMilliseconds(300), TestContext.Current.CancellationToken);
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);

        // The backchannel call observed the cancellation rather than hanging to its timeout.
        Assert.True(blocking.ObservedCancellation);
    }

    /// <summary>
    /// Fails the request only when the caller's token fires; any earlier fault would break the
    /// test with a different exception.
    /// </summary>
    private sealed class BlockingBackchannelHandler : DelegatingHandler
    {
        public bool ObservedCancellation { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                ObservedCancellation = true;
                throw;
            }

            throw new InvalidOperationException("The blocking backchannel must never complete.");
        }
    }
}
