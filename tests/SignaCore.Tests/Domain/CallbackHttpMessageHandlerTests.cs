using System.Net;
using SignaCore.Domain;
using Xunit;

namespace SignaCore.Tests.Domain;

public class CallbackHttpMessageHandlerTests
{
    [Fact]
    public void Create_UsesSecurityFocusedTransportDefaults()
    {
        using var messageHandler = CallbackHttpMessageHandler.Create(allowPrivateAddresses: false);
        var handler = Assert.IsType<SocketsHttpHandler>(messageHandler);

        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseProxy);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
        Assert.Equal(TimeSpan.FromSeconds(5), handler.ConnectTimeout);
        Assert.Equal(TimeSpan.FromMinutes(2), handler.PooledConnectionLifetime);
        Assert.Equal(50, handler.MaxConnectionsPerServer);
        Assert.NotNull(handler.ConnectCallback);
    }

    [Fact]
    public async Task SendAsync_WhenPrivateAddressesAreBlocked_RejectsLoopbackBeforeConnecting()
    {
        using var client = new HttpClient(
            CallbackHttpMessageHandler.Create(allowPrivateAddresses: false));

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.GetAsync("http://127.0.0.1:1/callback", TestContext.Current.CancellationToken));

        Assert.Contains("no permitted public address", exception.Message);
    }

    [Fact]
    public async Task SendAsync_WhenPrivateAddressesAreAllowed_AttemptsTheLoopbackConnection()
    {
        using var client = new HttpClient(
            CallbackHttpMessageHandler.Create(allowPrivateAddresses: true));

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.GetAsync("http://127.0.0.1:1/callback", TestContext.Current.CancellationToken));

        Assert.Contains("no reachable address", exception.Message);
    }
}
