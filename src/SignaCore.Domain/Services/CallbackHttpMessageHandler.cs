using System.Net;
using System.Net.Sockets;

namespace SignaCore.Domain;

/// <summary>
/// Pins callback connections to an address that was checked immediately before the TCP connect.
/// This closes the DNS-rebinding window between URL validation and HttpClient's own DNS lookup.
/// </summary>
public static class CallbackHttpMessageHandler
{
    public static HttpMessageHandler Create(bool allowPrivateAddresses)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            MaxConnectionsPerServer = 50,
            AutomaticDecompression = DecompressionMethods.None
        };

        handler.ConnectCallback = async (context, cancellationToken) =>
        {
            var addresses = await Dns.GetHostAddressesAsync(
                context.DnsEndPoint.Host,
                cancellationToken);
            var candidates = allowPrivateAddresses
                ? addresses
                : addresses.Where(address => !CallbackUrlValidator.IsNonPublicAddress(address)).ToArray();

            Exception? lastError = null;
            foreach (var address in candidates)
            {
                var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(
                        new IPEndPoint(address, context.DnsEndPoint.Port),
                        cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch (Exception exception) when (exception is SocketException or OperationCanceledException)
                {
                    socket.Dispose();
                    lastError = exception;
                    if (exception is OperationCanceledException)
                    {
                        throw;
                    }
                }
            }

            throw new HttpRequestException(
                allowPrivateAddresses
                    ? $"Callback host '{context.DnsEndPoint.Host}' has no reachable address."
                    : $"Callback host '{context.DnsEndPoint.Host}' has no permitted public address.",
                lastError);
        };

        return handler;
    }
}
