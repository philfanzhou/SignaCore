using QuantumZhou.Identity.Service;
using Xunit;

namespace QuantumZhou.Identity.Tests.Service;

public class GrpcContextExtensionsTests
{
    [Theory]
    [InlineData("ipv4:127.0.0.1:5001", "127.0.0.1")]
    [InlineData("ipv4:192.168.1.1:8080", "192.168.1.1")]
    [InlineData("ipv4:10.0.0.1:443", "10.0.0.1")]
    public void ExtractIpFromPeer_WithIpv4Peer_ReturnsIp(string peer, string expectedIp)
    {
        var result = GrpcContextExtensions.ExtractIpFromPeer(peer);

        Assert.Equal(expectedIp, result);
    }

    [Fact]
    public void ExtractIpFromPeer_WithIpv6Peer_ReturnsIp()
    {
        var result = GrpcContextExtensions.ExtractIpFromPeer("ipv6:[::1]:5001");

        Assert.Equal("[::1]", result);
    }

    [Fact]
    public void ExtractIpFromPeer_WithNullPeer_ReturnsNull()
    {
        var result = GrpcContextExtensions.ExtractIpFromPeer(null);

        Assert.Null(result);
    }

    [Fact]
    public void ExtractIpFromPeer_WithEmptyPeer_ReturnsNull()
    {
        var result = GrpcContextExtensions.ExtractIpFromPeer("");

        Assert.Null(result);
    }

    [Fact]
    public void ExtractIpFromPeer_WithUnknownFormat_ReturnsAsIs()
    {
        var result = GrpcContextExtensions.ExtractIpFromPeer("unknown_format");

        Assert.Equal("unknown_format", result);
    }

    [Fact]
    public void ExtractIpFromPeer_WithIpv4NoPort_ReturnsFullAddress()
    {
        var result = GrpcContextExtensions.ExtractIpFromPeer("ipv4:192.168.1.1");

        Assert.Equal("192.168.1.1", result);
    }
}
