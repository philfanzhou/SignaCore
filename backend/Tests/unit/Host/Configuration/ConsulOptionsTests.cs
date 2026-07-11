using Microsoft.Extensions.Configuration;
using QuantumZhou.Identity.Host.Configuration;
using Xunit;

namespace QuantumZhou.Identity.Tests.Host.Configuration;

public class ConsulOptionsTests
{
    [Fact]
    public void Bind_ParsesConsulHttpAddrIntoHostAndPort()
    {
        var previous = Environment.GetEnvironmentVariable("CONSUL_HTTP_ADDR");
        try
        {
            Environment.SetEnvironmentVariable("CONSUL_HTTP_ADDR", "host.docker.internal:8600");
            var configuration = new ConfigurationBuilder().AddInMemoryCollection().Build();

            var options = ConsulOptions.Bind(configuration);

            Assert.Equal("host.docker.internal", options.Host);
            Assert.Equal(8600, options.Port);
        }
        finally
        {
            Environment.SetEnvironmentVariable("CONSUL_HTTP_ADDR", previous);
        }
    }
}
