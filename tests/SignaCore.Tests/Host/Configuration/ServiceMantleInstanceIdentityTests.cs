using Microsoft.Extensions.DependencyInjection;
using ServiceMantle;
using SignaCore.Host;
using SignaCore.Host.Migration;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

public sealed class ServiceMantleInstanceIdentityTests
{
    [Fact]
    public void HostComposition_GeneratesFreshDiagnosticIdentityWithStableServiceIdentity()
    {
        var firstServices = new ServiceCollection();
        firstServices.AddSignaCoreServiceMantle();
        using var first = firstServices.BuildServiceProvider();
        var secondServices = new ServiceCollection();
        secondServices.AddSignaCoreServiceMantle();
        using var second = secondServices.BuildServiceProvider();

        Assert.Equal(ServiceId.Parse("signacore"), first.GetRequiredService<ServiceId>());
        Assert.Equal(first.GetRequiredService<ServiceId>(), second.GetRequiredService<ServiceId>());
        var firstId = first.GetRequiredService<InstanceId>();
        var secondId = second.GetRequiredService<InstanceId>();
        Assert.Matches("^signacore-[0-9a-f]{32}$", firstId.Value);
        Assert.Matches("^signacore-[0-9a-f]{32}$", secondId.Value);
        Assert.Equal(firstId, InstanceId.Parse(firstId.Value));
        Assert.Equal(secondId, InstanceId.Parse(secondId.Value));
        Assert.NotEqual(firstId, secondId);
        Assert.Same(firstId, first.GetRequiredService<InstanceId>());
    }

    [Fact]
    public void DirectStartupComposition_PreservesItsDistinctDiagnosticPrefixOnEachInvocation()
    {
        var first = StartupMigrationGate.CreateStartupInstanceId();
        var second = StartupMigrationGate.CreateStartupInstanceId();
        Assert.Matches("^signacore-startup-[0-9a-f]{32}$", first.Value);
        Assert.Matches("^signacore-startup-[0-9a-f]{32}$", second.Value);
        Assert.Equal(first, InstanceId.Parse(first.Value));
        Assert.Equal(second, InstanceId.Parse(second.Value));
        Assert.NotEqual(first, second);
    }
}
