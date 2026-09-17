using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SignaCore.Domain.Services;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests;

/// <summary>
/// The shape of the per-process decoy hash: a real BCrypt hash at the configured work factor,
/// generated once per instance even under concurrent first readers, never persisted or exposed,
/// and registered as a singleton alongside the password hasher.
/// </summary>
public sealed class PasswordDecoyHashTests
{
    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    public async Task Value_IsAVerifiableBCryptHashAtTheConfiguredWorkFactor(int workFactor)
    {
        var decoy = new PasswordDecoyHash(new PasswordHasherOptions { WorkFactor = workFactor });

        var value = decoy.Value;

        // The modular crypt format carries the cost: $2a$NN$…
        Assert.StartsWith("$2", value, StringComparison.Ordinal);
        var secondDollar = value.IndexOf('$', 2);
        Assert.True(secondDollar > 0, "The hash must carry its version and cost prefix.");
        var thirdDollar = value.IndexOf('$', secondDollar + 1);
        Assert.True(thirdDollar > secondDollar, "The hash must close its cost field.");
        Assert.Equal(
            workFactor,
            int.Parse(value.AsSpan(secondDollar + 1, thirdDollar - secondDollar - 1)));

        // Any password verifies against it as a well-formed BCrypt hash (this seed never matches).
        var hasher = new BCryptPasswordHasher(new PasswordHasherOptions());
        Assert.False(hasher.VerifyPassword("not-the-seed", value));
        await Task.CompletedTask;
    }

    [Fact]
    public async Task OneInstance_ReturnsOneValue_EvenForConcurrentFirstReaders()
    {
        var decoy = new PasswordDecoyHash(new PasswordHasherOptions { WorkFactor = 4 });

        var tasks = Enumerable.Range(0, 16)
            .Select(_ => Task.Run(() => decoy.Value));
        var values = await Task.WhenAll(tasks);

        Assert.All(values, value => Assert.Equal(values[0], value));
    }

    [Fact]
    public void TwoInstances_ProduceDifferentValues()
    {
        var options = new PasswordHasherOptions { WorkFactor = 4 };

        Assert.NotEqual(
            new PasswordDecoyHash(options).Value,
            new PasswordDecoyHash(options).Value);
    }

    [Fact]
    public void TheType_DoesNotOverrideToString()
    {
        var method = typeof(PasswordDecoyHash).GetMethod(
            "ToString", Type.EmptyTypes)!;

        Assert.Same(typeof(object), method.DeclaringType);
    }

    [Fact]
    public void RegisterPasswordHashingDefaults_RegistersTheDecoyAsASingleton()
    {
        var services = new ServiceCollection();
        services.RegisterPasswordHashingDefaults();

        var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        Assert.Same(scope.ServiceProvider.GetRequiredService<PasswordDecoyHash>(), provider.GetRequiredService<PasswordDecoyHash>());
    }
}
