using System.Security.Cryptography;
using ServiceMantle.Configuration;
using SignaCore.Domain.Keys;
using SignaCore.Host.Configuration;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

public sealed class SharedSettingRootKeyAndConstraintTests
{
    [Fact]
    public async Task RootKeySource_EncodesTheMasterKeyStablyAsBase64()
    {
        var masterKey = RandomNumberGenerator.GetBytes(32);
        var provider = new FixedMasterKeyProvider(masterKey);
        var source = new MasterKeyRootKeySource(provider);

        var first = await source.GetRootKeyAsync(TestContext.Current.CancellationToken);
        var second = await source.GetRootKeyAsync(TestContext.Current.CancellationToken);

        Assert.Equal(Convert.ToBase64String(masterKey), first);
        Assert.Equal(first, second);
    }

    [Fact]
    public async Task RootKeySource_PropagatesCallerCancellation()
    {
        var source = new MasterKeyRootKeySource(new FixedMasterKeyProvider(RandomNumberGenerator.GetBytes(32)));
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => source.GetRootKeyAsync(cancellation.Token).AsTask());
        Assert.Equal(cancellation.Token, exception.CancellationToken);
    }

    [Theory]
    [InlineData("2", true)]
    [InlineData("0", true)]
    [InlineData("-5", true)]
    [InlineData("2.5", false)]
    [InlineData("2.0", true)]
    [InlineData("0.1", false)]
    public void IntegerConstraint_MatchesTheLegacyIntegerParse(string candidate, bool expected)
    {
        // The shared stack parses Number as decimal; the constraint must keep the legacy integer
        // semantics on the real value path (registry parse + constraint).
        var registry = new ServiceSettingDefinitionRegistry([new NumberOnlyDefinitions()]);
        var result = registry.Validate(new Dictionary<string, string?> { ["sample.number"] = candidate });

        Assert.Equal(expected, result.IsValid);
        if (!expected)
        {
            Assert.Contains(result.Errors, error =>
                error.ErrorCode == ServiceSettingDefinitions.IntegerErrorCode);
        }
    }

    private sealed class NumberOnlyDefinitions : IServiceSettingDefinitionProvider
    {
        public IEnumerable<ServiceSettingDefinition> GetDefinitions() =>
        [
            new ServiceSettingDefinition(
                "sample.number",
                ServiceSettingValueType.Number,
                constraints: [new IntegerSettingConstraint()])
        ];
    }

    private sealed class FixedMasterKeyProvider(byte[] masterKey) : IMasterKeyProvider
    {
        public byte[] GetMasterKey() => masterKey;
    }
}
