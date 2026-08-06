using Microsoft.Extensions.Configuration;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

public class ServiceCollectionExtensionsSmsTests
{
    private static IConfiguration BuildConfiguration(params (string Key, string Value)[] entries)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(entries.ToDictionary(
                static entry => entry.Key,
                static entry => (string?)entry.Value))
            .Build();
    }

    [Fact]
    public void ResolveBypassPhones_WithoutConfiguration_ReturnsEmpty()
    {
        var phones = ServiceCollectionExtensions.ResolveBypassPhones(BuildConfiguration());

        Assert.Empty(phones);
    }

    [Fact]
    public void ResolveBypassPhones_WithCommaSeparatedString_SplitsAndTrims()
    {
        var configuration = BuildConfiguration(
            ("Sms:BypassPhones", " 13800138000 , 13900139000 ,, "));

        var phones = ServiceCollectionExtensions.ResolveBypassPhones(configuration);

        Assert.Equal(new[] { "13800138000", "13900139000" }, phones);
    }

    [Fact]
    public void ResolveBypassPhones_WithJsonArraySection_ReadsChildren()
    {
        var configuration = BuildConfiguration(
            ("Sms:BypassPhones:0", "13800138000"),
            ("Sms:BypassPhones:1", "13900139000"));

        var phones = ServiceCollectionExtensions.ResolveBypassPhones(configuration);

        Assert.Equal(new[] { "13800138000", "13900139000" }, phones);
    }

    [Fact]
    public void ResolveBypassPhones_WithDuplicates_Deduplicates()
    {
        var configuration = BuildConfiguration(
            ("Sms:BypassPhones", "13800138000,13800138000"));

        var phones = ServiceCollectionExtensions.ResolveBypassPhones(configuration);

        Assert.Single(phones);
    }
}
