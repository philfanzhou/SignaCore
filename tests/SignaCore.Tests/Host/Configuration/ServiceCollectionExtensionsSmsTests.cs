using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using SignaCore.Database;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services.Sms;
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

    /// <summary>
    /// The retired SMS_BYPASS_PHONES environment variable no longer feeds the allow-list; a
    /// deployment that still sets it gets a LegacyConfigurationGuard warning instead.
    /// </summary>
    [Fact]
    public void ResolveBypassPhones_WithRetiredEnvironmentVariableSet_ReturnsEmpty()
    {
        using var _ = SetEnvironmentVariable("SMS_BYPASS_PHONES", "13800138000");
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection()
            .AddEnvironmentVariables()
            .Build();

        var phones = ServiceCollectionExtensions.ResolveBypassPhones(configuration);

        Assert.Empty(phones);
    }

    /// <summary>
    /// Locks the unchanged behavior when the retired environment variables are absent: the
    /// configuration (the database snapshot in a running deployment) remains the only source and
    /// binds exactly as before.
    /// </summary>
    [Fact]
    public void AddIdentityInfrastructure_WithoutRetiredEnvironmentVariables_BindsConfiguredSmsSettings()
    {
        using var _ = ClearRetiredSmsEnvironmentVariables();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "https://identity.example.test",
                ["Sms:BypassCode"] = "1234",
                ["Sms:BypassPhones"] = "13800138000,13900139000"
            })
            .AddEnvironmentVariables()
            .Build();

        var smsOptions = ComposeSmsOptions(configuration);

        Assert.Equal("1234", smsOptions.BypassCode);
        Assert.Equal(new[] { "13800138000", "13900139000" }, smsOptions.BypassPhones);
    }

    /// <summary>
    /// The retired flat-named environment variables no longer reach <see cref="SmsOptions"/> even
    /// when the process still sets them; the Development random HMAC key keeps covering the empty
    /// key so the composition stays usable.
    /// </summary>
    [Fact]
    public void AddIdentityInfrastructure_WithRetiredEnvironmentVariablesSet_DoesNotReadThemIntoSmsOptions()
    {
        const string retiredHmacKey = "retired-not-a-base64-key";
        using var _ = ClearRetiredSmsEnvironmentVariables();
        using var __ = SetEnvironmentVariable("SMS_BYPASS_CODE", "1234");
        using var ___ = SetEnvironmentVariable("SMS_OTP_HMAC_KEY", retiredHmacKey);
        using var ____ = SetEnvironmentVariable("SMS_BYPASS_PHONES", "13800138000");
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "https://identity.example.test"
            })
            .AddEnvironmentVariables()
            .Build();

        var smsOptions = ComposeSmsOptions(configuration);

        Assert.Null(smsOptions.BypassCode);
        Assert.Empty(smsOptions.BypassPhones);
        // The Development random key replaced the retired value (which is not valid base64 and
        // would otherwise fail validation outright).
        Assert.NotEqual(retiredHmacKey, smsOptions.OtpHmacKey);
        Assert.True(smsOptions.DecodeHmacKey().Length >= 32);
    }

    private static SmsOptions ComposeSmsOptions(IConfiguration configuration)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddIdentityInfrastructure(
            configuration,
            new StubHostEnvironment { EnvironmentName = Environments.Development },
            new DatabaseOptions
            {
                Provider = "PostgreSQL",
                ServerVersion = "15",
                ConnectionString = "Host=localhost;Database=identity;Username=postgres;Password=test"
            },
            new BootstrapMasterKeyProvider("sms-composition-tests-root-secret"));

        return services.BuildServiceProvider().GetRequiredService<SmsOptions>();
    }

    private static IDisposable SetEnvironmentVariable(string name, string? value)
    {
        var original = Environment.GetEnvironmentVariable(name);
        Environment.SetEnvironmentVariable(name, value);
        return new RestoredEnvironmentVariable(name, original);
    }

    private static IDisposable ClearRetiredSmsEnvironmentVariables() => new CompositeDisposable(
        SetEnvironmentVariable("SMS_BYPASS_CODE", null),
        SetEnvironmentVariable("SMS_OTP_HMAC_KEY", null),
        SetEnvironmentVariable("SMS_BYPASS_PHONES", null));

    private sealed class RestoredEnvironmentVariable(string name, string? original) : IDisposable
    {
        public void Dispose() => Environment.SetEnvironmentVariable(name, original);
    }

    private sealed class CompositeDisposable(params IDisposable[] disposables) : IDisposable
    {
        public void Dispose()
        {
            foreach (var disposable in disposables)
            {
                disposable.Dispose();
            }
        }
    }

    private sealed class StubHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "SignaCore.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
