using Microsoft.Extensions.Configuration;
using SignaCore.Host.Configuration;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

/// <summary>
/// The retired flat-named SMS environment variables stopped reaching <c>SmsOptions</c>; the guard
/// must still tell the operator that a deployment keeps setting them, because the flat names match
/// no managed legacy key and would otherwise disappear silently.
/// </summary>
public class LegacyConfigurationGuardTests
{
    [Fact]
    public void FindRetiredSmsEnvironmentVariables_WhenAllAreSet_ReturnsEachName()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SMS_BYPASS_CODE"] = "1234",
                ["SMS_OTP_HMAC_KEY"] = "retired-key",
                ["SMS_BYPASS_PHONES"] = "13800000000"
            })
            .Build();

        var names = LegacyConfigurationGuard.FindRetiredSmsEnvironmentVariables(configuration);

        // Declaration order, one entry per set variable, and names only — never values.
        Assert.Equal(["SMS_BYPASS_CODE", "SMS_OTP_HMAC_KEY", "SMS_BYPASS_PHONES"], names);
    }

    [Fact]
    public void FindRetiredSmsEnvironmentVariables_WhenOnlySomeAreSet_ReturnsOnlyThose()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SMS_BYPASS_CODE"] = "1234",
                ["SMS_BYPASS_PHONES"] = "13800000000"
            })
            .Build();

        var names = LegacyConfigurationGuard.FindRetiredSmsEnvironmentVariables(configuration);

        Assert.Equal(["SMS_BYPASS_CODE", "SMS_BYPASS_PHONES"], names);
    }

    [Fact]
    public void FindRetiredSmsEnvironmentVariables_WhenNoneAreSet_ReturnsEmpty()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection().Build();

        var names = LegacyConfigurationGuard.FindRetiredSmsEnvironmentVariables(configuration);

        Assert.Empty(names);
    }

    /// <summary>
    /// The production path: the host's environment-variables provider surfaces a set variable as a
    /// flat configuration key, so the guard must see it through the same providers the host uses.
    /// </summary>
    [Fact]
    public void FindRetiredSmsEnvironmentVariables_WhenSetAsProcessEnvironmentVariable_IsReported()
    {
        using var _ = TemporaryEnvironmentVariable.Set("SMS_BYPASS_CODE", "1234");

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection()
            .AddEnvironmentVariables()
            .Build();

        var names = LegacyConfigurationGuard.FindRetiredSmsEnvironmentVariables(configuration);

        Assert.Equal(["SMS_BYPASS_CODE"], names);
    }

    /// <summary>
    /// Once <c>app.title</c> is a managed setting, a deployment still setting the flat
    /// <c>APP_TITLE</c> is inert on the normal host (the database snapshot wins) and must be
    /// reported so the operator stops expecting an effect (#595).
    /// </summary>
    [Fact]
    public void FindManagedOverrides_WhenAppTitleIsStillSet_ReportsTheLegacyKey()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["APP_TITLE"] = "Launcher Console"
            })
            .Build();

        var overrides = LegacyConfigurationGuard.FindManagedOverrides(configuration);

        Assert.Contains("APP_TITLE", overrides);
    }

    private sealed class TemporaryEnvironmentVariable : IDisposable
    {
        private readonly string _name;
        private readonly string? _original;

        private TemporaryEnvironmentVariable(string name, string? original)
        {
            _name = name;
            _original = original;
        }

        public static TemporaryEnvironmentVariable Set(string name, string value)
        {
            var original = Environment.GetEnvironmentVariable(name);
            Environment.SetEnvironmentVariable(name, value);
            return new TemporaryEnvironmentVariable(name, original);
        }

        public void Dispose() => Environment.SetEnvironmentVariable(_name, _original);
    }
}
