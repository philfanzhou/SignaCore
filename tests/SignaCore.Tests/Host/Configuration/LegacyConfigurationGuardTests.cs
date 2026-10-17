using Microsoft.Extensions.Configuration;
using SignaCore.Host.Configuration;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

/// <summary>
/// The startup legacy-override diagnostic. The retired flat-named SMS environment variables
/// stopped reaching <c>SmsOptions</c>; the guard must still tell the operator that a deployment
/// keeps setting them, because the flat names match no managed legacy key and would otherwise
/// disappear silently. The shipped appsettings files must stay inert: a dead managed key (the
/// former Production <c>OpenTelemetry:OtlpEndpoint: ""</c>) produced one spurious warning on every
/// start because the guard counts any present value, including the empty string, as an override.
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

    [Fact]
    public void ShippedAppSettings_DeclareNoManagedOverrides()
    {
        var hostDirectory = Path.Combine(RepositoryRoot(), "src", "SignaCore.Host");
        var configuration = new ConfigurationBuilder()
            .AddJsonFile(Path.Combine(hostDirectory, "appsettings.json"))
            .AddJsonFile(Path.Combine(hostDirectory, "appsettings.Production.json"))
            .Build();

        // The two shipped files cover only logging and the bootstrap pre-seed path; none of the
        // managed keys may appear in them, so startup reports no legacy override and no legacy
        // database section from a clean deployment.
        Assert.Empty(LegacyConfigurationGuard.FindManagedOverrides(configuration));
        Assert.False(LegacyConfigurationGuard.HasDatabaseSectionOverride(configuration));
    }

    [Fact]
    public void AnEmptyOtlpEndpointValue_IsStillAManagedOverride()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["OpenTelemetry:OtlpEndpoint"] = ""
            })
            .Build();

        // Documents why the dead Production key had to be deleted rather than left empty: the
        // guard treats a present empty-string value as a deployment-provided override, so keeping
        // it would warn on every start while the value never reaches the telemetry decision.
        Assert.Contains(
            "OpenTelemetry:OtlpEndpoint",
            LegacyConfigurationGuard.FindManagedOverrides(configuration));
    }

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "SignaCore.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("The repository root was not found.");
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
