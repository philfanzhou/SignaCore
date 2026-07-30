using Microsoft.Extensions.Configuration;
using QuantumZhou.Identity.Host.Configuration;
using Xunit;

namespace QuantumZhou.Identity.Tests.Host.Configuration;

public class ProgramConsulExtensionsTests
{
    [Fact]
    public void RemoveLegacyDatabaseKeys_PreservesNonDatabaseSharedValues()
    {
        var snapshot = ProgramConsulExtensions.RemoveLegacyDatabaseKeys(
            new Dictionary<string, string?>
            {
                ["PostgreSql:Host"] = "ruoyu-postgres",
                ["Database:Name"] = "legacy",
                ["Loki:Uri"] = "http://ruoyu-loki:3100"
            });

        Assert.False(snapshot.ContainsKey("PostgreSql:Host"));
        Assert.False(snapshot.ContainsKey("Database:Name"));
        Assert.Equal("http://ruoyu-loki:3100", snapshot["Loki:Uri"]);
    }

    [Fact]
    public void ApplySnapshotWithExpectedPrecedence_OverridesAppSettings()
    {
        var builder = new ConfigurationManager();
        builder.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["PostgreSql:Host"] = "localhost",
            ["Loki:Uri"] = "http://localhost:3100"
        });

        ProgramConsulExtensions.ApplySnapshotWithExpectedPrecedence(
            builder,
            new Dictionary<string, string?>
            {
                ["PostgreSql:Host"] = "ruoyu-postgres",
                ["Loki:Uri"] = "http://ruoyu-loki:3100"
            });

        Assert.Equal("ruoyu-postgres", builder["PostgreSql:Host"]);
        Assert.Equal("http://ruoyu-loki:3100", builder["Loki:Uri"]);
    }

    [Fact]
    public void ApplySnapshotWithExpectedPrecedence_PreservesEnvironmentVariablesHigherPriority()
    {
        const string envName = "PostgreSql__Host";
        var previous = Environment.GetEnvironmentVariable(envName);

        try
        {
            Environment.SetEnvironmentVariable(envName, "env-postgres");

            var builder = new ConfigurationManager();
            builder.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PostgreSql:Host"] = "localhost"
            });
            builder.AddEnvironmentVariables();

            ProgramConsulExtensions.ApplySnapshotWithExpectedPrecedence(
                builder,
                new Dictionary<string, string?>
                {
                    ["PostgreSql:Host"] = "ruoyu-postgres"
                });

            Assert.Equal("env-postgres", builder["PostgreSql:Host"]);
        }
        finally
        {
            Environment.SetEnvironmentVariable(envName, previous);
        }
    }
}
