using Microsoft.Extensions.Configuration;
using SignaCore.Host.Configuration;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

public class ProgramConsulExtensionsTests
{
    [Fact]
    public void RemoveLegacyDatabaseKeys_PreservesNonDatabaseSharedValues()
    {
        var snapshot = ProgramConsulExtensions.RemoveLegacyDatabaseKeys(
            new Dictionary<string, string?>
            {
                ["PostgreSql:Host"] = "example-postgres",
                ["Database:Name"] = "legacy",
                ["Loki:Uri"] = "http://example-loki:3100"
            });

        Assert.False(snapshot.ContainsKey("PostgreSql:Host"));
        Assert.False(snapshot.ContainsKey("Database:Name"));
        Assert.Equal("http://example-loki:3100", snapshot["Loki:Uri"]);
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
                ["PostgreSql:Host"] = "example-postgres",
                ["Loki:Uri"] = "http://example-loki:3100"
            });

        Assert.Equal("example-postgres", builder["PostgreSql:Host"]);
        Assert.Equal("http://example-loki:3100", builder["Loki:Uri"]);
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
                    ["PostgreSql:Host"] = "example-postgres"
                });

            Assert.Equal("env-postgres", builder["PostgreSql:Host"]);
        }
        finally
        {
            Environment.SetEnvironmentVariable(envName, previous);
        }
    }
}
