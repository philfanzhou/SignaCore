using QuantumZhou.Identity.Host.Configuration;
using Xunit;

namespace QuantumZhou.Identity.Tests.Host.Configuration;

public class ConsulKvLoaderTests
{
    [Fact]
    public void FlattenJson_ExpandsNestedObjectsAndArrays()
    {
        const string json = """
        {
          "Serilog": {
            "MinimumLevel": {
              "Default": "Information"
            },
            "WriteTo": [
              {
                "Name": "Console"
              }
            ]
          },
          "FeatureFlags": {
            "EnableNewLogin": true
          }
        }
        """;

        var flattened = ConsulKvLoader.FlattenJson(json);

        Assert.Equal("Information", flattened["Serilog:MinimumLevel:Default"]);
        Assert.Equal("Console", flattened["Serilog:WriteTo:0:Name"]);
        Assert.Equal("true", flattened["FeatureFlags:EnableNewLogin"]);
    }

    [Fact]
    public void BuildPrefixes_ReturnsSingleSharedPrefix()
    {
        var options = new ConsulOptions
        {
            KvPrefix = "config/ruoyu"
        };

        var prefixes = ConsulKvLoader.BuildPrefixes(options);

        Assert.Equal(
            [
                "config/ruoyu"
            ],
            prefixes);
    }
}
