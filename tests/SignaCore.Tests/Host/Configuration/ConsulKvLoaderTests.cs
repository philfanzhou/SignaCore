using SignaCore.Host.Configuration;
using Xunit;

namespace SignaCore.Tests.Host.Configuration;

public class ConsulKvLoaderTests
{
    [Fact]
    public void FlattenJson_ExpandsNestedObjectsAndArrays()
    {
        const string json = """
        {
          "__comment": "Top-level comment should be ignored.",
          "Serilog": {
            "__comment": "Serilog settings shared by services.",
            "MinimumLevel": {
              "Default": "Information"
            },
            "WriteTo": [
              {
                "Name": "Console"
              }
            ]
          },
          "Loki": {
            "Uri": "http://example-loki:3100"
          }
        }
        """;

        var flattened = ConsulKvLoader.FlattenJson(json);

        Assert.Equal("Information", flattened["Serilog:MinimumLevel:Default"]);
        Assert.Equal("Console", flattened["Serilog:WriteTo:0:Name"]);
        Assert.Equal("http://example-loki:3100", flattened["Loki:Uri"]);
        Assert.DoesNotContain("__comment", flattened.Keys);
        Assert.DoesNotContain("Serilog:__comment", flattened.Keys);
    }

    [Fact]
    public void BuildPrefixes_ReturnsSingleSharedPrefix()
    {
        var options = new ConsulOptions
        {
            KvPrefix = "config/signacore"
        };

        var prefixes = ConsulKvLoader.BuildPrefixes(options);

        Assert.Equal(
            [
                "config/signacore"
            ],
            prefixes);
    }
}
