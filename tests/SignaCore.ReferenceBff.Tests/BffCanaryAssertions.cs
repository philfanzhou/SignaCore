using System.Net;
using System.Text.Json;
using Xunit;
using Xunit.Sdk;

namespace SignaCore.ReferenceBff.Tests;

internal static class BffCanaryAssertions
{
    internal static void Absent(string output, IEnumerable<string> canaries, string carrier)
    {
        foreach (var canary in canaries)
        {
            Assert.False(string.IsNullOrEmpty(canary), "A canary must be populated before scanning.");
            foreach (var representation in Representations(canary))
                Assert.False(output.Contains(representation, StringComparison.Ordinal),
                    $"Sensitive canary appeared in {carrier}.");
        }
    }

    internal static IEnumerable<string> Representations(string value) => new[]
    {
        value, Uri.EscapeDataString(value), WebUtility.HtmlEncode(value), JsonSerializer.Serialize(value)[1..^1]
    }.Distinct(StringComparer.Ordinal);

    internal static async Task ResponseAsync(HttpResponseMessage response, IEnumerable<string> canaries)
    {
        var values = canaries.ToArray();
        Absent(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), values, "response body");
        Absent(response.Headers.ToString(), values, "response headers (including Location and Set-Cookie)");
        Absent(response.Content.Headers.ToString(), values, "content headers");
    }
}

public sealed class BffCanaryAssertionTests
{
    [Theory]
    [InlineData("password")]
    [InlineData("setup-code")]
    [InlineData("cookie")]
    [InlineData("token-or-verifier")]
    [InlineData("client-secret")]
    [InlineData("root-key")]
    [InlineData("connection")]
    [InlineData("authorization")]
    public void EverySensitiveValue_InjectedIntoEachCarrierFailsWithoutPrintingIt(string kind)
    {
        var canary = $"synthetic-{kind}-{Guid.NewGuid():N}/+<>&=";
        foreach (var carrier in new[] { "console", "body", "headers", "URL", "audit column", "stdout", "stderr" })
        foreach (var representation in BffCanaryAssertions.Representations(canary))
        {
            var error = Assert.Throws<FalseException>(() => BffCanaryAssertions.Absent(
                "before " + representation + " after", [canary], carrier));
            Assert.False(error.Message.Contains(canary, StringComparison.Ordinal));
            Assert.Contains(carrier, error.Message, StringComparison.Ordinal);
        }
    }
}
