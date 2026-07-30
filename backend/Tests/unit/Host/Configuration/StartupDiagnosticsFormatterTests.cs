using QuantumZhou.Identity.Host.Configuration;
using Xunit;

namespace QuantumZhou.Identity.Tests.Host.Configuration;

public class StartupDiagnosticsFormatterTests
{
    [Theory]
    [InlineData(null, "<empty>")]
    [InlineData("", "<empty>")]
    [InlineData("abcd", "****")]
    [InlineData("abcdef", "a***f")]
    [InlineData("1234567890", "1234***7890")]
    public void MaskSecret_ReturnsExpectedSummary(string? value, string expected)
    {
        Assert.Equal(expected, StartupDiagnosticsFormatter.MaskSecret(value));
    }

    [Theory]
    [InlineData(null, "<empty>")]
    [InlineData("", "<empty>")]
    [InlineData("postgres", "postgres")]
    public void SummarizeValue_ReturnsExpectedSummary(string? value, string expected)
    {
        Assert.Equal(expected, StartupDiagnosticsFormatter.SummarizeValue(value));
    }

    [Theory]
    [InlineData(null, "<empty>")]
    [InlineData("", "<empty>")]
    [InlineData("postgres", "<masked:length=8>")]
    public void SummarizePassword_DoesNotExposeRawValue(string? value, string expected)
    {
        Assert.Equal(expected, StartupDiagnosticsFormatter.SummarizePassword(value));
    }
}
