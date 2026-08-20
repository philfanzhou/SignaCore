using SignaCore.Domain;
using Xunit;

namespace SignaCore.Tests.Domain;

public class LogValueSanitizerTests
{
    [Theory]
    [InlineData("value", "value")]
    [InlineData("first\r\nsecond", "first\\nsecond")]
    [InlineData("first\rsecond", "first\\nsecond")]
    [InlineData("first\nsecond", "first\\nsecond")]
    [InlineData("first\u0085second", "first\\nsecond")]
    [InlineData("first\u2028second", "first\\nsecond")]
    [InlineData("first\u2029second", "first\\nsecond")]
    public void Sanitize_EncodesLineEndings(string value, string expected)
    {
        Assert.Equal(expected, LogValueSanitizer.Sanitize(value));
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void Sanitize_EmptyOrNull_ReturnsEmpty(string? value)
    {
        Assert.Equal(string.Empty, LogValueSanitizer.Sanitize(value));
    }
}
