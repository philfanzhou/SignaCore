using SignaCore.Domain.Services.Sms;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

public class MainlandChinaPhoneNumberTests
{
    [Theory]
    [InlineData("13800138000", "+8613800138000")]
    [InlineData("8613800138000", "+8613800138000")]
    [InlineData("008613800138000", "+8613800138000")]
    [InlineData("+86 138-0013-8000", "+8613800138000")]
    public void TryNormalize_AcceptedMainlandFormats_ReturnsE164(string input, string expected)
    {
        Assert.True(MainlandChinaPhoneNumber.TryNormalize(input, out var actual));
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("")]
    [InlineData("12800138000")]
    [InlineData("+85291234567")]
    [InlineData("1380013800")]
    public void TryNormalize_NonMainlandMobile_ReturnsFalse(string input)
    {
        Assert.False(MainlandChinaPhoneNumber.TryNormalize(input, out _));
    }
}
