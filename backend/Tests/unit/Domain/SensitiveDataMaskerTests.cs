using QuantumZhou.Identity.Domain;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain;

public class SensitiveDataMaskerTests
{
    [Theory]
    [InlineData("13812341234", "138****1234")]
    [InlineData("13800000000", "138****0000")]
    [InlineData("8613812341234", "861****1234")]
    public void MaskPhone_NormalLength_PreservesHead3AndTail4(string phone, string expected)
    {
        Assert.Equal(expected, SensitiveDataMasker.MaskPhone(phone));
    }

    [Theory]
    [InlineData("123456", "****")]
    [InlineData("12345", "****")]
    [InlineData("1234567", "123****4567")]   // length=7: exactly 3+4, no middle chars dropped
    [InlineData("12345678", "123****5678")]
    public void MaskPhone_BoundaryLengths_HandlesCorrectly(string phone, string expected)
    {
        Assert.Equal(expected, SensitiveDataMasker.MaskPhone(phone));
    }

    [Theory]
    [InlineData("", "")]
    [InlineData(null, "")]
    public void MaskPhone_EmptyOrNull_ReturnsEmpty(string? phone, string expected)
    {
        Assert.Equal(expected, SensitiveDataMasker.MaskPhone(phone));
    }

    [Theory]
    [InlineData("o1QxYzAbcdefghijklwxyz", "o1Qx****wxyz")]
    [InlineData("o1QxYzAb", "o1Qx****YzAb")]
    public void MaskOpenId_NormalLength_PreservesHead4AndTail4(string openId, string expected)
    {
        Assert.Equal(expected, SensitiveDataMasker.MaskOpenId(openId));
    }

    [Theory]
    [InlineData("1234567", "****")]
    [InlineData("12345678", "1234****5678")]
    [InlineData("123456789", "1234****6789")] // length=9: 4+4 + 1 middle char dropped
    public void MaskOpenId_BoundaryLengths_HandlesCorrectly(string openId, string expected)
    {
        Assert.Equal(expected, SensitiveDataMasker.MaskOpenId(openId));
    }

    [Theory]
    [InlineData("", "")]
    [InlineData(null, "")]
    public void MaskOpenId_EmptyOrNull_ReturnsEmpty(string? openId, string expected)
    {
        Assert.Equal(expected, SensitiveDataMasker.MaskOpenId(openId));
    }
}
