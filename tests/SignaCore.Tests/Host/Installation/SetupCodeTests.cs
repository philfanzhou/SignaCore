using SignaCore.Host.Installation;
using Xunit;

namespace SignaCore.Tests.Host.Installation;

public class SetupCodeTests
{
    [Fact]
    public void Generate_ProducesDistinctCodes()
    {
        var codes = Enumerable.Range(0, 200).Select(_ => SetupCode.Generate()).ToHashSet(StringComparer.Ordinal);

        Assert.Equal(200, codes.Count);
    }

    /// <summary>
    /// Thirty independent selections from a 32-character alphabet provide 150 bits of entropy.
    /// This asserts the shape and alphabet rather than trying to measure entropy statistically.
    /// </summary>
    [Fact]
    public void Generate_UsesAnUnambiguousAlphabetAndGrouping()
    {
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

        var code = SetupCode.Generate();

        var groups = code.Split('-');
        Assert.Equal(6, groups.Length);
        Assert.All(groups, group => Assert.Equal(5, group.Length));
        Assert.All(code.Replace("-", string.Empty), character => Assert.Contains(character, alphabet));
    }

    [Fact]
    public void Verify_AcceptsTheGeneratedCode()
    {
        var code = SetupCode.Generate();

        Assert.True(SetupCode.Verify(code, SetupCode.Hash(code)));
    }

    /// <summary>
    /// Case, whitespace, and the display hyphens are presentation, not secret, so an operator
    /// retyping the code out of a terminal is not punished for formatting.
    /// </summary>
    [Theory]
    [InlineData("ABCDE-FGHJK-LMNPQ-RSTUV")]
    [InlineData("abcde-fghjk-lmnpq-rstuv")]
    [InlineData("ABCDEFGHJKLMNPQRSTUV")]
    [InlineData("  ABCDE FGHJK LMNPQ RSTUV  ")]
    public void Verify_IgnoresFormattingDifferences(string candidate)
    {
        var hash = SetupCode.Hash("ABCDE-FGHJK-LMNPQ-RSTUV");

        Assert.True(SetupCode.Verify(candidate, hash));
    }

    [Fact]
    public void Verify_RejectsADifferentCode()
    {
        Assert.False(SetupCode.Verify(SetupCode.Generate(), SetupCode.Hash(SetupCode.Generate())));
    }

    /// <summary>
    /// A cleared hash is what a completed installation stores. It must never verify, otherwise
    /// completing setup would leave the door open.
    /// </summary>
    [Theory]
    [InlineData(null, "irrelevant")]
    [InlineData("ABCDE-FGHJK-LMNPQ-RSTUV", null)]
    [InlineData("", "")]
    [InlineData("ABCDE-FGHJK-LMNPQ-RSTUV", "not-base64!")]
    public void Verify_RejectsMissingOrMalformedInput(string? candidate, string? hash)
    {
        Assert.False(SetupCode.Verify(candidate, hash));
    }

    [Fact]
    public void Hash_DoesNotContainThePlaintext()
    {
        var code = SetupCode.Generate();

        Assert.DoesNotContain(
            code.Replace("-", string.Empty),
            SetupCode.Hash(code),
            StringComparison.OrdinalIgnoreCase);
    }
}
