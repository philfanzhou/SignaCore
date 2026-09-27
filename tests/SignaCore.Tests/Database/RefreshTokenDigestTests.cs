using SignaCore.Database;
using Xunit;

namespace SignaCore.Tests.Database;

public class RefreshTokenDigestTests
{
    [Fact]
    public void Compute_ReturnsDeterministicVersionedLowercaseDigest()
    {
        var first = RefreshTokenDigest.Compute("a-high-entropy-refresh-token");
        var second = RefreshTokenDigest.Compute("a-high-entropy-refresh-token");

        Assert.Equal(first, second);
        Assert.StartsWith(RefreshTokenDigest.Prefix, first);
        Assert.Equal(RefreshTokenDigest.EncodedLength, first.Length);
        Assert.True(RefreshTokenDigest.IsDigest(first));
        Assert.DoesNotContain("a-high-entropy-refresh-token", first);
    }

    [Fact]
    public void PublicDigest_HasDedicatedNamespaceAndIsIdempotent()
    {
        var digest = RefreshTokenDigest.ComputePublic("raw-token");
        Assert.StartsWith(RefreshTokenDigest.PublicPrefix, digest);
        Assert.Equal(RefreshTokenDigest.PublicEncodedLength, digest.Length);
        Assert.True(RefreshTokenDigest.IsPublicDigest(digest));
        Assert.True(RefreshTokenDigest.IsDigest(digest));
        Assert.Same(digest, RefreshTokenDigest.EnsureDigest(digest));
        Assert.NotEqual(RefreshTokenDigest.Compute("raw-token"), digest);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Compute_RejectsMissingTokens(string? value)
    {
        Assert.ThrowsAny<ArgumentException>(() => RefreshTokenDigest.Compute(value!));
    }

    [Theory]
    [InlineData("sha256:short")]
    [InlineData("sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")]
    [InlineData("sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("md5:0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("sha256-public:short")]
    [InlineData("sha256-public:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("sha256-public:000000000000000000000000000000000000000000000000000000000000000g")]
    public void IsDigest_RejectsMalformedRepresentations(string value)
    {
        Assert.False(RefreshTokenDigest.IsDigest(value));
    }

    [Fact]
    public void EnsureDigest_IsIdempotentAndProtectsMalformedPrefixedValues()
    {
        var digest = RefreshTokenDigest.Compute("raw-token");

        Assert.Same(digest, RefreshTokenDigest.EnsureDigest(digest));
        Assert.Equal(
            RefreshTokenDigest.Compute("sha256:not-a-digest"),
            RefreshTokenDigest.EnsureDigest("sha256:not-a-digest"));
    }
}
