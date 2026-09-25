using SignaCore.Database;
using Xunit;

namespace SignaCore.Tests.Database;

/// <summary>
/// The credential shape and digest are a persistence contract (#360). The vector below was
/// computed by an independent base64url/SHA-256 implementation. Assertions on credential values
/// use <see cref="Assert.True(bool, string)"/> so a failure never prints the value.
/// </summary>
public class ManagementBearerTokenTests
{
    private const string Canonical = "scm1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    private const string CanonicalDigest = "sha256:6be711785233c003e2ebd40261d52414a78fa2f969ff3a78e69216c110256566";

    [Fact]
    public void Generate_ProducesDistinctCanonicalCredentials()
    {
        var tokens = Enumerable.Range(0, 256).Select(_ => ManagementBearerToken.Generate()).ToArray();

        Assert.All(tokens, token =>
        {
            Assert.Equal(48, token.Length);
            Assert.True(token.StartsWith("scm1.", StringComparison.Ordinal), "The credential prefix differs.");
            Assert.True(ManagementBearerToken.IsWellFormed(token), "A generated credential is not canonical.");
        });
        Assert.Equal(tokens.Length, tokens.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(tokens.Length, tokens.Select(ManagementBearerToken.ComputeDigest).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void ComputeDigest_MatchesTheIndependentVector()
    {
        Assert.True(ManagementBearerToken.IsWellFormed(Canonical));
        var digest = ManagementBearerToken.ComputeDigest(Canonical);

        Assert.True(string.Equals(CanonicalDigest, digest, StringComparison.Ordinal), "The digest differs from the vector.");
        Assert.Equal(ManagementBearerToken.DigestLength, digest.Length);
        Assert.True(LoginHandleDigest.IsDigest(digest), "The digest is not versioned lowercase hex.");
        Assert.False(digest.Contains(Canonical[5..], StringComparison.Ordinal), "The digest contains the credential.");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("scm1.")]
    [InlineData("scm1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh")]
    [InlineData("scm1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8A")]
    [InlineData("SCM1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")]
    [InlineData("scm2.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")]
    [InlineData("scm1-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")]
    [InlineData("scm1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9")]
    [InlineData("scm1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh=")]
    [InlineData("scm1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdH+8")]
    [InlineData("scm1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdH/8")]
    [InlineData("scm1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdH 8")]
    [InlineData(" scm1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh")]
    [InlineData("scm1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHｈ8")]
    [InlineData(CanonicalDigest)]
    public void IsWellFormed_RejectsEveryNonCanonicalShapeWithoutEchoingIt(string? value)
    {
        Assert.False(ManagementBearerToken.IsWellFormed(value));

        var exception = Assert.ThrowsAny<ArgumentException>(() => ManagementBearerToken.ComputeDigest(value!));
        if (!string.IsNullOrEmpty(value))
        {
            Assert.False(exception.Message.Contains(value, StringComparison.Ordinal), "The message echoes the input.");
        }
    }
}
