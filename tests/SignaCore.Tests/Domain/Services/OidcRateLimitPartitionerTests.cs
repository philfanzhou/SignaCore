using System.Security.Cryptography;
using System.Text;
using SignaCore.Database;
using SignaCore.Database.RateLimiting;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

/// <summary>
/// The partition digest is a persistence contract shared by every instance that counts one budget:
/// the vectors below were computed by an independent HKDF/HMAC implementation, not by the code
/// under test.
/// </summary>
public class OidcRateLimitPartitionerTests
{
    private sealed class FixedMasterKeyProvider(byte fill) : IMasterKeyProvider
    {
        public int Calls;

        public byte[] GetMasterKey()
        {
            Interlocked.Increment(ref Calls);
            return Enumerable.Repeat(fill, 32).ToArray();
        }
    }

    [Theory]
    [InlineData("client:OrderService", "27c7e9c6665560e841e17ab9beb75979ae235cdf4637d996ed0dac9f96357742")]
    [InlineData("ip:203.0.113.7", "4227b513edae5e4a579ccfa380e1e0626b5df487075f3572f46327b8f805642d")]
    public void Digest_MatchesIndependentVectorAndStoreShape(string partitionKey, string expected)
    {
        var partitioner = new OidcRateLimitPartitioner(new FixedMasterKeyProvider(0x2A));

        var digest = partitioner.Digest(partitionKey);

        Assert.Equal(expected, digest);
        Assert.True(OidcRateLimitBudgets.IsPartitionDigest(digest));
        Assert.Equal(digest, partitioner.Digest(partitionKey));
        Assert.DoesNotContain(partitionKey.Split(':')[1], digest, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Digest_SeparatesPartitionsRootKeysAndDerivationPurposes()
    {
        var provider = new FixedMasterKeyProvider(0x2A);
        var partitioner = new OidcRateLimitPartitioner(provider);
        var digests = new[] { "client:OrderService", "client:orderservice", "ip:203.0.113.7", "ip:203.0.113.8", "ip:OrderService" }
            .Select(partitioner.Digest)
            .ToArray();
        Assert.Equal(digests.Length, digests.Distinct(StringComparer.Ordinal).Count());

        var otherRoot = new OidcRateLimitPartitioner(new FixedMasterKeyProvider(0x2B)).Digest("client:OrderService");
        Assert.NotEqual(digests[0], otherRoot);

        // Domain separation: neither the raw master key nor a key derived for another purpose
        // produces the stored digest.
        var message = Encoding.UTF8.GetBytes("v1\nclient:OrderService");
        var masterKey = provider.GetMasterKey();
        var otherPurposeKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, 32, [],
            Encoding.UTF8.GetBytes(IdentityConstants.ConfigurationProtectionHkdfInfo));
        Assert.NotEqual(digests[0], Convert.ToHexStringLower(HMACSHA256.HashData(masterKey, message)));
        Assert.NotEqual(digests[0], Convert.ToHexStringLower(HMACSHA256.HashData(otherPurposeKey, message)));
        Assert.NotEqual(digests[0], Convert.ToHexStringLower(SHA256.HashData(message)));
    }

    [Fact]
    public void Digest_DerivesTheKeyOnceAndRejectsEmptyKeys()
    {
        var provider = new FixedMasterKeyProvider(0x2A);
        var partitioner = new OidcRateLimitPartitioner(provider);
        Assert.Equal(0, provider.Calls);

        Parallel.For(0, 32, i => partitioner.Digest($"ip:198.51.100.{i}"));

        Assert.Equal(1, provider.Calls);
        Assert.ThrowsAny<ArgumentException>(() => partitioner.Digest(""));
        Assert.ThrowsAny<ArgumentException>(() => partitioner.Digest(null!));
    }
}
