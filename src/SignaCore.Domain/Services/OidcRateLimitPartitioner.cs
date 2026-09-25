using System.Security.Cryptography;
using System.Text;
using SignaCore.Database;
using SignaCore.Domain.Keys;

namespace SignaCore.Domain.Services;

/// <summary>
/// Turns a raw OIDC rate-limit partition key (<c>client:{appId}</c> or <c>ip:{remote}</c>) into
/// the 64-character lowercase hex digest the shared budget table stores, so no raw client id or
/// source address is ever persisted.
/// <para>
/// The digest is <c>HMAC-SHA256(key, UTF8("v1\n" + partitionKey))</c> under a key derived once
/// from the master key with <c>HKDF-SHA256(masterKey, salt: empty,
/// info: <see cref="IdentityConstants.OidcRateLimitPartitionHkdfInfo"/>)</c>. Every instance that
/// shares one budget must share one root key; a different key or info resets every budget.
/// </para>
/// </summary>
public sealed class OidcRateLimitPartitioner
{
    private const int KeySizeBytes = 32;
    private const string DigestVersionPrefix = "v1\n";

    private readonly Lazy<byte[]> _key;

    public OidcRateLimitPartitioner(IMasterKeyProvider masterKeyProvider)
    {
        ArgumentNullException.ThrowIfNull(masterKeyProvider);
        _key = new Lazy<byte[]>(
            () => HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                masterKeyProvider.GetMasterKey(),
                KeySizeBytes,
                salt: [],
                info: Encoding.UTF8.GetBytes(IdentityConstants.OidcRateLimitPartitionHkdfInfo)),
            LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public string Digest(string partitionKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(partitionKey);
        var mac = HMACSHA256.HashData(_key.Value, Encoding.UTF8.GetBytes(DigestVersionPrefix + partitionKey));
        return Convert.ToHexStringLower(mac);
    }
}
