using System.Security.Cryptography;
using System.Text;
using SignaCore.Database;

namespace SignaCore.Domain.Keys;

/// <summary>
/// Derives the master key from the external root secret supplied by the protected bootstrap file.
/// <para>
/// The derivation is byte-for-byte compatible with the legacy <c>RSA_MASTER_KEY</c> path, so a
/// deployment that moves its existing root secret
/// into the bootstrap file keeps every stored RSA private key decryptable. The salt and info
/// literals are a contract with stored data and must not change.
/// </para>
/// </summary>
public sealed class BootstrapMasterKeyProvider : IMasterKeyProvider
{
    private const int MasterKeySizeBytes = 32;

    private readonly Lazy<byte[]> _masterKey;

    public BootstrapMasterKeyProvider(string rootSecret)
    {
        ArgumentException.ThrowIfNullOrEmpty(rootSecret);

        // Deriving lazily keeps the secret out of memory until something actually needs a key, and
        // matches the previous provider's "no side effects in the constructor" contract.
        _masterKey = new Lazy<byte[]>(
            () => HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                Encoding.UTF8.GetBytes(rootSecret),
                MasterKeySizeBytes,
                Encoding.UTF8.GetBytes(IdentityConstants.MasterKeyHkdfSalt),
                Encoding.UTF8.GetBytes(IdentityConstants.MasterKeyHkdfInfo)),
            LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public byte[] GetMasterKey() => _masterKey.Value;
}
