namespace SignaCore.Domain.Keys;

/// <summary>
/// Provides the master key (32 bytes) used to encrypt RSA private keys.
/// </summary>
public interface IMasterKeyProvider
{
    /// <summary>
    /// Gets the master key. Implementations should cache the result; this method may trigger disk I/O.
    /// </summary>
    byte[] GetMasterKey();
}
