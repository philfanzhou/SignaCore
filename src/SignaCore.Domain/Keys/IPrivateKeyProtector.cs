namespace SignaCore.Domain.Keys;

/// <summary>
/// Encryption at rest for RSA private keys. The byte format of <see cref="Protect"/> and
/// <see cref="Unprotect"/> is a <b>persistence contract</b>: every ciphertext already in the
/// database was written in the current format, so any change to it makes stored private keys
/// undecryptable and invalidates every JWT that has been issued.
/// </summary>
public interface IPrivateKeyProtector
{
    /// <summary>
    /// Encrypts a PKCS#8 private key and returns the base64 ciphertext together with the base64 salt
    /// used for this encryption.
    /// </summary>
    (string EncryptedKey, string Salt) Protect(byte[] pkcs8PrivateKey);

    /// <summary>
    /// Decrypts back to the PKCS#8 private key. A key that does not match throws
    /// <see cref="System.Security.Cryptography.CryptographicException"/>.
    /// </summary>
    byte[] Unprotect(string encryptedKey, string salt);
}
