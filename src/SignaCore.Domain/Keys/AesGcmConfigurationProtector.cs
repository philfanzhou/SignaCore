using System.Security.Cryptography;
using System.Text;
using SignaCore.Database;

namespace SignaCore.Domain.Keys;

/// <summary>
/// AES-GCM protection for secret settings.
/// <para>
/// The root secret is shared with RSA private-key protection, but the derived key is not: the HKDF
/// info differs (<see cref="IdentityConstants.ConfigurationProtectionHkdfInfo"/> versus
/// <see cref="IdentityConstants.PrivateKeyHkdfInfo"/>), so the two data classes stay separated even
/// though one operator secret protects both.
/// </para>
/// <para>
/// Persisted layout (byte order before base64): <c>salt(16) || nonce(12) || tag(16) || ciphertext(N)</c>.
/// AAD is <c>UTF8("{settingKey}|{schemaVersion}")</c>. All of this is a contract with stored data.
/// </para>
/// </summary>
public sealed class AesGcmConfigurationProtector : IConfigurationProtector
{
    private const int SaltSizeBytes = 16;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;
    private const int DerivedKeySizeBytes = 32;
    private const int HeaderSizeBytes = SaltSizeBytes + NonceSizeBytes + TagSizeBytes;

    private readonly IMasterKeyProvider _masterKeyProvider;

    public AesGcmConfigurationProtector(IMasterKeyProvider masterKeyProvider)
    {
        _masterKeyProvider = masterKeyProvider;
    }

    public string Protect(string settingKey, string plaintext)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(settingKey);
        ArgumentNullException.ThrowIfNull(plaintext);

        var salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

        var payload = new byte[HeaderSizeBytes + plaintextBytes.Length];
        salt.CopyTo(payload, 0);
        nonce.CopyTo(payload, SaltSizeBytes);

        using var aes = new AesGcm(DeriveDataKey(salt), TagSizeBytes);
        aes.Encrypt(
            nonce,
            plaintextBytes,
            payload.AsSpan(HeaderSizeBytes),
            payload.AsSpan(SaltSizeBytes + NonceSizeBytes, TagSizeBytes),
            BuildAssociatedData(settingKey));

        return Convert.ToBase64String(payload);
    }

    public string Unprotect(string settingKey, string protectedValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(settingKey);
        ArgumentNullException.ThrowIfNull(protectedValue);

        byte[] payload;
        try
        {
            payload = Convert.FromBase64String(protectedValue);
        }
        catch (FormatException exception)
        {
            throw new CryptographicException(
                $"Protected value for setting '{settingKey}' is not valid base64.",
                exception);
        }

        if (payload.Length < HeaderSizeBytes)
        {
            throw new CryptographicException(
                $"Protected value for setting '{settingKey}' is truncated.");
        }

        var salt = payload.AsSpan(0, SaltSizeBytes).ToArray();
        var nonce = payload.AsSpan(SaltSizeBytes, NonceSizeBytes);
        var tag = payload.AsSpan(SaltSizeBytes + NonceSizeBytes, TagSizeBytes);
        var ciphertext = payload.AsSpan(HeaderSizeBytes);

        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(DeriveDataKey(salt), TagSizeBytes);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, BuildAssociatedData(settingKey));

        return Encoding.UTF8.GetString(plaintext);
    }

    private static byte[] BuildAssociatedData(string settingKey) =>
        Encoding.UTF8.GetBytes(
            $"{settingKey}|{IdentityConstants.ConfigurationProtectionSchemaVersion}");

    private byte[] DeriveDataKey(byte[] salt) =>
        HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            _masterKeyProvider.GetMasterKey(),
            DerivedKeySizeBytes,
            salt,
            Encoding.UTF8.GetBytes(IdentityConstants.ConfigurationProtectionHkdfInfo));
}
