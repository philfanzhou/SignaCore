using System.Security.Cryptography;
using System.Text;
using SignaCore.Database;

namespace SignaCore.Domain.Keys;

/// <summary>
/// AES-GCM 实现。每次加密随机生成 16 字节 salt，用
/// <c>HKDF-SHA256(masterKey, salt, PrivateKeyHkdfInfo)</c> 派生 32 字节数据密钥，
/// 再以随机 12 字节 nonce 加密。
/// <para>
/// 持久化布局（base64 前的字节序）：<c>nonce(12) || tag(16) || ciphertext(N)</c>，
/// salt 与密文分列存储。**这些常量与顺序都是存量数据的契约，不可更改。**
/// </para>
/// </summary>
public sealed class AesGcmPrivateKeyProtector : IPrivateKeyProtector
{
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;
    private const int SaltSizeBytes = 16;
    private const int DerivedKeySizeBytes = 32;

    private readonly IMasterKeyProvider _masterKeyProvider;

    public AesGcmPrivateKeyProtector(IMasterKeyProvider masterKeyProvider)
    {
        _masterKeyProvider = masterKeyProvider;
    }

    public (string EncryptedKey, string Salt) Protect(byte[] pkcs8PrivateKey)
    {
        var saltBytes = RandomNumberGenerator.GetBytes(SaltSizeBytes);
        var salt = Convert.ToBase64String(saltBytes);

        using var aes = new AesGcm(DeriveDataKey(saltBytes), TagSizeBytes);
        var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);

        var ciphertext = new byte[pkcs8PrivateKey.Length];
        var tag = new byte[TagSizeBytes];
        aes.Encrypt(nonce, pkcs8PrivateKey, ciphertext, tag);

        var payload = new byte[NonceSizeBytes + TagSizeBytes + ciphertext.Length];
        nonce.CopyTo(payload, 0);
        tag.CopyTo(payload, NonceSizeBytes);
        ciphertext.CopyTo(payload, NonceSizeBytes + TagSizeBytes);

        return (Convert.ToBase64String(payload), salt);
    }

    public byte[] Unprotect(string encryptedKey, string salt)
    {
        var saltBytes = Convert.FromBase64String(salt);

        using var aes = new AesGcm(DeriveDataKey(saltBytes), TagSizeBytes);

        var payload = Convert.FromBase64String(encryptedKey);
        var nonce = payload.AsSpan(0, NonceSizeBytes);
        var tag = payload.AsSpan(NonceSizeBytes, TagSizeBytes);
        var ciphertext = payload.AsSpan(NonceSizeBytes + TagSizeBytes);

        var plaintext = new byte[ciphertext.Length];
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext;
    }

    private byte[] DeriveDataKey(byte[] saltBytes) =>
        HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            _masterKeyProvider.GetMasterKey(),
            DerivedKeySizeBytes,
            saltBytes,
            Encoding.UTF8.GetBytes(IdentityConstants.PrivateKeyHkdfInfo));
}
