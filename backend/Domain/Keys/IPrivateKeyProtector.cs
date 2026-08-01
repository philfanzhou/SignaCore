namespace QuantumZhou.Identity.Domain.Keys;

/// <summary>
/// RSA 私钥的静态加密。<see cref="Protect"/> 与 <see cref="Unprotect"/> 的字节格式是
/// **持久化契约**——库里存量的密文都是按当前格式写的，任何改动都会导致存量私钥
/// 无法解密、已签发的 JWT 全部失效。
/// </summary>
public interface IPrivateKeyProtector
{
    /// <summary>加密 PKCS#8 私钥，返回 base64 密文与本次使用的 base64 salt。</summary>
    (string EncryptedKey, string Salt) Protect(byte[] pkcs8PrivateKey);

    /// <summary>解密回 PKCS#8 私钥。密钥不匹配时抛 <see cref="System.Security.Cryptography.CryptographicException"/>。</summary>
    byte[] Unprotect(string encryptedKey, string salt);
}
