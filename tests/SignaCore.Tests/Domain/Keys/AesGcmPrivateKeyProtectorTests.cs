using System.Security.Cryptography;
using System.Text;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using Xunit;

namespace SignaCore.Tests.Domain.Keys;

/// <summary>
/// <see cref="AesGcmPrivateKeyProtector"/> 的字节格式是持久化契约：库里 security_keys 表
/// 存量的密文都按当前格式写入。格式一旦改变，存量私钥解不开、已签发的 JWT 全部失效。
/// 本文件用一份**独立重写**的参考实现交叉验证格式，而不是拿被测代码自己验自己。
/// </summary>
public class AesGcmPrivateKeyProtectorTests
{
    private sealed class FixedMasterKeyProvider : IMasterKeyProvider
    {
        private readonly byte[] _key;
        public FixedMasterKeyProvider(byte[] key) => _key = key;
        public byte[] GetMasterKey() => _key;
    }

    private const int NonceSize = 12;
    private const int TagSize = 16;

    private static byte[] MasterKey(byte fill = 0x2A) => Enumerable.Repeat(fill, 32).ToArray();

    private static AesGcmPrivateKeyProtector CreateProtector(byte fill = 0x2A) =>
        new(new FixedMasterKeyProvider(MasterKey(fill)));

    private static byte[] SamplePkcs8()
    {
        using var rsa = RSA.Create(2048);
        return rsa.ExportPkcs8PrivateKey();
    }

    /// <summary>
    /// 参考实现：与生产代码无共享代码路径，独立按约定的格式加密。
    /// 布局：base64(nonce(12) || tag(16) || ciphertext)，salt 单独 base64。
    /// </summary>
    private static (string EncryptedKey, string Salt) ReferenceEncrypt(byte[] plaintext, byte[] masterKey)
    {
        var saltBytes = RandomNumberGenerator.GetBytes(16);
        var dataKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            masterKey,
            32,
            saltBytes,
            Encoding.UTF8.GetBytes(IdentityConstants.PrivateKeyHkdfInfo));

        using var aes = new AesGcm(dataKey, TagSize);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        return (
            Convert.ToBase64String(nonce.Concat(tag).Concat(ciphertext).ToArray()),
            Convert.ToBase64String(saltBytes));
    }

    [Fact]
    public void ProtectThenUnprotect_RoundTrips()
    {
        var protector = CreateProtector();
        var plaintext = SamplePkcs8();

        var (encrypted, salt) = protector.Protect(plaintext);

        Assert.Equal(plaintext, protector.Unprotect(encrypted, salt));
    }

    [Fact]
    public void Unprotect_ReadsPayloadWrittenByIndependentReferenceImplementation()
    {
        // 格式兼容性：外部按约定格式写的密文，本实现必须能解开。
        // 这条覆盖了"存量数据能不能读"。
        var plaintext = SamplePkcs8();
        var (encrypted, salt) = ReferenceEncrypt(plaintext, MasterKey());

        Assert.Equal(plaintext, CreateProtector().Unprotect(encrypted, salt));
    }

    [Fact]
    public void Protect_ProducesPayloadReadableByIndependentReferenceImplementation()
    {
        // 反方向：本实现写的密文，按约定格式也必须能被外部解开。
        // 这条覆盖了"新写的数据格式有没有跑偏"。
        var plaintext = SamplePkcs8();
        var (encrypted, salt) = CreateProtector().Protect(plaintext);

        var payload = Convert.FromBase64String(encrypted);
        var dataKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            MasterKey(),
            32,
            Convert.FromBase64String(salt),
            Encoding.UTF8.GetBytes(IdentityConstants.PrivateKeyHkdfInfo));

        using var aes = new AesGcm(dataKey, TagSize);
        var decrypted = new byte[payload.Length - NonceSize - TagSize];
        aes.Decrypt(
            payload.AsSpan(0, NonceSize),
            payload.AsSpan(NonceSize + TagSize),
            payload.AsSpan(NonceSize, TagSize),
            decrypted);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Protect_LayoutIsNoncePlusTagPlusCiphertext()
    {
        var plaintext = SamplePkcs8();

        var (encrypted, salt) = CreateProtector().Protect(plaintext);

        var payload = Convert.FromBase64String(encrypted);
        Assert.Equal(NonceSize + TagSize + plaintext.Length, payload.Length);
        Assert.Equal(16, Convert.FromBase64String(salt).Length);
    }

    [Fact]
    public void Protect_UsesFreshSaltAndNonceEachCall()
    {
        var protector = CreateProtector();
        var plaintext = SamplePkcs8();

        var first = protector.Protect(plaintext);
        var second = protector.Protect(plaintext);

        Assert.NotEqual(first.Salt, second.Salt);
        Assert.NotEqual(first.EncryptedKey, second.EncryptedKey);
    }

    // 下面两条用 ThrowsAny：实际抛的是 AuthenticationTagMismatchException，
    // 它派生自 CryptographicException。KeyManager 里 catch 的是基类，
    // 所以基类才是这里要锁定的契约——换成精确匹配会把实现细节焊死在测试里。

    [Fact]
    public void Unprotect_WithDifferentMasterKey_ThrowsCryptographicException()
    {
        // 主密钥丢失/被换掉时必须抛 CryptographicException——
        // KeyManager 正是靠捕获它来触发"主密钥丢失，强制重建密钥对"的分支。
        var (encrypted, salt) = CreateProtector(0x2A).Protect(SamplePkcs8());

        Assert.ThrowsAny<CryptographicException>(
            () => CreateProtector(0x7B).Unprotect(encrypted, salt));
    }

    [Fact]
    public void Unprotect_WithTamperedCiphertext_ThrowsCryptographicException()
    {
        var protector = CreateProtector();
        var (encrypted, salt) = protector.Protect(SamplePkcs8());

        var payload = Convert.FromBase64String(encrypted);
        payload[^1] ^= 0xFF; // 翻转最后一个字节，GCM 校验必须发现
        var tampered = Convert.ToBase64String(payload);

        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(tampered, salt));
    }
}
