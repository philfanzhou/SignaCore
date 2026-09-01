using System.Security.Cryptography;
using System.Text;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using Xunit;

namespace SignaCore.Tests.Domain.Keys;

/// <summary>
/// The byte format of <see cref="AesGcmPrivateKeyProtector"/> is a persistence contract: every
/// ciphertext already in the security_keys table was written in the current format. Change the
/// format and stored private keys stop decrypting, invalidating every JWT that has been issued.
/// These tests cross-check the format against an <b>independently rewritten</b> reference
/// implementation rather than letting the code under test verify itself.
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
    /// The reference implementation: it shares no code path with production and encrypts to the
    /// agreed format on its own.
    /// Layout: base64(nonce(12) || tag(16) || ciphertext), with the salt base64-encoded separately.
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
        // Format compatibility: a ciphertext written elsewhere in the agreed format has to decrypt
        // here. This is the "can the data already in the database still be read" direction.
        var plaintext = SamplePkcs8();
        var (encrypted, salt) = ReferenceEncrypt(plaintext, MasterKey());

        Assert.Equal(plaintext, CreateProtector().Unprotect(encrypted, salt));
    }

    [Fact]
    public void Protect_ProducesPayloadReadableByIndependentReferenceImplementation()
    {
        // The other direction: a ciphertext written here has to be readable elsewhere from the
        // agreed format. This is the "has the format of newly written data drifted" direction.
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

    // The two tests below use ThrowsAny: what is actually thrown is
    // AuthenticationTagMismatchException, which derives from CryptographicException. KeyManager
    // catches the base type, so the base type is the contract to pin down here — an exact match
    // would weld an implementation detail into the tests.

    [Fact]
    public void Unprotect_WithDifferentMasterKey_ThrowsCryptographicException()
    {
        // A lost or replaced master key has to throw CryptographicException; that is what lets
        // KeyManager fail startup closed instead of silently deactivating or regenerating an
        // existing signing key.
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
        payload[^1] ^= 0xFF; // Flip the last byte; the GCM tag check has to notice.
        var tampered = Convert.ToBase64String(payload);

        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(tampered, salt));
    }
}
