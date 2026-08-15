using System.Security.Cryptography;
using System.Text;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using Xunit;

namespace SignaCore.Tests.Domain.Keys;

public class AesGcmConfigurationProtectorTests
{
    private const string RootSecret = "configuration-protection-root-secret";
    private const string SettingKey = "Sms:OtpHmacKey";

    [Fact]
    public void ProtectThenUnprotect_RoundTripsTheValue()
    {
        var protector = CreateProtector(RootSecret);
        const string plaintext = "cM6l3Q2r8+aBv0oNqYhJ7pS1wZfE4tXkR9uGdLmT0iA=";

        var restored = protector.Unprotect(SettingKey, protector.Protect(SettingKey, plaintext));

        Assert.Equal(plaintext, restored);
    }

    [Fact]
    public void Protect_ProducesADistinctEnvelopeEachTime()
    {
        var protector = CreateProtector(RootSecret);

        Assert.NotEqual(
            protector.Protect(SettingKey, "same-value"),
            protector.Protect(SettingKey, "same-value"));
    }

    /// <summary>
    /// A wrong root key must fail loudly rather than yield garbage that a subsystem then treats as
    /// a real credential.
    /// </summary>
    [Fact]
    public void Unprotect_WithADifferentRootKey_Fails()
    {
        var envelope = CreateProtector(RootSecret).Protect(SettingKey, "secret-value");

        Assert.Throws<AuthenticationTagMismatchException>(() =>
            CreateProtector("a-different-root-secret").Unprotect(SettingKey, envelope));
    }

    /// <summary>
    /// The setting key is authenticated associated data, so an envelope cannot be moved from one
    /// setting into another — for example a throwaway value into the OTP HMAC slot.
    /// </summary>
    [Fact]
    public void Unprotect_UnderADifferentSettingKey_Fails()
    {
        var protector = CreateProtector(RootSecret);
        var envelope = protector.Protect("WeChat:AppSecret", "secret-value");

        Assert.Throws<AuthenticationTagMismatchException>(() =>
            protector.Unprotect(SettingKey, envelope));
    }

    [Fact]
    public void Unprotect_WithTamperedCiphertext_Fails()
    {
        var protector = CreateProtector(RootSecret);
        var payload = Convert.FromBase64String(protector.Protect(SettingKey, "secret-value"));
        payload[^1] ^= 0xFF;

        Assert.Throws<AuthenticationTagMismatchException>(() =>
            protector.Unprotect(SettingKey, Convert.ToBase64String(payload)));
    }

    [Theory]
    [InlineData("not base64 at all!")]
    [InlineData("QUJD")]
    public void Unprotect_WithAMalformedEnvelope_ThrowsCryptographicException(string envelope)
    {
        var protector = CreateProtector(RootSecret);

        Assert.Throws<CryptographicException>(() => protector.Unprotect(SettingKey, envelope));
    }

    /// <summary>
    /// Configuration protection and RSA private-key protection share the root secret but must not
    /// share a derived key; the HKDF info values differ for exactly that reason.
    /// </summary>
    [Fact]
    public void ConfigurationEnvelopes_AreNotReadableByThePrivateKeyProtector()
    {
        var masterKeyProvider = new BootstrapMasterKeyProvider(RootSecret);
        var configurationProtector = new AesGcmConfigurationProtector(masterKeyProvider);
        var privateKeyProtector = new AesGcmPrivateKeyProtector(masterKeyProvider);

        var payload = Convert.FromBase64String(configurationProtector.Protect(SettingKey, "secret"));
        // The configuration layout is salt(16) || nonce(12) || tag(16) || ciphertext; the private-key
        // layout keeps the salt in a separate column. Feed it the same bytes in its own shape.
        var salt = Convert.ToBase64String(payload.AsSpan(0, 16));
        var body = Convert.ToBase64String(payload.AsSpan(16));

        Assert.ThrowsAny<CryptographicException>(() => privateKeyProtector.Unprotect(body, salt));
    }

    /// <summary>
    /// Regression guard for stored data: the bootstrap root secret must derive exactly the key the
    /// old <c>RSA_MASTER_KEY</c> path derived, or every stored RSA private key stops decrypting on
    /// upgrade.
    /// </summary>
    [Fact]
    public void BootstrapMasterKeyProvider_PreservesTheLegacyDerivation()
    {
        var expected = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            Encoding.UTF8.GetBytes(RootSecret),
            32,
            Encoding.UTF8.GetBytes(IdentityConstants.MasterKeyHkdfSalt),
            Encoding.UTF8.GetBytes(IdentityConstants.MasterKeyHkdfInfo));

        Assert.Equal(expected, new BootstrapMasterKeyProvider(RootSecret).GetMasterKey());
    }

    private static AesGcmConfigurationProtector CreateProtector(string rootSecret) =>
        new(new BootstrapMasterKeyProvider(rootSecret));
}
