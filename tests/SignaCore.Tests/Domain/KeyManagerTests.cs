using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using Xunit;

namespace SignaCore.Tests.Domain;

[Collection(SignaCore.Tests.Domain.Keys.MasterKeyStateCollection.Name)]
public class KeyManagerTests : IDisposable
{
    private const string TestRootSecret = "test_master_key_for_unit_tests_only_32bytes!";
    private string? _previousMasterKey;
    private bool _envVarSet;

    /// <summary>
    /// The single repository mock factory, with <c>GetValidKeysAsync</c> preset to an empty set.
    /// <para>
    /// Moq 4.20 returns null rather than an empty collection by default for
    /// <c>Task&lt;IReadOnlyList&lt;T&gt;&gt;</c>, and KeyManager always calls it during
    /// initialization to refresh the validation key snapshot, so without the preset it would throw
    /// a NullReferenceException. A test that needs a specific return value simply sets it up again
    /// on the mock it is handed.
    /// </para>
    /// </summary>
    private static Mock<ISecurityKeyRepository> CreateKeyRepoMock()
    {
        var mock = new Mock<ISecurityKeyRepository>();
        mock.Setup(r => r.GetValidKeysAsync()).ReturnsAsync(Array.Empty<SecurityKeyEntity>());
        return mock;
    }

    private static Mock<IServiceScopeFactory> CreateMockScopeFactory(
        Mock<ISecurityKeyRepository>? keyRepoMock = null,
        Mock<IUnitOfWork>? unitOfWorkMock = null)
    {
        var scopeFactoryMock = new Mock<IServiceScopeFactory>();
        var scopeMock = new Mock<IServiceScope>();
        var serviceProviderMock = new Mock<IServiceProvider>();

        serviceProviderMock
            .Setup(sp => sp.GetService(typeof(ISecurityKeyRepository)))
            .Returns((keyRepoMock ?? CreateKeyRepoMock()).Object);
        serviceProviderMock
            .Setup(sp => sp.GetService(typeof(IUnitOfWork)))
            .Returns((unitOfWorkMock ?? new Mock<IUnitOfWork>()).Object);

        scopeMock.Setup(s => s.ServiceProvider).Returns(serviceProviderMock.Object);
        scopeFactoryMock.Setup(f => f.CreateScope()).Returns(scopeMock.Object);

        return scopeFactoryMock;
    }

    private void SetEnvironmentMasterKey()
    {
        _previousMasterKey = Environment.GetEnvironmentVariable("RSA_MASTER_KEY");
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", "test_master_key_for_unit_tests_only_32bytes!");
        _envVarSet = true;
    }

    /// <summary>
    /// The real production encryption implementation, paired with the external root secret from the
    /// bootstrap file. The encryption logic itself is covered by AesGcmPrivateKeyProtectorTests;
    /// here it only exists so KeyManager can run.
    /// </summary>
    private static IPrivateKeyProtector CreateProtector(string rootSecret = TestRootSecret) =>
        new AesGcmPrivateKeyProtector(
            new BootstrapMasterKeyProvider(rootSecret));

    private const int AesNonceSize = 12;
    private const int AesTagSize = 16;

    private static (string encryptedKey, string salt) EncryptPrivateKeyForTest(byte[] pkcs8PrivateKey)
    {
        var masterKey = GetMasterKeyForTest();
        var salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        var saltBytes = Convert.FromBase64String(salt);

        var encryptKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            masterKey,
            32,
            saltBytes,
            Encoding.UTF8.GetBytes(IdentityConstants.PrivateKeyHkdfInfo));

        using var aes = new AesGcm(encryptKey, AesTagSize);
        var nonce = RandomNumberGenerator.GetBytes(AesNonceSize);

        var ciphertext = new byte[pkcs8PrivateKey.Length];
        var tag = new byte[AesTagSize];
        aes.Encrypt(nonce, pkcs8PrivateKey, ciphertext, tag);

        var encryptedKey = Convert.ToBase64String(nonce.Concat(tag).Concat(ciphertext).ToArray());

        return (encryptedKey, salt);
    }

    private static byte[] GetMasterKeyForTest()
    {
        var envKey = TestRootSecret;
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            Encoding.UTF8.GetBytes(envKey),
            32,
            Encoding.UTF8.GetBytes(IdentityConstants.MasterKeyHkdfSalt),
            Encoding.UTF8.GetBytes(IdentityConstants.MasterKeyHkdfInfo));
    }

    [Fact]
    public void Constructor_WithBootstrapMasterKey_Initializes()
    {
        var scopeFactoryMock = CreateMockScopeFactory();
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), logger);

        Assert.NotNull(keyManager);
        Assert.NotNull(keyManager.InitializationCompleted);
    }

    [Fact]
    public async Task GetCurrentKey_WhenKeyExists_ReturnsRsaSecurityKey()
    {
        SetEnvironmentMasterKey();

        var keyEntity = CreateTestSecurityKeyEntity();
        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(keyEntity);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), logger);
        await keyManager.InitializationCompleted;

        var key = keyManager.GetCurrentKey();

        Assert.NotNull(key);
        Assert.NotNull(key.KeyId);
        Assert.NotEmpty(key.KeyId);
    }

    [Fact]
    public async Task GetCurrentKey_WhenNoKeyExists_GeneratesNewKey()
    {
        SetEnvironmentMasterKey();

        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync((SecurityKeyEntity?)null);
        keyRepoMock.Setup(r => r.AddAsync(It.IsAny<SecurityKeyEntity>())).Returns(Task.CompletedTask);

        var unitOfWorkMock = new Mock<IUnitOfWork>();
        unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock, unitOfWorkMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), logger);
        await keyManager.InitializationCompleted;

        var key = keyManager.GetCurrentKey();

        Assert.NotNull(key);
        Assert.NotNull(key.KeyId);
        Assert.NotEmpty(key.KeyId);
        keyRepoMock.Verify(r => r.AddAsync(It.Is<SecurityKeyEntity>(k => k.IsActive)), Times.Once);
    }

    [Fact]
    public async Task NeedsKeyRotation_WhenKeyExpired_ReturnsTrue()
    {
        SetEnvironmentMasterKey();

        var keyEntity = CreateTestSecurityKeyEntity(expired: true);
        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetLatestKeyAsync()).ReturnsAsync(keyEntity);
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(keyEntity);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), logger);
        await keyManager.InitializationCompleted;

        Assert.True(await keyManager.NeedsKeyRotationAsync());
    }

    [Fact]
    public async Task NeedsKeyRotation_WhenKeyNotExpired_ReturnsFalse()
    {
        SetEnvironmentMasterKey();

        var keyEntity = CreateTestSecurityKeyEntity();
        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetLatestKeyAsync()).ReturnsAsync(keyEntity);
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(keyEntity);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), logger);
        await keyManager.InitializationCompleted;

        Assert.False(await keyManager.NeedsKeyRotationAsync());
    }

    [Fact]
    public async Task NeedsKeyRotation_WhenNoKeyExists_ReturnsTrue()
    {
        SetEnvironmentMasterKey();

        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetLatestKeyAsync()).ReturnsAsync((SecurityKeyEntity?)null);
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync((SecurityKeyEntity?)null);
        keyRepoMock.Setup(r => r.AddAsync(It.IsAny<SecurityKeyEntity>())).Returns(Task.CompletedTask);

        var unitOfWorkMock = new Mock<IUnitOfWork>();
        unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock, unitOfWorkMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), logger);
        await keyManager.InitializationCompleted;

        Assert.True(await keyManager.NeedsKeyRotationAsync());
    }

    [Fact]
    public async Task RotateKey_WhenActiveKeyHasSufficientLifetime_SkipsRotation()
    {
        SetEnvironmentMasterKey();

        var keyEntity = CreateTestSecurityKeyEntity();
        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(keyEntity);
        keyRepoMock.Setup(r => r.GetLatestKeyAsync()).ReturnsAsync(keyEntity);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), logger);
        await keyManager.InitializationCompleted;
        var originalKeyId = keyManager.GetCurrentKey().KeyId;

        await keyManager.RotateKeyAsync();

        Assert.Equal(originalKeyId, keyManager.GetCurrentKey().KeyId);
        keyRepoMock.Verify(r => r.AddAsync(It.IsAny<SecurityKeyEntity>()), Times.Never);
    }

    [Fact]
    public async Task RefreshKeys_WhenAnotherInstanceRotated_AdoptsDatabaseActiveKey()
    {
        SetEnvironmentMasterKey();

        var originalKey = CreateTestSecurityKeyEntity();
        originalKey.KeyId = "original-key";
        var replacementKey = CreateTestSecurityKeyEntity();
        replacementKey.KeyId = "replacement-key";

        var activeKey = originalKey;
        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(() => activeKey);
        keyRepoMock.Setup(r => r.GetValidKeysAsync()).ReturnsAsync(() => new[] { activeKey });

        var keyManager = new KeyManager(
            CreateMockScopeFactory(keyRepoMock).Object,
            CreateProtector(),
            NullLogger<KeyManager>.Instance);
        await keyManager.InitializationCompleted;
        Assert.Equal("original-key", keyManager.GetCurrentKey().KeyId);

        activeKey = replacementKey;
        await keyManager.RefreshKeysAsync();

        Assert.Equal("replacement-key", keyManager.GetCurrentKey().KeyId);
        Assert.Contains(keyManager.GetValidationKeys(), key => key.KeyId == "replacement-key");
    }

    [Fact]
    public async Task RotateKey_WhenKeyNeedsRotation_GeneratesNewKey()
    {
        SetEnvironmentMasterKey();

        var oldKey = CreateTestSecurityKeyEntity(expiresInDays: 5);
        oldKey.KeyId = "old-key";

        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(oldKey);
        keyRepoMock.Setup(r => r.AddAsync(It.IsAny<SecurityKeyEntity>())).Returns(Task.CompletedTask);

        var unitOfWorkMock = new Mock<IUnitOfWork>();
        unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock, unitOfWorkMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), logger);
        await keyManager.InitializationCompleted;

        await keyManager.RotateKeyAsync();

        var newKey = keyManager.GetCurrentKey();
        Assert.NotNull(newKey);
        Assert.NotEqual("old-key", newKey.KeyId);
        keyRepoMock.Verify(r => r.AddAsync(It.Is<SecurityKeyEntity>(k => k.IsActive)), Times.Once);
    }

    [Fact]
    public async Task RotateKey_DeactivatesOldKey()
    {
        SetEnvironmentMasterKey();

        var oldKey = CreateTestSecurityKeyEntity(expiresInDays: 5);
        oldKey.KeyId = "old-key-to-deactivate";

        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(oldKey);
        keyRepoMock.Setup(r => r.DeactivateAllActiveAsync()).ReturnsAsync(1);
        keyRepoMock.Setup(r => r.AddAsync(It.IsAny<SecurityKeyEntity>())).Returns(Task.CompletedTask);

        var unitOfWorkMock = new Mock<IUnitOfWork>();
        unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock, unitOfWorkMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), logger);
        await keyManager.InitializationCompleted;

        await keyManager.RotateKeyAsync();

        keyRepoMock.Verify(r => r.DeactivateAllActiveAsync(), Times.Once);
        unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.AtLeastOnce);
    }

    /// <summary>
    /// Once a key has expired, <c>GetActiveKeyAsync</c> returns null because it filters on
    /// <c>ExpiresAt &gt; now</c>. Deactivation therefore has to go through
    /// <c>DeactivateAllActiveAsync</c>: otherwise the old row stays stuck at IsActive=true, and
    /// since <c>RemoveExpiredInactiveAsync</c> only deletes !IsActive rows, every rotation would
    /// leave behind one more zombie row that can never be cleaned up.
    /// </summary>
    [Fact]
    public async Task RotateKey_WhenActiveKeyAlreadyExpired_StillDeactivatesStaleRows()
    {
        SetEnvironmentMasterKey();

        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync((SecurityKeyEntity?)null);
        keyRepoMock.Setup(r => r.DeactivateAllActiveAsync()).ReturnsAsync(1);
        keyRepoMock.Setup(r => r.AddAsync(It.IsAny<SecurityKeyEntity>())).Returns(Task.CompletedTask);

        var unitOfWorkMock = new Mock<IUnitOfWork>();
        unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock, unitOfWorkMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), logger);
        await keyManager.InitializationCompleted;

        await keyManager.RotateKeyAsync();

        keyRepoMock.Verify(r => r.DeactivateAllActiveAsync(), Times.Once);
        keyRepoMock.Verify(r => r.AddAsync(It.Is<SecurityKeyEntity>(k => k.IsActive)), Times.AtLeastOnce);
    }

    /// <summary>
    /// Regression: rotation has to trigger <b>before</b> the key expires (SPEC AC-FR-04/05: rotate
    /// once less than half the lifetime remains). The earlier implementation used
    /// <c>ExpiresAt &lt; now</c> and only returned true after expiry, and since JWKS publishes
    /// unexpired keys only, JWKS returned an empty array between expiry and the next CleanupWorker
    /// tick, failing validation for every downstream consumer.
    /// </summary>
    [Fact]
    public async Task NeedsKeyRotation_WhenKeyPastHalfLifeButNotExpired_ReturnsTrue()
    {
        SetEnvironmentMasterKey();

        // A key with a 30-day lifetime has 10 days left: past its half-life, but far from expired.
        var keyEntity = CreateTestSecurityKeyEntity(expiresInDays: 10);
        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetLatestKeyAsync()).ReturnsAsync(keyEntity);
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(keyEntity);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), logger);
        await keyManager.InitializationCompleted;

        Assert.True(await keyManager.NeedsKeyRotationAsync());
    }

    /// <summary>
    /// The snapshot behind <c>IssuerSigningKeyResolver</c> has to contain every unexpired key, not
    /// only the current signing key. Otherwise, at the moment of a rotation this service would
    /// reject tokens it had just issued under the previous key and that are still within their
    /// lifetime, while downstream microservices went on accepting them.
    /// </summary>
    [Fact]
    public async Task GetValidationKeys_ReturnsAllValidKeys_NotOnlyCurrentKey()
    {
        SetEnvironmentMasterKey();

        var activeKey = CreateTestSecurityKeyEntity();
        activeKey.KeyId = "current-key";

        var retiredButValidKey = CreateTestSecurityKeyEntity(expiresInDays: 12);
        retiredButValidKey.KeyId = "retired-but-still-valid";
        retiredButValidKey.IsActive = false;

        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(activeKey);
        keyRepoMock.Setup(r => r.GetValidKeysAsync())
            .ReturnsAsync(new[] { activeKey, retiredButValidKey });

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), logger);
        await keyManager.InitializationCompleted;

        var validationKeys = keyManager.GetValidationKeys();

        Assert.Equal(2, validationKeys.Count);
        Assert.Contains(validationKeys, k => k.KeyId == "current-key");
        Assert.Contains(validationKeys, k => k.KeyId == "retired-but-still-valid");
    }

    /// <summary>
    /// The validation key snapshot lives on a singleton for the lifetime of the process, and
    /// validation only needs public keys, so there is no reason for private key material to stay
    /// resident in it. Exporting the private parameters is expected to throw
    /// CryptographicException.
    /// </summary>
    [Fact]
    public async Task GetValidationKeys_ContainsPublicKeysOnly()
    {
        SetEnvironmentMasterKey();

        var activeKey = CreateTestSecurityKeyEntity();
        activeKey.KeyId = "public-only-check";

        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(activeKey);
        keyRepoMock.Setup(r => r.GetValidKeysAsync()).ReturnsAsync(new[] { activeKey });

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), logger);
        await keyManager.InitializationCompleted;

        var rsaKey = Assert.IsType<RsaSecurityKey>(Assert.Single(keyManager.GetValidationKeys()));

        // The public key is usable, which is what validation needs.
        var publicParameters = rsaKey.Rsa!.ExportParameters(includePrivateParameters: false);
        Assert.NotNull(publicParameters.Modulus);
        Assert.NotNull(publicParameters.Exponent);

        // The private key is not there. ThrowsAny rather than Throws: the latter requires an exact
        // exception type, and Windows (RSACng) and Linux (RSAOpenSsl) may throw different subclasses
        // of CryptographicException. CI runs on Linux and local development on Windows, so an exact
        // match would make this test fail for no reason when the platform changes.
        Assert.ThrowsAny<CryptographicException>(
            () => rsaKey.Rsa!.ExportParameters(includePrivateParameters: true));
    }

    /// <summary>
    /// The current signing key must be in the validation set at all times. <c>RotateKeyAsync</c>
    /// calls <c>SetCurrentKey</c> before refreshing the snapshot, so a failed refresh leaves the
    /// snapshot on old content that does not contain the current key. That snapshot is not empty,
    /// so the empty-snapshot fallback does not help: the service would reject every token it has
    /// just issued, with the exception swallowed into a single CleanupWorker log line.
    /// </summary>
    [Fact]
    public async Task GetValidationKeys_AlwaysIncludesCurrentKey_EvenWhenSnapshotIsStale()
    {
        SetEnvironmentMasterKey();

        var currentKey = CreateTestSecurityKeyEntity();
        currentKey.KeyId = "current-signing-key";

        var staleEntry = CreateTestSecurityKeyEntity(expiresInDays: 20);
        staleEntry.KeyId = "stale-snapshot-entry";

        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(currentKey);
        // A non-empty snapshot that does not contain the current signing key: the stale snapshot
        // left behind by a failed refresh.
        keyRepoMock.Setup(r => r.GetValidKeysAsync()).ReturnsAsync(new[] { staleEntry });

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock);
        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), NullLogger<KeyManager>.Instance);
        await keyManager.InitializationCompleted;

        var keyIds = keyManager.GetValidationKeys().Select(k => k.KeyId).ToList();

        Assert.Contains("current-signing-key", keyIds);
        Assert.Contains("stale-snapshot-entry", keyIds);
    }

    /// <summary>
    /// JwksMapper.ToJwk requires <c>RsaSecurityKey.Rsa</c> to be non-null (see JwksMapperTests).
    /// Taking the shortcut of <c>new RsaSecurityKey(RSAParameters)</c> for the public key copy would
    /// leave that property null and make the JWKS endpoint return 500.
    /// </summary>
    [Fact]
    public async Task GetValidationKeys_KeysExposeRsaInstance_ForJwksMapper()
    {
        SetEnvironmentMasterKey();

        var activeKey = CreateTestSecurityKeyEntity();
        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(activeKey);
        keyRepoMock.Setup(r => r.GetValidKeysAsync()).ReturnsAsync(new[] { activeKey });

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock);
        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), NullLogger<KeyManager>.Instance);
        await keyManager.InitializationCompleted;

        var rsaKey = Assert.IsType<RsaSecurityKey>(Assert.Single(keyManager.GetValidationKeys()));
        Assert.NotNull(rsaKey.Rsa);
    }

    [Fact]
    public async Task Initialization_WhenMasterKeyIsWrong_FailsClosedWithoutChangingStoredKeys()
    {
        var corruptedEntity = CreateTestSecurityKeyEntity();

        var keyRepoMock = CreateKeyRepoMock();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(corruptedEntity);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock);
        var logger = new TestLogger<KeyManager>();

        var keyManager = new KeyManager(
            scopeFactoryMock.Object,
            CreateProtector("DIFFERENT_test_master_key_for_unit_tests!!"),
            logger);
        var exception = await Assert.ThrowsAsync<CryptographicException>(
            () => keyManager.InitializationCompleted);

        Assert.Contains("could not be decrypted", exception.Message, StringComparison.Ordinal);
        Assert.Contains(logger.Entries, entry =>
            entry.LogLevel == LogLevel.Error &&
            entry.Message.Contains("failing closed", StringComparison.Ordinal));
        keyRepoMock.Verify(r => r.DeactivateAllActiveAsync(), Times.Never);
        keyRepoMock.Verify(r => r.AddAsync(It.IsAny<SecurityKeyEntity>()), Times.Never);
    }

    public void Dispose()
    {
        if (_envVarSet)
        {
            Environment.SetEnvironmentVariable("RSA_MASTER_KEY", _previousMasterKey);
        }

    }

    private static SecurityKeyEntity CreateTestSecurityKeyEntity(bool expired = false, int expiresInDays = 30)
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(true);
        var pkcs8 = rsa.ExportPkcs8PrivateKey();
        var (encryptedKey, salt) = EncryptPrivateKeyForTest(pkcs8);

        return new SecurityKeyEntity
        {
            Id = Guid.NewGuid(),
            KeyId = "test-key-id",
            PublicKeyExponent = Convert.ToBase64String(parameters.Exponent!),
            PublicKeyModulus = Convert.ToBase64String(parameters.Modulus!),
            EncryptedPrivateKeyParams = encryptedKey,
            EncryptionSalt = salt,
            CreatedAt = expired ? DateTimeOffset.UtcNow.AddDays(-40) : DateTimeOffset.UtcNow,
            ExpiresAt = expired ? DateTimeOffset.UtcNow.AddDays(-10) : DateTimeOffset.UtcNow.AddDays(expiresInDays),
            IsActive = true
        };
    }

    private class TestLogger<T> : ILogger<T>
    {
        public List<(LogLevel LogLevel, string Message, Exception? Exception)> Entries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Entries.Add((logLevel, formatter(state, exception), exception));
        }
    }
}
