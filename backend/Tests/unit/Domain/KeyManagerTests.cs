using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain;

public class KeyManagerTests : IDisposable
{
    private string? _previousMasterKey;
    private bool _envVarSet;
    private static Mock<IServiceScopeFactory> CreateMockScopeFactory(
        Mock<ISecurityKeyRepository>? keyRepoMock = null,
        Mock<IUnitOfWork>? unitOfWorkMock = null)
    {
        var scopeFactoryMock = new Mock<IServiceScopeFactory>();
        var scopeMock = new Mock<IServiceScope>();
        var serviceProviderMock = new Mock<IServiceProvider>();

        serviceProviderMock
            .Setup(sp => sp.GetService(typeof(ISecurityKeyRepository)))
            .Returns((keyRepoMock ?? new Mock<ISecurityKeyRepository>()).Object);
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
        var envKey = "test_master_key_for_unit_tests_only_32bytes!";
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            Encoding.UTF8.GetBytes(envKey),
            32,
            Encoding.UTF8.GetBytes(IdentityConstants.MasterKeyHkdfSalt),
            Encoding.UTF8.GetBytes(IdentityConstants.MasterKeyHkdfInfo));
    }

    [Fact]
    public void Constructor_NoEnvironmentVariable_GeneratesNewMasterKeyFile()
    {
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", null);

        var scopeFactoryMock = CreateMockScopeFactory();
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, logger);

        Assert.NotNull(keyManager);
        Assert.NotNull(keyManager.InitializationCompleted);
    }

    [Fact]
    public async Task GetCurrentKey_WhenKeyExists_ReturnsRsaSecurityKey()
    {
        SetEnvironmentMasterKey();

        var keyEntity = CreateTestSecurityKeyEntity();
        var keyRepoMock = new Mock<ISecurityKeyRepository>();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(keyEntity);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, logger);
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

        var keyRepoMock = new Mock<ISecurityKeyRepository>();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync((SecurityKeyEntity?)null);
        keyRepoMock.Setup(r => r.AddAsync(It.IsAny<SecurityKeyEntity>())).Returns(Task.CompletedTask);

        var unitOfWorkMock = new Mock<IUnitOfWork>();
        unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock, unitOfWorkMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, logger);
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
        var keyRepoMock = new Mock<ISecurityKeyRepository>();
        keyRepoMock.Setup(r => r.GetLatestKeyAsync()).ReturnsAsync(keyEntity);
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(keyEntity);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, logger);
        await keyManager.InitializationCompleted;

        Assert.True(await keyManager.NeedsKeyRotationAsync());
    }

    [Fact]
    public async Task NeedsKeyRotation_WhenKeyNotExpired_ReturnsFalse()
    {
        SetEnvironmentMasterKey();

        var keyEntity = CreateTestSecurityKeyEntity();
        var keyRepoMock = new Mock<ISecurityKeyRepository>();
        keyRepoMock.Setup(r => r.GetLatestKeyAsync()).ReturnsAsync(keyEntity);
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(keyEntity);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, logger);
        await keyManager.InitializationCompleted;

        Assert.False(await keyManager.NeedsKeyRotationAsync());
    }

    [Fact]
    public async Task NeedsKeyRotation_WhenNoKeyExists_ReturnsTrue()
    {
        SetEnvironmentMasterKey();

        var keyRepoMock = new Mock<ISecurityKeyRepository>();
        keyRepoMock.Setup(r => r.GetLatestKeyAsync()).ReturnsAsync((SecurityKeyEntity?)null);
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync((SecurityKeyEntity?)null);
        keyRepoMock.Setup(r => r.AddAsync(It.IsAny<SecurityKeyEntity>())).Returns(Task.CompletedTask);

        var unitOfWorkMock = new Mock<IUnitOfWork>();
        unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock, unitOfWorkMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, logger);
        await keyManager.InitializationCompleted;

        Assert.True(await keyManager.NeedsKeyRotationAsync());
    }

    [Fact]
    public async Task RotateKey_WhenActiveKeyHasSufficientLifetime_SkipsRotation()
    {
        SetEnvironmentMasterKey();

        var keyEntity = CreateTestSecurityKeyEntity();
        var keyRepoMock = new Mock<ISecurityKeyRepository>();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(keyEntity);
        keyRepoMock.Setup(r => r.GetLatestKeyAsync()).ReturnsAsync(keyEntity);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, logger);
        await keyManager.InitializationCompleted;
        var originalKeyId = keyManager.GetCurrentKey().KeyId;

        await keyManager.RotateKeyAsync();

        Assert.Equal(originalKeyId, keyManager.GetCurrentKey().KeyId);
        keyRepoMock.Verify(r => r.AddAsync(It.IsAny<SecurityKeyEntity>()), Times.Never);
    }

    [Fact]
    public async Task RotateKey_WhenKeyNeedsRotation_GeneratesNewKey()
    {
        SetEnvironmentMasterKey();

        var oldKey = CreateTestSecurityKeyEntity(expiresInDays: 5);
        oldKey.KeyId = "old-key";

        var keyRepoMock = new Mock<ISecurityKeyRepository>();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(oldKey);
        keyRepoMock.Setup(r => r.AddAsync(It.IsAny<SecurityKeyEntity>())).Returns(Task.CompletedTask);

        var unitOfWorkMock = new Mock<IUnitOfWork>();
        unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock, unitOfWorkMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, logger);
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

        var keyRepoMock = new Mock<ISecurityKeyRepository>();
        keyRepoMock.Setup(r => r.GetActiveKeyAsync()).ReturnsAsync(oldKey);
        keyRepoMock.Setup(r => r.AddAsync(It.IsAny<SecurityKeyEntity>())).Returns(Task.CompletedTask);

        var unitOfWorkMock = new Mock<IUnitOfWork>();
        unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock, unitOfWorkMock);
        var logger = NullLogger<KeyManager>.Instance;

        var keyManager = new KeyManager(scopeFactoryMock.Object, logger);
        await keyManager.InitializationCompleted;

        await keyManager.RotateKeyAsync();

        Assert.False(oldKey.IsActive);
        unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.AtLeastOnce);
    }

    [Fact]
    public async Task Initialization_WhenMasterKeyLost_LogsErrorAndRegeneratesKey()
    {
        // Encrypt private key with the standard test master key (hardcoded in GetMasterKeyForTest)
        var corruptedEntity = CreateTestSecurityKeyEntity();

        // Override env to a DIFFERENT master key so KeyManager cannot decrypt the corrupted entity
        _previousMasterKey = Environment.GetEnvironmentVariable("RSA_MASTER_KEY");
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", "DIFFERENT_test_master_key_for_unit_tests!!");
        _envVarSet = true;

        // Capture the fresh entity generated by ForceRegenerateKeyAsync so the second
        // GetActiveKeyAsync call returns it (encrypted with the new master key, decryptable)
        SecurityKeyEntity? capturedFreshEntity = null;

        var keyRepoMock = new Mock<ISecurityKeyRepository>();
        keyRepoMock.SetupSequence(r => r.GetActiveKeyAsync())
            .ReturnsAsync(corruptedEntity)
            .ReturnsAsync(() => capturedFreshEntity!);

        keyRepoMock.Setup(r => r.AddAsync(It.IsAny<SecurityKeyEntity>()))
            .Callback<SecurityKeyEntity>(e => capturedFreshEntity = e)
            .Returns(Task.CompletedTask);

        var unitOfWorkMock = new Mock<IUnitOfWork>();
        unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);

        var scopeFactoryMock = CreateMockScopeFactory(keyRepoMock, unitOfWorkMock);
        var logger = new TestLogger<KeyManager>();

        var keyManager = new KeyManager(scopeFactoryMock.Object, logger);
        await keyManager.InitializationCompleted;

        // Per KeyManagement 02-SPEC.md AC-FR-06: master key loss must log Error (not Warning)
        var errorEntries = logger.Entries.Where(e => e.LogLevel == LogLevel.Error).ToList();
        Assert.Single(errorEntries);
        Assert.Contains("Failed to decrypt RSA key", errorEntries[0].Message);
        Assert.Contains("master key", errorEntries[0].Message);

        // Recovery: a new key was generated and saved
        keyRepoMock.Verify(r => r.AddAsync(It.Is<SecurityKeyEntity>(k => k.IsActive)), Times.Once);
        Assert.NotNull(keyManager.GetCurrentKey());
    }

    public void Dispose()
    {
        if (_envVarSet)
        {
            Environment.SetEnvironmentVariable("RSA_MASTER_KEY", _previousMasterKey);
        }

        // Clean up master key file left by Constructor_NoEnvironmentVariable_GeneratesNewMasterKeyFile
        var masterKeyDir = Path.Combine(AppContext.BaseDirectory, "data", "master-key");
        var masterKeyFile = Path.Combine(masterKeyDir, "master-key.json");
        if (File.Exists(masterKeyFile))
        {
            try { File.Delete(masterKeyFile); } catch { }
        }
        if (Directory.Exists(masterKeyDir))
        {
            try { Directory.Delete(masterKeyDir); } catch { }
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
