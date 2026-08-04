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
using QuantumZhou.Identity.Domain.Keys;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain;

[Collection(QuantumZhou.Identity.Tests.Domain.Keys.MasterKeyStateCollection.Name)]
public class KeyManagerTests : IDisposable
{
    private string? _previousMasterKey;
    private bool _envVarSet;

    /// <summary>
    /// 统一的仓储 mock 工厂：预置 <c>GetValidKeysAsync</c> 返回空集合。
    /// <para>
    /// Moq 4.20 对 <c>Task&lt;IReadOnlyList&lt;T&gt;&gt;</c> 的默认返回是 null 而不是空集合，
    /// 而 KeyManager 初始化时必定调用它来刷新校验密钥快照，不预置就会 NRE。
    /// 需要具体返回值的用例在拿到 mock 后再 Setup 一次覆盖即可。
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
    /// 生产用的真实加解密实现（配合当前进程的 RSA_MASTER_KEY / 密钥文件）。
    /// 加解密逻辑本身另有 AesGcmPrivateKeyProtectorTests 覆盖，这里只是让 KeyManager 能跑起来。
    /// </summary>
    private static IPrivateKeyProtector CreateProtector() =>
        new AesGcmPrivateKeyProtector(
            new FileMasterKeyProvider(NullLogger<FileMasterKeyProvider>.Instance));

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
    /// 密钥已过期时 <c>GetActiveKeyAsync</c> 因带 <c>ExpiresAt &gt; now</c> 过滤而返回 null。
    /// 停用必须走 <c>DeactivateAllActiveAsync</c>——否则旧行永远卡在 IsActive=true，
    /// 而 <c>RemoveExpiredInactiveAsync</c> 只删 !IsActive，每轮换一次就多一条清不掉的僵尸行。
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
    /// 回归：轮换必须在密钥过期**之前**触发（SPEC AC-FR-04/05，剩余寿命不足一半即轮换）。
    /// 此前的实现是 <c>ExpiresAt &lt; now</c>，只有过期后才返回 true，而 JWKS 只发布未过期密钥，
    /// 于是过期到下次 CleanupWorker tick 之间 JWKS 返回空数组，下游全部验签失败。
    /// </summary>
    [Fact]
    public async Task NeedsKeyRotation_WhenKeyPastHalfLifeButNotExpired_ReturnsTrue()
    {
        SetEnvironmentMasterKey();

        // 30 天寿命的密钥只剩 10 天 —— 已过半衰期，但远未过期
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
    /// <c>IssuerSigningKeyResolver</c> 用的快照必须包含全部未过期密钥，而不只是当前签名密钥，
    /// 否则轮换瞬间本服务会拒掉自己刚签发、仍在有效期内的旧密钥 token，而下游微服务却认。
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

        var keyRepoMock = CreateKeyRepoMock();
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

        var keyManager = new KeyManager(scopeFactoryMock.Object, CreateProtector(), logger);
        await keyManager.InitializationCompleted;

        // Per KeyManagement 02-SPEC.md AC-FR-06: master key loss must log Error (not Warning)
        var errorEntries = logger.Entries.Where(e => e.LogLevel == LogLevel.Error).ToList();
        Assert.Single(errorEntries);
        Assert.Contains("Failed to decrypt RSA key", errorEntries[0].Message);
        Assert.Contains("master key", errorEntries[0].Message);

        // Recovery: a new key was generated and saved
        keyRepoMock.Verify(r => r.AddAsync(It.Is<SecurityKeyEntity>(k => k.IsActive)), Times.Once);
        Assert.NotNull(keyManager.GetCurrentKey());

        // 与 RotateKeyAsync 同一不变量：停用走集合操作，而不是只改 GetActiveKeyAsync 返回的那一条。
        // 单条停用会漏掉历史僵尸行，且其独立的 SaveChanges 会留下"零个活跃密钥"的中间态。
        keyRepoMock.Verify(r => r.DeactivateAllActiveAsync(), Times.Once);
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
