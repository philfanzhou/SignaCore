using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;

namespace QuantumZhou.Identity.Domain.Keys;

public interface IKeyManager
{
    RsaSecurityKey GetCurrentKey();
    Task<IReadOnlyList<RsaSecurityKey>> GetValidKeysAsync();
    Task<bool> NeedsKeyRotationAsync();
    Task RotateKeyAsync();
    Task InitializationCompleted { get; }
}

/// <summary>生成新密钥对的场景。用于区分调用来源，不要再靠日志文案区分。</summary>
internal enum KeyGenerationReason
{
    /// <summary>库里没有可用密钥，首次生成。</summary>
    Initial,

    /// <summary>到期轮换。</summary>
    Rotation,

    /// <summary>主密钥丢失导致存量密文无法解密，强制重建。</summary>
    MasterKeyLost
}

/// <summary>
/// RSA 签名密钥的生命周期编排：启动时加载或创建当前密钥、按需轮换、对外提供
/// 当前密钥与全部有效公钥（供 JWKS）。
/// <para>
/// 主密钥的来源交给 <see cref="IMasterKeyProvider"/>，私钥的加解密交给
/// <see cref="IPrivateKeyProtector"/>——本类不接触任何密钥字节。
/// </para>
/// </summary>
public class KeyManager : IKeyManager
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IPrivateKeyProtector _protector;
    private readonly ILogger<KeyManager> _logger;
    private readonly TaskCompletionSource<bool> _initializationTcs = new();
    private readonly object _keyLock = new();
    private RsaSecurityKey? _currentKey;

    public Task InitializationCompleted => _initializationTcs.Task;

    public KeyManager(
        IServiceScopeFactory scopeFactory,
        IPrivateKeyProtector protector,
        ILogger<KeyManager> logger)
    {
        _scopeFactory = scopeFactory;
        _protector = protector;
        _logger = logger;

        // 即发即弃：构造函数不能 await。异常通过 _initializationTcs 传给
        // Program.cs 里的 `await keyManager.InitializationCompleted`，
        // 初始化失败即启动失败。
        _ = InitializeAsync();
    }

    private async Task InitializeAsync()
    {
        try
        {
            var key = await LoadOrCreateKeyAsync();
            SetCurrentKey(key);
            _initializationTcs.SetResult(true);
            _logger.LogInformation("KeyManager initialization completed");
        }
        catch (Exception ex)
        {
            _initializationTcs.SetException(ex);
            _logger.LogError(ex, "KeyManager initialization failed");
        }
    }

    public RsaSecurityKey GetCurrentKey()
    {
        // 单次加锁读取：此前的写法在锁外做 null 检查、锁内再读一次，
        // 读者得自己推演一遍才能确认没有竞态。
        lock (_keyLock)
        {
            return _currentKey
                ?? throw new InvalidOperationException(
                    "KeyManager is not initialized yet. Await InitializationCompleted before calling this method.");
        }
    }

    private void SetCurrentKey(RsaSecurityKey key)
    {
        lock (_keyLock)
        {
            _currentKey = key;
        }
    }

    public async Task<IReadOnlyList<RsaSecurityKey>> GetValidKeysAsync()
    {
        await _initializationTcs.Task;
        using var scope = _scopeFactory.CreateScope();
        var keyRepo = scope.ServiceProvider.GetRequiredService<ISecurityKeyRepository>();
        var keyEntities = await keyRepo.GetValidKeysAsync();

        var keys = new List<RsaSecurityKey>();
        foreach (var entity in keyEntities)
        {
            try
            {
                keys.Add(LoadKeyFromEntity(entity));
            }
            catch (CryptographicException ex)
            {
                _logger.LogWarning(ex, "Failed to load key {KeyId}, skipping", entity.KeyId);
            }
        }

        return keys;
    }

    public async Task<bool> NeedsKeyRotationAsync()
    {
        using var scope = _scopeFactory.CreateScope();
        var keyRepo = scope.ServiceProvider.GetRequiredService<ISecurityKeyRepository>();
        var keyEntity = await keyRepo.GetLatestKeyAsync();

        if (keyEntity == null) return true;

        return keyEntity.ExpiresAt < DateTimeOffset.UtcNow;
    }

    public async Task RotateKeyAsync()
    {
        using var scope = _scopeFactory.CreateScope();
        var keyRepo = scope.ServiceProvider.GetRequiredService<ISecurityKeyRepository>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();

        var existingKey = await keyRepo.GetActiveKeyAsync();

        if (existingKey != null && existingKey.ExpiresAt > DateTimeOffset.UtcNow.AddDays(IdentityConstants.KeyRotationDays / 2))
        {
            _logger.LogDebug("Active key still has sufficient lifetime, skipping rotation");
            return;
        }

        _logger.LogInformation("Rotating RSA key pair");

        if (existingKey != null)
        {
            existingKey.IsActive = false;
            await unitOfWork.SaveChangesAsync();
        }

        SetCurrentKey(await GenerateAndSaveKeyAsync(keyRepo, unitOfWork, KeyGenerationReason.Rotation));
    }

    private async Task<RsaSecurityKey> LoadOrCreateKeyAsync()
    {
        using var scope = _scopeFactory.CreateScope();
        var keyRepo = scope.ServiceProvider.GetRequiredService<ISecurityKeyRepository>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var keyEntity = await keyRepo.GetActiveKeyAsync();

        if (keyEntity == null)
        {
            return await GenerateAndSaveKeyAsync(keyRepo, unitOfWork, KeyGenerationReason.Initial);
        }

        try
        {
            _logger.LogInformation("Loaded RSA key from database, KeyId: {KeyId}", keyEntity.KeyId);
            return LoadKeyFromEntity(keyEntity);
        }
        catch (CryptographicException ex)
        {
            _logger.LogError(ex,
                "Failed to decrypt RSA key from database. Master key may have been lost. Re-encrypting with new key pair. " +
                "All previously issued JWTs are now invalid; operations team must audit master key provenance.");

            keyEntity.IsActive = false;
            await unitOfWork.SaveChangesAsync();
            var newKey = await GenerateAndSaveKeyAsync(keyRepo, unitOfWork, KeyGenerationReason.MasterKeyLost);
            SetCurrentKey(newKey);

            _logger.LogWarning("RSA key re-encrypted after master key loss. All clients must re-authenticate.");

            var freshEntity = await keyRepo.GetActiveKeyAsync();
            return LoadKeyFromEntity(freshEntity!);
        }
    }

    private async Task<RsaSecurityKey> GenerateAndSaveKeyAsync(
        ISecurityKeyRepository keyRepo,
        IUnitOfWork unitOfWork,
        KeyGenerationReason reason)
    {
        _logger.LogInformation("Generating new RSA key pair: Reason={Reason}", reason);

        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(true);

        var (encryptedKey, salt) = _protector.Protect(rsa.ExportPkcs8PrivateKey());

        var keyEntity = new SecurityKeyEntity
        {
            Id = Guid.NewGuid(),
            KeyId = Guid.NewGuid().ToString(),
            PublicKeyExponent = Convert.ToBase64String(parameters.Exponent!),
            PublicKeyModulus = Convert.ToBase64String(parameters.Modulus!),
            EncryptedPrivateKeyParams = encryptedKey,
            EncryptionSalt = salt,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(IdentityConstants.KeyRotationDays),
            IsActive = true
        };

        await keyRepo.AddAsync(keyEntity);
        await unitOfWork.SaveChangesAsync();

        _logger.LogInformation("RSA private key encrypted and saved, KeyId: {KeyId}", keyEntity.KeyId);

        var newRsa = RSA.Create();
        newRsa.ImportParameters(parameters);
        return new RsaSecurityKey(newRsa) { KeyId = keyEntity.KeyId };
    }

    private RsaSecurityKey LoadKeyFromEntity(SecurityKeyEntity entity)
    {
        var pkcs8PrivateKey = _protector.Unprotect(
            entity.EncryptedPrivateKeyParams,
            entity.EncryptionSalt);

        var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(pkcs8PrivateKey, out _);

        return new RsaSecurityKey(rsa) { KeyId = entity.KeyId };
    }
}
