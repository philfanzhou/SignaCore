using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;

namespace QuantumZhou.Identity.Domain;

public class MasterKeyInfo
{
    public string EncodedKey { get; set; } = string.Empty;
    public DateTimeOffset GeneratedAt { get; set; }
}

public interface IKeyManager
{
    RsaSecurityKey GetCurrentKey();
    Task<IReadOnlyList<RsaSecurityKey>> GetValidKeysAsync();
    Task<bool> NeedsKeyRotationAsync();
    Task RotateKeyAsync();
    Task InitializationCompleted { get; }
}

public class KeyManager : IKeyManager
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<KeyManager> _logger;
    private readonly byte[] _masterKey;
    private RsaSecurityKey? _currentKey;
    private readonly object _keyLock = new();
    private readonly TaskCompletionSource<bool> _initializationTcs;
    private readonly string _masterKeyDirectory;
    private readonly string _masterKeyFilePath;

    public Task InitializationCompleted => _initializationTcs.Task;

    public KeyManager(IServiceScopeFactory scopeFactory, ILogger<KeyManager> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
        _masterKeyDirectory = Path.Combine(AppContext.BaseDirectory, "master-key");
        _masterKeyFilePath = Path.Combine(_masterKeyDirectory, "master-key.json");

        if (!Directory.Exists(_masterKeyDirectory))
        {
            Directory.CreateDirectory(_masterKeyDirectory);
        }

        _masterKey = GetMasterKey();
        _initializationTcs = new TaskCompletionSource<bool>();
        
        _ = InitializeAsync();
    }

    private async Task InitializeAsync()
    {
        try
        {
            var key = await LoadOrCreateKeyAsync();
            lock (_keyLock)
            {
                _currentKey = key;
            }
            _initializationTcs.SetResult(true);
            _logger.LogInformation("KeyManager initialization completed");
        }
        catch (Exception ex)
        {
            _initializationTcs.SetException(ex);
            _logger.LogError(ex, "KeyManager initialization failed");
        }
    }

    private byte[] GetMasterKey()
    {
        var envMasterKey = Environment.GetEnvironmentVariable("RSA_MASTER_KEY");
        if (!string.IsNullOrEmpty(envMasterKey))
        {
            var derivedKey = HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                Encoding.UTF8.GetBytes(envMasterKey),
                32,
                Encoding.UTF8.GetBytes(IdentityConstants.MasterKeyInfo),
                Encoding.UTF8.GetBytes(IdentityConstants.KeyProtectionLabel));
            _logger.LogInformation("Using RSA master key from environment variable");
            return derivedKey;
        }

        var existingKey = ReadMasterKeyFile();
        if (existingKey != null)
        {
            _logger.LogInformation("Loaded existing RSA master key from file");
            return existingKey;
        }

        _logger.LogInformation("No RSA master key file found, generating new one");
        var newKey = GenerateAndSaveMasterKey();
        return newKey;
    }

    private byte[]? ReadMasterKeyFile()
    {
        if (!File.Exists(_masterKeyFilePath))
        {
            return null;
        }

        try
        {
            var json = File.ReadAllText(_masterKeyFilePath);
            var info = JsonSerializer.Deserialize<MasterKeyInfo>(json);
            if (info == null || string.IsNullOrEmpty(info.EncodedKey))
            {
                return null;
            }
            return Convert.FromBase64String(info.EncodedKey);
        }
        catch
        {
            return null;
        }
    }

    private byte[] GenerateAndSaveMasterKey()
    {
        var keyBytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(keyBytes);
        }

        var info = new MasterKeyInfo
        {
            EncodedKey = Convert.ToBase64String(keyBytes),
            GeneratedAt = DateTimeOffset.UtcNow
        };

        var json = JsonSerializer.Serialize(info, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_masterKeyFilePath, json);

        _logger.LogInformation("New RSA master key generated and saved to {Path}", _masterKeyFilePath);
        return keyBytes;
    }

    public async Task<RsaSecurityKey> GetCurrentKeyAsync()
    {
        await _initializationTcs.Task;
        lock (_keyLock)
        {
            return _currentKey!;
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

    public RsaSecurityKey GetCurrentKey()
    {
        if (_currentKey == null)
        {
            throw new InvalidOperationException("KeyManager is not initialized yet. Await InitializationCompleted before calling this method.");
        }
        
        lock (_keyLock)
        {
            return _currentKey!;
        }
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

        var newKey = await GenerateAndSaveKeyAsync(keyRepo, unitOfWork, "RSA key rotated");
        lock (_keyLock)
        {
            _currentKey = newKey;
        }
    }

    private async Task<RsaSecurityKey> LoadOrCreateKeyAsync()
    {
        using var scope = _scopeFactory.CreateScope();
        var keyRepo = scope.ServiceProvider.GetRequiredService<ISecurityKeyRepository>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var keyEntity = await keyRepo.GetActiveKeyAsync();

        if (keyEntity != null)
        {
            try
            {
                _logger.LogInformation("Loaded RSA key from database, KeyId: {KeyId}", keyEntity.KeyId);
                return LoadKeyFromEntity(keyEntity);
            }
            catch (CryptographicException ex)
            {
                _logger.LogWarning(ex, "Failed to decrypt RSA key from database. Master key may have been lost. Re-encrypting with new key pair.");
                await ForceRegenerateKeyAsync(keyRepo, unitOfWork, keyEntity);
                _logger.LogInformation("RSA key re-encrypted. All clients must re-authenticate.");
                var freshEntity = await keyRepo.GetActiveKeyAsync();
                return LoadKeyFromEntity(freshEntity!);
            }
        }

        return await GenerateAndSaveKeyAsync(keyRepo, unitOfWork, "Generating new RSA key pair");
    }

    private async Task ForceRegenerateKeyAsync(ISecurityKeyRepository keyRepo, IUnitOfWork unitOfWork, SecurityKeyEntity oldEntity)
    {
        oldEntity.IsActive = false;
        await unitOfWork.SaveChangesAsync();

        var newKey = await GenerateAndSaveKeyAsync(keyRepo, unitOfWork, "Master key lost - generating new RSA key pair");
        lock (_keyLock)
        {
            _currentKey = newKey;
        }
    }

    private async Task<RsaSecurityKey> GenerateAndSaveKeyAsync(ISecurityKeyRepository keyRepo, IUnitOfWork unitOfWork, string logMessage)
    {
        _logger.LogInformation(logMessage);

        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(true);

        var pkcs8 = rsa.ExportPkcs8PrivateKey();
        var (encryptedKey, salt) = EncryptPrivateKey(pkcs8);

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
        var key = new RsaSecurityKey(newRsa)
        {
            KeyId = keyEntity.KeyId
        };

        return key;
    }

    private const int AesNonceSize = 12;
    private const int AesTagSize = 16;

    private (string encryptedKey, string salt) EncryptPrivateKey(byte[] pkcs8PrivateKey)
    {
        var salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        var saltBytes = Convert.FromBase64String(salt);

        var encryptKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            _masterKey,
            32,
            saltBytes,
            Encoding.UTF8.GetBytes(IdentityConstants.KeyEncryptLabel));

        using var aes = new AesGcm(encryptKey, AesTagSize);
        var nonce = RandomNumberGenerator.GetBytes(AesNonceSize);

        var ciphertext = new byte[pkcs8PrivateKey.Length];
        var tag = new byte[AesTagSize];
        aes.Encrypt(nonce, pkcs8PrivateKey, ciphertext, tag);

        var encryptedKey = Convert.ToBase64String(nonce.Concat(tag).Concat(ciphertext).ToArray());

        return (encryptedKey, salt);
    }

    private byte[] DecryptPrivateKey(string encryptedKey, string salt)
    {
        var saltBytes = Convert.FromBase64String(salt);
        var encryptKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            _masterKey,
            32,
            saltBytes,
            Encoding.UTF8.GetBytes(IdentityConstants.KeyEncryptLabel));

        using var aes = new AesGcm(encryptKey, AesTagSize);

        var ciphertextBytes = Convert.FromBase64String(encryptedKey);

        var nonce = ciphertextBytes.AsSpan(0, AesNonceSize);
        var tag = ciphertextBytes.AsSpan(AesNonceSize, AesTagSize);
        var ciphertext = ciphertextBytes.AsSpan(AesNonceSize + AesTagSize);

        var plaintext = new byte[ciphertext.Length];
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext;
    }

    private RsaSecurityKey LoadKeyFromEntity(SecurityKeyEntity entity)
    {
        var pkcs8PrivateKey = DecryptPrivateKey(
            entity.EncryptedPrivateKeyParams,
            entity.EncryptionSalt);

        var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(pkcs8PrivateKey, out _);

        return new RsaSecurityKey(rsa) { KeyId = entity.KeyId };
    }
}
