using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;

namespace SignaCore.Domain.Keys;

public interface IKeyManager
{
    RsaSecurityKey GetCurrentKey();

    /// <summary>
    /// JwtBearer 校验用的密钥快照——同步、纯内存，不做 DB 往返（每个已认证请求都会调用）。
    /// 内容与 JWKS 发布的是同一批密钥，见 <see cref="KeyManager.GetValidationKeys"/>。
    /// </summary>
    IReadOnlyList<SecurityKey> GetValidationKeys();

    /// <summary>
    /// Refreshes the in-memory signing and validation key ring from the shared database.
    /// Multi-instance callers use this before signing and when an unfamiliar JWT <c>kid</c> is seen.
    /// </summary>
    // Default keeps third-party/test implementations of the existing interface source-compatible;
    // the built-in database-backed manager overrides it with multi-instance synchronization.
    Task RefreshKeysAsync() => Task.CompletedTask;

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
    Rotation
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
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private RsaSecurityKey? _currentKey;
    private IReadOnlyList<SecurityKey> _validationKeys = Array.Empty<SecurityKey>();

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
            // 必须在 SetResult 之前刷快照，否则第一批请求会拿到空的校验密钥集。
            // 这里只能调不等待 TCS 的私有版本，公开的 GetValidKeysAsync 会死锁。
            await RefreshValidationKeysAsync();
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

    /// <summary>
    /// JwtBearer 的 <c>IssuerSigningKeyResolver</c> 走这里，返回本实例已知的**全部**未过期密钥，
    /// 而不只是当前签名密钥：轮换后旧密钥签发的 token 仍在有效期内、JWKS 也还在发布它们，
    /// 本服务自己的 /api/profile/* 不能比下游微服务更严格。JWT 库按 <c>kid</c> 自动匹配。
    /// <para>
    /// 快照在初始化与轮换时刷新，新鲜度与 <see cref="GetCurrentKey"/> 一致——每请求读库对这个
    /// 调用频次来说不可接受。快照意外为空时兜底返回当前密钥，避免退化成"全部 401"。
    /// </para>
    /// <para>
    /// 快照里只有公钥：验签不需要私钥，而这个字段挂在单例上、生命周期与进程等长。
    /// 当前签名密钥 <see cref="_currentKey"/> 仍带私钥并被无条件并入返回值，但那是签发用的
    /// 密钥，本来就得常驻。
    /// </para>
    /// </summary>
    public IReadOnlyList<SecurityKey> GetValidationKeys()
    {
        lock (_keyLock)
        {
            if (_currentKey is null)
            {
                return _validationKeys;
            }

            // 正常路径：刷新成功的快照必然含当前密钥，直接返回，无额外分配。
            foreach (var key in _validationKeys)
            {
                if (key.KeyId == _currentKey.KeyId)
                {
                    return _validationKeys;
                }
            }

            // 当前签名密钥必须**永远**在校验集里。快照只在初始化与轮换时刷新，
            // 而 RotateKeyAsync 是先 SetCurrentKey 再刷快照：刷新一旦抛异常，
            // _currentKey 已是新密钥而快照还是旧的那份——它非空，所以"空则兜底"救不了，
            // 服务会拒掉自己刚签发的每一个 token，直到下次轮换（15 天）或重启，
            // 且异常被 CleanupWorker 吞成一条日志，健康检查全绿。
            var withCurrentKey = new List<SecurityKey>(_validationKeys.Count + 1);
            withCurrentKey.AddRange(_validationKeys);
            withCurrentKey.Add(_currentKey);
            return withCurrentKey;
        }
    }

    private async Task RefreshValidationKeysAsync()
    {
        var keys = await LoadValidKeysAsync();

        // 验签只需要公钥。LoadValidKeysAsync 返回的是带私钥的密钥（解密成功与否同时充当
        // "本实例是否仍掌握这把密钥"的准入判据，见 LoadValidKeysAsync 的注释），这里只取公钥部分
        // 存进快照——快照是单例上的长生命周期字段，没有理由让私钥常驻其中。
        var publicOnlyKeys = new List<SecurityKey>(keys.Count);
        foreach (var key in keys)
        {
            publicOnlyKeys.Add(ToPublicOnlyKey(key));
            // 私钥副本用完即弃，不等 GC 的终结器
            key.Rsa?.Dispose();
        }

        lock (_keyLock)
        {
            // 刻意不释放上一份快照：并发请求可能正持有从 GetValidationKeys 拿到的引用，
            // 释放会让验签中途抛 ObjectDisposedException。轮换 15 天才一次，交给 GC。
            _validationKeys = publicOnlyKeys;
        }
    }

    /// <summary>
    /// 复制出一把只含公钥的 <see cref="RsaSecurityKey"/>。
    /// 用 <see cref="RSA.ImportParameters"/> 而非直接 <c>new RsaSecurityKey(RSAParameters)</c>：
    /// 后者的 <c>Rsa</c> 属性为 null，会让 <c>JwksMapper.ToJwk</c> 抛异常，
    /// 也不符合调用方对该属性可用的预期。
    /// </summary>
    private static RsaSecurityKey ToPublicOnlyKey(RsaSecurityKey key)
    {
        var publicRsa = RSA.Create();
        publicRsa.ImportParameters(key.Rsa!.ExportParameters(includePrivateParameters: false));
        return new RsaSecurityKey(publicRsa) { KeyId = key.KeyId };
    }

    public async Task<IReadOnlyList<RsaSecurityKey>> GetValidKeysAsync()
    {
        await _initializationTcs.Task;
        return await LoadValidKeysAsync();
    }

    /// <summary>
    /// Reconciles this process with the database-backed key ring. The asynchronous gate prevents a
    /// burst of requests carrying the same newly-rotated <c>kid</c> from all decrypting and replacing
    /// the same key material concurrently.
    /// </summary>
    public async Task RefreshKeysAsync()
    {
        await _initializationTcs.Task;
        await _refreshLock.WaitAsync();
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var keyRepo = scope.ServiceProvider.GetRequiredService<ISecurityKeyRepository>();
            var activeKey = await keyRepo.GetActiveKeyAsync();

            if (activeKey is null ||
                string.Equals(GetCurrentKey().KeyId, activeKey.KeyId, StringComparison.Ordinal))
            {
                return;
            }

            SetCurrentKey(LoadKeyFromEntity(activeKey));
            _logger.LogInformation(
                "Adopted signing key {KeyId} created by another service instance",
                activeKey.KeyId);
            await RefreshValidationKeysAsync();
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    /// <summary>
    /// 从库里读全部未过期密钥。不等待 <see cref="InitializationCompleted"/>，
    /// 因此初始化流程内部也能调用。
    /// <para>
    /// 这里**必须**走私钥解密（<see cref="LoadKeyFromEntity"/>）而不是直接读
    /// <c>PublicKeyModulus</c> / <c>PublicKeyExponent</c> 明文列：解密成功与否同时充当
    /// "本实例是否仍掌握这把私钥"的准入判据。主密钥一旦变更，用旧主密钥保护的密钥就解不开——
    /// 此时那把私钥可能仍在他人手中，其公钥绝不能继续出现在 JWKS 里，否则等于替对方背书。
    /// 解不开的密钥记 Warning 后跳过。
    /// </para>
    /// <para>
    /// **所有权契约**：每次调用都构造全新的 <see cref="RsaSecurityKey"/>，不复用、不缓存，
    /// 调用方独占所有权并可自行释放（<see cref="RefreshValidationKeysAsync"/> 就依赖这一点）。
    /// 若将来在此处加缓存，必须同步改掉那边的 Dispose，否则 JWKS 请求会撞
    /// <see cref="ObjectDisposedException"/>。
    /// </para>
    /// </summary>
    private async Task<IReadOnlyList<RsaSecurityKey>> LoadValidKeysAsync()
    {
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

    /// <summary>
    /// 轮换窗口：剩余寿命不足总寿命的一半即进入（SPEC AC-FR-04/05）。
    /// <para>
    /// <see cref="NeedsKeyRotationAsync"/> 与 <see cref="RotateKeyAsync"/> 必须共用这一个判断。
    /// 此前二者阈值不同——前者是"已过期"、后者是"剩余不足一半"——于是轮换只可能发生在密钥
    /// **过期之后**，而 JWKS 只发布未过期的密钥（<c>GetValidKeysAsync</c> 过滤 <c>ExpiresAt &gt; now</c>），
    /// 从密钥过期到 CleanupWorker 下一次 tick（最长 24h）之间 JWKS 会返回空数组，
    /// 下游微服务拿不到任何公钥、全部 token 验签失败，而本服务仍在用内存里那把过期密钥继续签发。
    /// </para>
    /// </summary>
    private static bool IsInRotationWindow(SecurityKeyEntity key, DateTimeOffset utcNow) =>
        key.ExpiresAt <= utcNow.AddDays(IdentityConstants.KeyRotationDays / 2.0);

    public async Task<bool> NeedsKeyRotationAsync()
    {
        using var scope = _scopeFactory.CreateScope();
        var keyRepo = scope.ServiceProvider.GetRequiredService<ISecurityKeyRepository>();
        var keyEntity = await keyRepo.GetLatestKeyAsync();

        if (keyEntity == null) return true;

        return IsInRotationWindow(keyEntity, DateTimeOffset.UtcNow);
    }

    public async Task RotateKeyAsync()
    {
        await _initializationTcs.Task;
        await _refreshLock.WaitAsync();
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var keyRepo = scope.ServiceProvider.GetRequiredService<ISecurityKeyRepository>();
            var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();

            var existingKey = await keyRepo.GetActiveKeyAsync();

            if (existingKey != null && !IsInRotationWindow(existingKey, DateTimeOffset.UtcNow))
            {
                _logger.LogDebug("Active key still has sufficient lifetime, skipping rotation");
                return;
            }

            _logger.LogInformation("Rotating RSA key pair");

            // 停用所有 IsActive 行，而不是只停用 GetActiveKeyAsync 返回的那一条：后者带过期过滤，
            // 密钥过期后返回 null，旧行会永远留在 IsActive=true 且被 RemoveExpiredInactiveAsync 漏掉。
            // 不在这里 SaveChanges——与下面新密钥的插入合并成一次提交，中途不出现零个活跃密钥。
            var deactivatedCount = await keyRepo.DeactivateAllActiveAsync();

            SetCurrentKey(await GenerateAndSaveKeyAsync(keyRepo, unitOfWork, KeyGenerationReason.Rotation));

            // 停用是在上面那次 SaveChanges 里才落库的，日志必须等提交完成后再发：
            // 提交失败时不能留下一条"已停用 N 把密钥"、而实际已回滚的记录去误导排查。
            if (deactivatedCount > 0)
            {
                _logger.LogInformation("Deactivated {Count} previously active key(s)", deactivatedCount);
            }

            await RefreshValidationKeysAsync();
        }
        finally
        {
            _refreshLock.Release();
        }
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
                "Failed to decrypt the stored RSA signing key. Startup is failing closed; no key " +
                "was deactivated, generated, or replaced.");

            throw new CryptographicException(
                "The stored RSA signing key could not be decrypted with the configured master key. " +
                "Restore the bootstrap file that belongs to this database. Replacing the key " +
                "without rewrapping protected data is not supported.",
                ex);
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
