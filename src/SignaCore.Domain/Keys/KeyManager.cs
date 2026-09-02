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
    /// The key snapshot JwtBearer validates against: synchronous, purely in memory, and without a
    /// database round trip (every authenticated request calls it). It holds the same set of keys
    /// JWKS publishes; see <see cref="KeyManager.GetValidationKeys"/>.
    /// </summary>
    IReadOnlyList<SecurityKey> GetValidationKeys();

    /// <summary>
    /// Refreshes the in-memory signing and validation key ring from the shared database.
    /// Multi-instance callers use this before signing and when an unfamiliar JWT <c>kid</c> is seen.
    /// </summary>
    // Default keeps third-party/test implementations of the existing interface source-compatible;
    // the built-in database-backed manager overrides it with multi-instance synchronization.
    Task RefreshKeysAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

    Task<IReadOnlyList<RsaSecurityKey>> GetValidKeysAsync(CancellationToken cancellationToken = default);
    Task<bool> NeedsKeyRotationAsync(CancellationToken cancellationToken = default);
    Task RotateKeyAsync(CancellationToken cancellationToken = default);
    Task InitializationCompleted { get; }
}

/// <summary>
/// Why a new key pair is being generated. It exists so callers can be told apart by value rather
/// than by the wording of a log message.
/// </summary>
internal enum KeyGenerationReason
{
    /// <summary>No usable key exists in the database yet; this is the first generation.</summary>
    Initial,

    /// <summary>The current key is due for rotation.</summary>
    Rotation
}

/// <summary>
/// Lifecycle orchestration for the RSA signing keys: load or create the current key at startup,
/// rotate it when it is due, and expose the current key together with every valid public key for
/// JWKS.
/// <para>
/// Where the master key comes from is <see cref="IMasterKeyProvider"/>'s concern, and encrypting or
/// decrypting a private key is <see cref="IPrivateKeyProtector"/>'s — this class never touches any
/// key material itself.
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

        // Fire and forget: a constructor cannot await. Failures travel through _initializationTcs
        // to the `await keyManager.InitializationCompleted` in Program.cs, so a failed
        // initialization is a failed startup.
        _ = InitializeAsync();
    }

    private async Task InitializeAsync()
    {
        try
        {
            var key = await LoadOrCreateKeyAsync();
            SetCurrentKey(key);
            // The snapshot has to be refreshed before SetResult, or the first requests would see
            // an empty validation key set. Only the private variant, which does not await the TCS,
            // can be called here; the public GetValidKeysAsync would deadlock.
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
        // One read under one lock. The earlier shape null-checked outside the lock and read again
        // inside it, which left the reader to work out for themselves that there was no race.
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
    /// The resolver behind JwtBearer's <c>IssuerSigningKeyResolver</c>. It returns <b>every</b>
    /// unexpired key this instance knows about rather than only the current signing key: after a
    /// rotation, tokens signed by the previous key are still within their lifetime and JWKS still
    /// publishes them, so this service's own /api/profile/* must not be stricter than a downstream
    /// microservice. The JWT library matches by <c>kid</c>.
    /// <para>
    /// The snapshot is refreshed at initialization and at rotation, which makes it exactly as fresh
    /// as <see cref="GetCurrentKey"/> — a database read per request is not acceptable at this call
    /// rate. If the snapshot is unexpectedly empty, the current key is returned as a fallback so the
    /// service does not degrade into rejecting everything with 401.
    /// </para>
    /// <para>
    /// The snapshot holds public keys only: signature validation does not need a private key, and
    /// this field lives on a singleton for the lifetime of the process. The current signing key
    /// <see cref="_currentKey"/> still carries its private key and is merged into the result
    /// unconditionally, but that is the issuing key and has to stay resident anyway.
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

            // The normal path: a successfully refreshed snapshot always contains the current key,
            // so it is returned as is, with no extra allocation.
            foreach (var key in _validationKeys)
            {
                if (key.KeyId == _currentKey.KeyId)
                {
                    return _validationKeys;
                }
            }

            // The current signing key must be in the validation set at all times. The snapshot is
            // only refreshed at initialization and at rotation, and RotateKeyAsync calls
            // SetCurrentKey before refreshing it: if that refresh throws, _currentKey is already the
            // new key while the snapshot is still the old one. That snapshot is not empty, so the
            // empty-snapshot fallback does not help, and the service would reject every token it
            // has just issued until the next rotation (15 days) or a restart — with the exception
            // swallowed into a single CleanupWorker log line and every health check still green.
            var withCurrentKey = new List<SecurityKey>(_validationKeys.Count + 1);
            withCurrentKey.AddRange(_validationKeys);
            withCurrentKey.Add(_currentKey);
            return withCurrentKey;
        }
    }

    private async Task RefreshValidationKeysAsync(CancellationToken cancellationToken = default)
    {
        var keys = await LoadValidKeysAsync(cancellationToken);

        // Validation only needs public keys. LoadValidKeysAsync returns keys that carry their
        // private half (whether decryption succeeds doubles as the admission test for "does this
        // instance still hold this key"; see the comments on LoadValidKeysAsync), so only the public
        // part goes into the snapshot — that field is long-lived on a singleton, and there is no
        // reason for private key material to stay resident in it.
        var publicOnlyKeys = new List<SecurityKey>(keys.Count);
        foreach (var key in keys)
        {
            publicOnlyKeys.Add(ToPublicOnlyKey(key));
            // The private key copy is finished with here; do not wait for the GC finalizer.
            key.Rsa?.Dispose();
        }

        lock (_keyLock)
        {
            // The previous snapshot is deliberately not disposed: concurrent requests may still
            // hold a reference handed out by GetValidationKeys, and disposing it would make
            // validation throw ObjectDisposedException mid-flight. Rotation happens once every 15
            // days, so the GC can have it.
            _validationKeys = publicOnlyKeys;
        }
    }

    /// <summary>
    /// Copies a key into a public-key-only <see cref="RsaSecurityKey"/>.
    /// <see cref="RSA.ImportParameters"/> is used instead of <c>new RsaSecurityKey(RSAParameters)</c>
    /// because the latter leaves the <c>Rsa</c> property null, which makes <c>JwksMapper.ToJwk</c>
    /// throw and breaks the expectation callers have that the property is usable.
    /// </summary>
    private static RsaSecurityKey ToPublicOnlyKey(RsaSecurityKey key)
    {
        var publicRsa = RSA.Create();
        publicRsa.ImportParameters(key.Rsa!.ExportParameters(includePrivateParameters: false));
        return new RsaSecurityKey(publicRsa) { KeyId = key.KeyId };
    }

    public async Task<IReadOnlyList<RsaSecurityKey>> GetValidKeysAsync(
        CancellationToken cancellationToken = default)
    {
        await _initializationTcs.Task.WaitAsync(cancellationToken);
        return await LoadValidKeysAsync(cancellationToken);
    }

    /// <summary>
    /// Reconciles this process with the database-backed key ring. The asynchronous gate prevents a
    /// burst of requests carrying the same newly-rotated <c>kid</c> from all decrypting and replacing
    /// the same key material concurrently.
    /// </summary>
    public async Task RefreshKeysAsync(CancellationToken cancellationToken = default)
    {
        await _initializationTcs.Task.WaitAsync(cancellationToken);
        await _refreshLock.WaitAsync(cancellationToken);
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var keyRepo = scope.ServiceProvider.GetRequiredService<ISecurityKeyRepository>();
            var activeKey = await keyRepo.GetActiveKeyAsync(cancellationToken);

            if (activeKey is null ||
                string.Equals(GetCurrentKey().KeyId, activeKey.KeyId, StringComparison.Ordinal))
            {
                return;
            }

            SetCurrentKey(LoadKeyFromEntity(activeKey));
            _logger.LogInformation(
                "Adopted signing key {KeyId} created by another service instance",
                activeKey.KeyId);
            await RefreshValidationKeysAsync(cancellationToken);
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    /// <summary>
    /// Reads every unexpired key from the database. It does not await
    /// <see cref="InitializationCompleted"/>, so the initialization flow itself can call it.
    /// <para>
    /// It <b>must</b> go through private key decryption (<see cref="LoadKeyFromEntity"/>) rather
    /// than read the plaintext <c>PublicKeyModulus</c> / <c>PublicKeyExponent</c> columns directly:
    /// whether decryption succeeds doubles as the admission test for "does this instance still hold
    /// this private key". Once the master key changes, a key protected by the previous master key no
    /// longer decrypts here — and that private key may well still be in someone else's hands, so its
    /// public key must not keep appearing in JWKS, which would amount to vouching for them. A key
    /// that does not decrypt is logged as a Warning and skipped.
    /// </para>
    /// <para>
    /// <b>Ownership contract</b>: every call constructs brand new <see cref="RsaSecurityKey"/>
    /// instances; nothing is reused or cached, so the caller owns them exclusively and may dispose
    /// them (<see cref="RefreshValidationKeysAsync"/> relies on exactly that). Adding a cache here
    /// later would require changing that disposal too, or JWKS requests would hit
    /// <see cref="ObjectDisposedException"/>.
    /// </para>
    /// </summary>
    private async Task<IReadOnlyList<RsaSecurityKey>> LoadValidKeysAsync(
        CancellationToken cancellationToken = default)
    {
        using var scope = _scopeFactory.CreateScope();
        var keyRepo = scope.ServiceProvider.GetRequiredService<ISecurityKeyRepository>();
        var keyEntities = await keyRepo.GetValidKeysAsync(cancellationToken);

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
    /// The rotation window: a key enters it once less than half of its total lifetime remains
    /// (SPEC AC-FR-04/05).
    /// <para>
    /// <see cref="NeedsKeyRotationAsync"/> and <see cref="RotateKeyAsync"/> must share this single
    /// decision. They once used different thresholds — "already expired" for the former and "less
    /// than half remaining" for the latter — so rotation could only ever happen <b>after</b> a key
    /// had expired. JWKS publishes unexpired keys only (<c>GetValidKeysAsync</c> filters on
    /// <c>ExpiresAt &gt; now</c>), so between the moment a key expired and the next CleanupWorker
    /// tick (up to 24h) JWKS returned an empty array: downstream microservices had no public key at
    /// all and every token failed validation, while this service kept signing with the expired key
    /// still held in memory.
    /// </para>
    /// </summary>
    private static bool IsInRotationWindow(SecurityKeyEntity key, DateTimeOffset utcNow) =>
        key.ExpiresAt <= utcNow.AddDays(IdentityConstants.KeyRotationDays / 2.0);

    public async Task<bool> NeedsKeyRotationAsync(CancellationToken cancellationToken = default)
    {
        using var scope = _scopeFactory.CreateScope();
        var keyRepo = scope.ServiceProvider.GetRequiredService<ISecurityKeyRepository>();
        var keyEntity = await keyRepo.GetLatestKeyAsync(cancellationToken);

        if (keyEntity == null) return true;

        return IsInRotationWindow(keyEntity, DateTimeOffset.UtcNow);
    }

    public async Task RotateKeyAsync(CancellationToken cancellationToken = default)
    {
        await _initializationTcs.Task.WaitAsync(cancellationToken);
        await _refreshLock.WaitAsync(cancellationToken);
        try
        {
            using var scope = _scopeFactory.CreateScope();
            var keyRepo = scope.ServiceProvider.GetRequiredService<ISecurityKeyRepository>();
            var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();

            var existingKey = await keyRepo.GetActiveKeyAsync(cancellationToken);

            if (existingKey != null && !IsInRotationWindow(existingKey, DateTimeOffset.UtcNow))
            {
                _logger.LogDebug("Active key still has sufficient lifetime, skipping rotation");
                return;
            }

            _logger.LogInformation("Rotating RSA key pair");

            // Deactivate every IsActive row rather than only the one GetActiveKeyAsync returns:
            // that one filters on expiry and returns null once the key has expired, which would
            // leave the old row at IsActive=true forever and out of reach of
            // RemoveExpiredInactiveAsync. No SaveChanges here — this is committed together with the
            // insert of the new key below, so there is never a moment with zero active keys.
            var deactivatedCount = await keyRepo.DeactivateAllActiveAsync(cancellationToken);

            SetCurrentKey(await GenerateAndSaveKeyAsync(
                keyRepo,
                unitOfWork,
                KeyGenerationReason.Rotation,
                cancellationToken));

            // The deactivation only reaches the database in that SaveChanges above, so this log
            // line has to wait until the commit has succeeded: a failed commit must not leave behind
            // a "deactivated N key(s)" record of something that was in fact rolled back.
            if (deactivatedCount > 0)
            {
                _logger.LogInformation("Deactivated {Count} previously active key(s)", deactivatedCount);
            }

            await RefreshValidationKeysAsync(cancellationToken);
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private async Task<RsaSecurityKey> LoadOrCreateKeyAsync(
        CancellationToken cancellationToken = default)
    {
        using var scope = _scopeFactory.CreateScope();
        var keyRepo = scope.ServiceProvider.GetRequiredService<ISecurityKeyRepository>();
        var unitOfWork = scope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var keyEntity = await keyRepo.GetActiveKeyAsync(cancellationToken);

        if (keyEntity == null)
        {
            return await GenerateAndSaveKeyAsync(
                keyRepo,
                unitOfWork,
                KeyGenerationReason.Initial,
                cancellationToken);
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
        KeyGenerationReason reason,
        CancellationToken cancellationToken = default)
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

        await keyRepo.AddAsync(keyEntity, cancellationToken);
        await unitOfWork.SaveChangesAsync(cancellationToken);

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
