using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Keys;
using Xunit;

namespace SignaCore.Tests.Domain.Keys;

/// <summary>
/// Timeline tests for key rotation: they drive the whole
/// <c>NeedsKeyRotationAsync</c> → <c>RotateKeyAsync</c> → <c>GetValidKeysAsync</c> chain against a
/// <b>real</b> <see cref="SecurityKeyRepository"/>.
/// <para>
/// Why they exist: KeyManagerTests are entirely Moq-based and each arranges
/// <c>GetActiveKeyAsync</c> into whatever state that test wants, which leaves the cross-method
/// contract — "when <c>NeedsKeyRotationAsync</c> says it is time to rotate, what does
/// <c>GetActiveKeyAsync</c> actually return?" — uncovered. That is exactly where the historical bug
/// was: rotation only triggered after a key had expired, while both <c>GetValidKeysAsync</c> and
/// <c>GetActiveKeyAsync</c> filter expired keys out, leaving a JWKS blackout. A bug of that shape
/// only shows up when both methods face the same real data.
/// </para>
/// </summary>
[Collection(MasterKeyStateCollection.Name)]
public sealed class KeyRotationTimelineTests : IDisposable
{
    private readonly string? _previousMasterKey;
    private readonly IdentityDbContext _dbContext;
    private readonly KeyManager _keyManager;

    public KeyRotationTimelineTests()
    {
        _previousMasterKey = Environment.GetEnvironmentVariable("RSA_MASTER_KEY");
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", "timeline_test_master_key_32bytes_min!!");

        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        _dbContext = new IdentityDbContext(options);

        var protector = new AesGcmPrivateKeyProtector(
            new BootstrapMasterKeyProvider("timeline_test_master_key_32bytes_min!!"));

        _keyManager = new KeyManager(
            CreateRealRepositoryScopeFactory(_dbContext),
            protector,
            NullLogger<KeyManager>.Instance);
    }

    /// <summary>
    /// The real <see cref="SecurityKeyRepository"/> and <see cref="EfCoreUnitOfWork"/> share one
    /// DbContext: in production they belong to the same scope, and deactivating the old keys must
    /// land in the same SaveChanges as inserting the new one.
    /// </summary>
    private static IServiceScopeFactory CreateRealRepositoryScopeFactory(IdentityDbContext dbContext)
    {
        var serviceProvider = new Mock<IServiceProvider>();
        serviceProvider
            .Setup(sp => sp.GetService(typeof(ISecurityKeyRepository)))
            .Returns(() => new SecurityKeyRepository(dbContext));
        serviceProvider
            .Setup(sp => sp.GetService(typeof(IUnitOfWork)))
            .Returns(() => new EfCoreUnitOfWork(dbContext));

        var scope = new Mock<IServiceScope>();
        scope.Setup(s => s.ServiceProvider).Returns(serviceProvider.Object);

        var scopeFactory = new Mock<IServiceScopeFactory>();
        scopeFactory.Setup(f => f.CreateScope()).Returns(scope.Object);
        return scopeFactory.Object;
    }

    /// <summary>
    /// Shifts the timeline of the stored keys back by <paramref name="days"/> days, simulating the
    /// passage of time.
    /// </summary>
    private async Task AdvanceKeyAgeAsync(int days)
    {
        var keys = await _dbContext.SecurityKeys.ToListAsync();
        foreach (var key in keys)
        {
            key.CreatedAt = key.CreatedAt.AddDays(-days);
            key.ExpiresAt = key.ExpiresAt.AddDays(-days);
        }
        await _dbContext.SaveChangesAsync();
    }

    /// <summary>
    /// The core regression: JWKS has to publish at least one public key at <b>every</b> moment of a
    /// key's lifetime, including between two CleanupWorker ticks. Downstream microservices fetch
    /// whenever they like; they do not wait for Identity to finish its cleanup.
    /// <para>
    /// The assertion <b>before</b> the tick is the one that matters: the rotation check and the
    /// rotation itself happen within the same tick, so checking JWKS only after the tick would never
    /// observe the blackout. The old implementation (rotate only once <c>ExpiresAt &lt; now</c>)
    /// fails at the pre-tick assertion on day 30 — the key has expired, the new one does not exist
    /// yet, and JWKS returns an empty array.
    /// </para>
    /// </summary>
    [Fact]
    public async Task Jwks_NeverReturnsEmpty_BetweenCleanupTicks()
    {
        await _keyManager.InitializationCompleted;

        var rotationCount = 0;
        var lastKeyId = _keyManager.GetCurrentKey().KeyId;

        // 45 days reaches the third rotation, so this covers the steady state rather than only the
        // first round.
        for (var day = 1; day <= 45; day++)
        {
            await AdvanceKeyAgeAsync(1);

            Assert.True(
                (await _keyManager.GetValidKeysAsync()).Count > 0,
                $"第 {day} 天、CleanupWorker tick 之前 JWKS 为空——下游此刻拉到零个公钥");

            // CleanupWorker ticks once every 24h.
            if (await _keyManager.NeedsKeyRotationAsync())
            {
                await _keyManager.RotateKeyAsync();
            }

            Assert.True(
                (await _keyManager.GetValidKeysAsync()).Count > 0,
                $"第 {day} 天、CleanupWorker tick 之后 JWKS 为空");

            var currentKeyId = _keyManager.GetCurrentKey().KeyId;
            if (currentKeyId != lastKeyId)
            {
                rotationCount++;
                lastKeyId = currentKeyId;
            }
        }

        // The upper bound is a regression point too: an implementation that rotated on every tick
        // would also keep JWKS non-empty throughout, but it would replace the key daily — the table
        // grows without bound and the intended 15-day overlap between old and new keys is lost.
        // A 30-day lifetime with half-life rotation means one rotation every 15 days, so 3 are
        // expected within 45 days.
        Assert.InRange(rotationCount, 2, 4);
    }

    /// <summary>
    /// Rotation has to happen before expiry, with an overlap between the old and new keys, so that
    /// the old public key a downstream microservice has cached stays valid until the tokens signed
    /// with it have expired.
    /// </summary>
    [Fact]
    public async Task Rotation_HappensBeforeExpiry_AndOldKeyStaysPublished()
    {
        await _keyManager.InitializationCompleted;
        var originalKeyId = _keyManager.GetCurrentKey().KeyId;

        // Day 16: past the half-life of 15 days, but still 14 days from expiry.
        await AdvanceKeyAgeAsync(16);

        Assert.True(
            await _keyManager.NeedsKeyRotationAsync(),
            "过半衰期就该轮换，不能等到过期");

        await _keyManager.RotateKeyAsync();

        var rotatedKeyId = _keyManager.GetCurrentKey().KeyId;
        Assert.NotEqual(originalKeyId, rotatedKeyId);

        // Both keys coexist: the old key is deactivated but not yet expired, so it still has to
        // appear in JWKS.
        var jwksKeyIds = (await _keyManager.GetValidKeysAsync()).Select(k => k.KeyId).ToList();
        Assert.Contains(rotatedKeyId, jwksKeyIds);
        Assert.Contains(originalKeyId, jwksKeyIds);
    }

    /// <summary>
    /// After a rotation the database holds exactly one <c>IsActive=true</c> row. In the old
    /// implementation <c>GetActiveKeyAsync</c> returned null once the key had expired, deactivation
    /// was skipped, and the old row stayed at IsActive=true forever.
    /// </summary>
    [Fact]
    public async Task AfterRotation_ExactlyOneActiveKeyRemains()
    {
        await _keyManager.InitializationCompleted;

        // Two rotations in a row, to confirm no zombie rows accumulate.
        for (var round = 0; round < 2; round++)
        {
            await AdvanceKeyAgeAsync(16);
            await _keyManager.RotateKeyAsync();

            var activeKeys = await _dbContext.SecurityKeys
                .Where(k => k.IsActive)
                .ToListAsync(cancellationToken: TestContext.Current.CancellationToken);

            Assert.Single(activeKeys);
            Assert.Equal(_keyManager.GetCurrentKey().KeyId, activeKeys[0].KeyId);
        }
    }

    /// <summary>
    /// Even when rotation only happens after the key has expired (for instance after the service was
    /// down for several days), the leftover IsActive row still has to be deactivated; otherwise
    /// <c>RemoveExpiredInactiveAsync</c>, which only deletes !IsActive rows, could never clean it
    /// up.
    /// </summary>
    [Fact]
    public async Task RotationAfterExpiry_LeavesNoStaleActiveRow()
    {
        await _keyManager.InitializationCompleted;

        await AdvanceKeyAgeAsync(35);   // Expired 5 days ago.

        Assert.Null(await new SecurityKeyRepository(_dbContext).GetActiveKeyAsync());

        await _keyManager.RotateKeyAsync();

        var staleRows = await _dbContext.SecurityKeys
            .Where(k => k.IsActive && k.ExpiresAt < DateTimeOffset.UtcNow)
            .ToListAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Empty(staleRows);
    }

    /// <summary>
    /// A rotation deliberately does <b>not</b> dispose the previous validation key snapshot:
    /// concurrent requests may still hold a reference handed out by <c>GetValidationKeys</c>, and
    /// disposing it would make validation throw <see cref="ObjectDisposedException"/> mid-flight.
    /// <para>
    /// Real concurrency is not needed here — "take a reference, rotate, the reference still works"
    /// covers the decision.
    /// </para>
    /// </summary>
    [Fact]
    public async Task ValidationKeys_PreviousSnapshotStaysUsableAfterRotation()
    {
        await _keyManager.InitializationCompleted;

        // Simulates a request already in flight: it takes the reference first, and the rotation
        // happens afterwards.
        var heldByInFlightRequest = _keyManager.GetValidationKeys();
        Assert.NotEmpty(heldByInFlightRequest);

        await AdvanceKeyAgeAsync(16);
        await _keyManager.RotateKeyAsync();

        foreach (var key in heldByInFlightRequest.Cast<RsaSecurityKey>())
        {
            // Not throwing ObjectDisposedException is what passing means here.
            var parameters = key.Rsa!.ExportParameters(includePrivateParameters: false);
            Assert.NotNull(parameters.Modulus);
        }
    }

    /// <summary>
    /// The validation key snapshot has to catch up immediately after a rotation and contain both the
    /// old and the new key; it must not wait for the next restart.
    /// </summary>
    [Fact]
    public async Task ValidationKeys_RefreshImmediatelyAfterRotation()
    {
        await _keyManager.InitializationCompleted;
        var originalKeyId = _keyManager.GetCurrentKey().KeyId;

        await AdvanceKeyAgeAsync(16);
        await _keyManager.RotateKeyAsync();

        var validationKeyIds = _keyManager.GetValidationKeys().Select(k => k.KeyId).ToList();

        Assert.Contains(_keyManager.GetCurrentKey().KeyId, validationKeyIds);
        Assert.Contains(originalKeyId, validationKeyIds);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
        Environment.SetEnvironmentVariable("RSA_MASTER_KEY", _previousMasterKey);
    }
}
