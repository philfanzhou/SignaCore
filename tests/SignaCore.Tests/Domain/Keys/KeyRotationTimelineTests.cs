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
/// 密钥轮换的时间线测试：用**真实**的 <see cref="SecurityKeyRepository"/> 跑通
/// <c>NeedsKeyRotationAsync</c> → <c>RotateKeyAsync</c> → <c>GetValidKeysAsync</c> 全链路。
/// <para>
/// 存在的理由：KeyManagerTests 全部用 Moq，各自把 <c>GetActiveKeyAsync</c> 摆成测试想要的状态，
/// 于是"<c>NeedsKeyRotationAsync</c> 说该轮换时，<c>GetActiveKeyAsync</c> 实际会返回什么"这个
/// 跨方法的契约无人覆盖——历史上正是这里出的问题：轮换只在密钥过期后触发，而
/// <c>GetValidKeysAsync</c>/<c>GetActiveKeyAsync</c> 都过滤掉了过期密钥，导致 JWKS 空窗。
/// 这类 bug 只有让两个方法面对同一份真实数据才暴露得出来。
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
    /// 真实的 <see cref="SecurityKeyRepository"/> 与 <see cref="EfCoreUnitOfWork"/> 共享同一个
    /// DbContext——生产里二者同属一个 scope，停用旧密钥与插入新密钥必须落进同一次 SaveChanges。
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

    /// <summary>把当前活跃密钥的时间轴整体往前推 <paramref name="days"/> 天，模拟时间流逝。</summary>
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
    /// 核心回归：JWKS 在密钥寿命的**任何**时刻都必须至少发布一把公钥——包括两次
    /// CleanupWorker tick 之间。下游微服务是随时来拉的，不会等 Identity 做完清理。
    /// <para>
    /// 关键在 tick **之前**那次断言：轮换检查与轮换动作发生在同一次 tick 里，如果只在
    /// tick 之后查 JWKS，永远观察不到空窗。旧实现（<c>ExpiresAt &lt; now</c> 才轮换）会在
    /// 第 30 天的 tick 前断言处失败——密钥已过期、新密钥尚未生成，JWKS 返回空数组。
    /// </para>
    /// </summary>
    [Fact]
    public async Task Jwks_NeverReturnsEmpty_BetweenCleanupTicks()
    {
        await _keyManager.InitializationCompleted;

        var rotationCount = 0;
        var lastKeyId = _keyManager.GetCurrentKey().KeyId;

        // 45 天覆盖到第三次轮换，确认稳态而不只是第一轮
        for (var day = 1; day <= 45; day++)
        {
            await AdvanceKeyAgeAsync(1);

            Assert.True(
                (await _keyManager.GetValidKeysAsync()).Count > 0,
                $"第 {day} 天、CleanupWorker tick 之前 JWKS 为空——下游此刻拉到零个公钥");

            // CleanupWorker 每 24h tick 一次
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

        // 上界同样是回归点：一个「每次 tick 都轮换」的实现照样能让 JWKS 全程非空，
        // 但会每天换一次密钥——表膨胀，且 15 天新旧重叠期的设计意图丢失。
        // 30 天寿命 + 半衰期轮换 = 每 15 天一次，45 天内期望 3 次。
        Assert.InRange(rotationCount, 2, 4);
    }

    /// <summary>
    /// 轮换必须在过期前发生，且新旧密钥有重叠期：下游微服务缓存的旧公钥在其 token 过期前始终有效。
    /// </summary>
    [Fact]
    public async Task Rotation_HappensBeforeExpiry_AndOldKeyStaysPublished()
    {
        await _keyManager.InitializationCompleted;
        var originalKeyId = _keyManager.GetCurrentKey().KeyId;

        // 第 16 天：已过半衰期（15 天），但离过期还有 14 天
        await AdvanceKeyAgeAsync(16);

        Assert.True(
            await _keyManager.NeedsKeyRotationAsync(),
            "过半衰期就该轮换，不能等到过期");

        await _keyManager.RotateKeyAsync();

        var rotatedKeyId = _keyManager.GetCurrentKey().KeyId;
        Assert.NotEqual(originalKeyId, rotatedKeyId);

        // 新旧并存：旧密钥虽已停用但尚未过期，仍需出现在 JWKS 里
        var jwksKeyIds = (await _keyManager.GetValidKeysAsync()).Select(k => k.KeyId).ToList();
        Assert.Contains(rotatedKeyId, jwksKeyIds);
        Assert.Contains(originalKeyId, jwksKeyIds);
    }

    /// <summary>
    /// 轮换后库里有且只有一条 <c>IsActive=true</c>。旧实现在密钥已过期时
    /// <c>GetActiveKeyAsync</c> 返回 null，跳过停用，旧行永久残留在 IsActive=true。
    /// </summary>
    [Fact]
    public async Task AfterRotation_ExactlyOneActiveKeyRemains()
    {
        await _keyManager.InitializationCompleted;

        // 连续两轮换，确认没有累积僵尸行
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
    /// 即使密钥已经过期才轮换（例如服务停机数日后重启），残留的 IsActive 行也要被停用，
    /// 否则 <c>RemoveExpiredInactiveAsync</c>（只删 !IsActive）永远清不掉它。
    /// </summary>
    [Fact]
    public async Task RotationAfterExpiry_LeavesNoStaleActiveRow()
    {
        await _keyManager.InitializationCompleted;

        await AdvanceKeyAgeAsync(35);   // 已过期 5 天

        Assert.Null(await new SecurityKeyRepository(_dbContext).GetActiveKeyAsync());

        await _keyManager.RotateKeyAsync();

        var staleRows = await _dbContext.SecurityKeys
            .Where(k => k.IsActive && k.ExpiresAt < DateTimeOffset.UtcNow)
            .ToListAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Empty(staleRows);
    }

    /// <summary>
    /// 轮换时刻意**不**释放上一份校验密钥快照：并发请求可能正持有 <c>GetValidationKeys</c>
    /// 返回的引用，释放会让验签中途抛 <see cref="ObjectDisposedException"/>。
    /// <para>
    /// 不需要真起并发——"拿到引用 → 轮换 → 引用仍可用"就足以覆盖这个决策。
    /// </para>
    /// </summary>
    [Fact]
    public async Task ValidationKeys_PreviousSnapshotStaysUsableAfterRotation()
    {
        await _keyManager.InitializationCompleted;

        // 模拟一个正在处理中的请求：先拿到引用，之后才发生轮换
        var heldByInFlightRequest = _keyManager.GetValidationKeys();
        Assert.NotEmpty(heldByInFlightRequest);

        await AdvanceKeyAgeAsync(16);
        await _keyManager.RotateKeyAsync();

        foreach (var key in heldByInFlightRequest.Cast<RsaSecurityKey>())
        {
            // 不抛 ObjectDisposedException 即为通过
            var parameters = key.Rsa!.ExportParameters(includePrivateParameters: false);
            Assert.NotNull(parameters.Modulus);
        }
    }

    /// <summary>轮换后校验密钥快照要立刻跟上，包含新旧两把——不能等下次重启。</summary>
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
