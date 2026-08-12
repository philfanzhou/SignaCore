using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly IdentityDbContext _dbContext;

    public RefreshTokenRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<RefreshTokenEntity?> GetByTokenValueAsync(string tokenValue)
    {
        var tokenDigest = RefreshTokenDigest.Compute(tokenValue);
        return await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(r => r.TokenValue == tokenDigest);
    }

    public Task AddAsync(RefreshTokenEntity refreshToken)
    {
        refreshToken.TokenValue = RefreshTokenDigest.EnsureDigest(refreshToken.TokenValue);
        _dbContext.RefreshTokens.Add(refreshToken);
        return Task.CompletedTask;
    }

    public async Task<bool> TryRevokeAsync(string tokenValue)
    {
        var tokenDigest = RefreshTokenDigest.Compute(tokenValue);
        var affectedRows = await _dbContext.RefreshTokens
            .Where(token => token.TokenValue == tokenDigest && !token.IsRevoked)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(token => token.IsRevoked, true));
        return affectedRows == 1;
    }

    /// <summary>
    /// 比较用精确相等而不是规范化：两侧都源自同一列 app_registrations.app_id——
    /// 签发时写的是 <c>app.AppId</c>，撤销方的身份也是网关认证解析出的同一个 <c>app.AppId</c>。
    /// 而且 <c>IdentityValueNormalizer.Normalize</c> 翻译不成 SQL，塞进这里会让整条查询落到客户端。
    /// </summary>
    public async Task<bool> TryRevokeForAppAsync(string tokenValue, string appId)
    {
        var tokenDigest = RefreshTokenDigest.Compute(tokenValue);
        var affectedRows = await _dbContext.RefreshTokens
            .Where(token => token.TokenValue == tokenDigest
                && !token.IsRevoked
                && token.AppId == appId)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(token => token.IsRevoked, true));
        return affectedRows == 1;
    }

    /// <summary>
    /// 一次性旋转 refresh token：撤销旧 token + 插入 replacement，两步同一事务，原子成败。
    /// <para>
    /// 显式事务**必须**整体跑在 <c>CreateExecutionStrategy()</c> 里。PostgreSQL / MySQL / MariaDB
    /// 都开了 <c>EnableRetryOnFailure()</c>（见 <see cref="IdentityDatabaseOptionsExtensions"/>），
    /// 重试策略拒绝在"调用方自己开的事务"里执行命令：直接 <c>BeginTransactionAsync</c> 会让第一条命令抛
    /// <c>InvalidOperationException: ... does not support user-initiated transactions</c>，
    /// 经 ExceptionHandlingMiddleware 变成 HTTP 409，刷新流程整个挂掉。SQLite 没开重试，
    /// 拿到的是 NonRetryingExecutionStrategy，lambda 只跑一次，行为不变。
    /// </para>
    /// <para>
    /// lambda 会被整体重放，所以里面的每一步都要按"可能重跑"来写，别往外提。
    /// </para>
    /// </summary>
    public async Task<bool> TryRotateAsync(string tokenValue, RefreshTokenEntity replacement)
    {
        var tokenDigest = RefreshTokenDigest.Compute(tokenValue);
        replacement.TokenValue = RefreshTokenDigest.EnsureDigest(replacement.TokenValue);
        var executionStrategy = _dbContext.Database.CreateExecutionStrategy();
        return await executionStrategy.ExecuteAsync(async () =>
        {
            await using var transaction = await _dbContext.Database.BeginTransactionAsync();

            // 并发语义靠这条条件更新 + 事务持锁：两个请求同时旋转同一个 token 时，
            // 后到的那个会阻塞在行锁上，等前一个提交后重新求值 is_revoked，命中 0 行返回 false。
            var affectedRows = await _dbContext.RefreshTokens
                .Where(token => token.TokenValue == tokenDigest && !token.IsRevoked)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(token => token.IsRevoked, true));

            if (affectedRows != 1)
            {
                // 重试路径上 replacement 可能已在上一次尝试里被 Add 过。回滚不会清 ChangeTracker，
                // 不显式脱钩的话，本次请求后续任何一次 SaveChanges 都会把这条不该存在的 token 落库。
                _dbContext.Entry(replacement).State = EntityState.Detached;
                await transaction.RollbackAsync();
                return false;
            }

            _dbContext.RefreshTokens.Add(replacement);

            // acceptAllChangesOnSuccess: false —— 提交成功前不把挂起状态标记为已保存。
            // 否则 SaveChanges 之后 replacement 就变成 Unchanged，若提交失败触发重试，
            // 重放时它不会被再次插入，留下"旧 token 已撤销、replacement 丢失"的半完成状态。
            await _dbContext.SaveChangesAsync(acceptAllChangesOnSuccess: false);
            await transaction.CommitAsync();
            _dbContext.ChangeTracker.AcceptAllChanges();
            return true;
        });
    }

    public Task RemoveRangeAsync(IEnumerable<RefreshTokenEntity> tokens)
    {
        _dbContext.RefreshTokens.RemoveRange(tokens);
        return Task.CompletedTask;
    }

    public async Task<int> RemoveExpiredAndRevokedAsync()
    {
        var now = DateTimeOffset.UtcNow;
        return await _dbContext.RefreshTokens
            .Where(r => r.IsRevoked || r.ExpiresAt < now)
            .ExecuteDeleteAsync();
    }
}
