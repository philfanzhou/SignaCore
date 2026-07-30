using Microsoft.EntityFrameworkCore;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly IdentityDbContext _dbContext;

    public RefreshTokenRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<RefreshTokenEntity?> GetByTokenValueAsync(string tokenValue)
    {
        return await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(r => r.TokenValue == tokenValue);
    }

    public Task AddAsync(RefreshTokenEntity refreshToken)
    {
        _dbContext.RefreshTokens.Add(refreshToken);
        return Task.CompletedTask;
    }

    public async Task<bool> TryRevokeAsync(string tokenValue)
    {
        var affectedRows = await _dbContext.RefreshTokens
            .Where(token => token.TokenValue == tokenValue && !token.IsRevoked)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(token => token.IsRevoked, true));
        return affectedRows == 1;
    }

    public async Task<bool> TryRotateAsync(string tokenValue, RefreshTokenEntity replacement)
    {
        await using var transaction = await _dbContext.Database.BeginTransactionAsync();
        var affectedRows = await _dbContext.RefreshTokens
            .Where(token => token.TokenValue == tokenValue && !token.IsRevoked)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(token => token.IsRevoked, true));

        if (affectedRows != 1)
        {
            return false;
        }

        _dbContext.RefreshTokens.Add(replacement);
        await _dbContext.SaveChangesAsync();
        await transaction.CommitAsync();
        return true;
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
