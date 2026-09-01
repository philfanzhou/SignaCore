using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public class LoginAttemptRepository : ILoginAttemptRepository
{
    private readonly IdentityDbContext _dbContext;

    public LoginAttemptRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<LoginAttemptEntity?> GetByUsernameAsync(
        string username,
        CancellationToken cancellationToken = default)
    {
        var normalizedUsername = IdentityValueNormalizer.Normalize(username);
        return await _dbContext.LoginAttempts
            .FirstOrDefaultAsync(
                l => l.UsernameNormalized == normalizedUsername,
                cancellationToken);
    }

    public Task AddAsync(
        LoginAttemptEntity loginAttempt,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.LoginAttempts.Add(loginAttempt);
        return Task.CompletedTask;
    }

    public async Task<LoginAttemptEntity> RecordFailureAsync(
        string username,
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default)
    {
        var normalizedUsername = IdentityValueNormalizer.Normalize(username);
        var lockoutUntil = utcNow.AddMinutes(IdentityConstants.LoginLockoutMinutes);

        var affectedRows = await IncrementExistingAsync(
            normalizedUsername,
            utcNow,
            lockoutUntil,
            cancellationToken);
        if (affectedRows == 0)
        {
            var loginAttempt = new LoginAttemptEntity
            {
                Id = Guid.NewGuid(),
                Username = username,
                UsernameNormalized = normalizedUsername,
                LastAttemptAt = utcNow,
                FailedAttempts = 1
            };
            _dbContext.LoginAttempts.Add(loginAttempt);

            try
            {
                await _dbContext.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException)
            {
                _dbContext.Entry(loginAttempt).State = EntityState.Detached;
                affectedRows = await IncrementExistingAsync(
                    normalizedUsername,
                    utcNow,
                    lockoutUntil,
                    cancellationToken);
                if (affectedRows == 0)
                {
                    throw;
                }
            }
        }

        return await _dbContext.LoginAttempts
            .AsNoTracking()
            .SingleAsync(
                attempt => attempt.UsernameNormalized == normalizedUsername,
                cancellationToken);
    }

    public Task RemoveAsync(
        LoginAttemptEntity loginAttempt,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.LoginAttempts.Remove(loginAttempt);
        return Task.CompletedTask;
    }

    public async Task RemoveExpiredAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default)
    {
        await _dbContext.LoginAttempts
            .Where(l => l.LastAttemptAt < cutoff)
            .ExecuteDeleteAsync(cancellationToken);
    }

    private async Task<int> IncrementExistingAsync(
        string normalizedUsername,
        DateTimeOffset utcNow,
        DateTimeOffset lockoutUntil,
        CancellationToken cancellationToken)
    {
        return await _dbContext.LoginAttempts
            .Where(attempt => attempt.UsernameNormalized == normalizedUsername)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(attempt => attempt.LastAttemptAt, utcNow)
                .SetProperty(
                    attempt => attempt.FailedAttempts,
                    attempt => attempt.FailedAttempts + 1)
                .SetProperty(
                    attempt => attempt.LockoutUntil,
                    attempt =>
                        attempt.FailedAttempts + 1 >=
                            IdentityConstants.MaxFailedLoginAttempts
                        ? lockoutUntil
                        : attempt.LockoutUntil),
                cancellationToken);
    }
}
