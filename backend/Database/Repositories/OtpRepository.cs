using Microsoft.EntityFrameworkCore;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public class OtpRepository : IOtpRepository
{
    private readonly IdentityDbContext _dbContext;

    public OtpRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<OtpEntity?> GetByPhoneAsync(string phone)
    {
        return await _dbContext.Otps.FirstOrDefaultAsync(o => o.Phone == phone);
    }

    public Task AddAsync(OtpEntity otp)
    {
        _dbContext.Otps.Add(otp);
        return Task.CompletedTask;
    }

    public async Task<int> RemoveByPhoneAsync(string phone)
    {
        return await _dbContext.Otps
            .Where(otp => otp.Phone == phone)
            .ExecuteDeleteAsync();
    }

    public async Task<int> RemoveExpiredAsync(string phone, DateTimeOffset utcNow)
    {
        return await _dbContext.Otps
            .Where(otp => otp.Phone == phone && otp.ExpiresAt < utcNow)
            .ExecuteDeleteAsync();
    }

    public async Task<bool> TryConsumeAsync(
        string phone,
        string code,
        DateTimeOffset utcNow,
        int maxAttempts)
    {
        var affectedRows = await _dbContext.Otps
            .Where(otp =>
                otp.Phone == phone &&
                otp.Code == code &&
                otp.ExpiresAt >= utcNow &&
                otp.LockoutUntil <= utcNow &&
                otp.Attempts < maxAttempts)
            .ExecuteDeleteAsync();
        return affectedRows == 1;
    }

    public async Task<int> IncrementFailedAttemptsAsync(
        string phone,
        DateTimeOffset utcNow,
        int maxAttempts,
        DateTimeOffset lockoutUntil)
    {
        return await _dbContext.Otps
            .Where(otp =>
                otp.Phone == phone &&
                otp.ExpiresAt >= utcNow &&
                otp.LockoutUntil <= utcNow &&
                otp.Attempts < maxAttempts)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(otp => otp.Attempts, otp => otp.Attempts + 1)
                .SetProperty(
                    otp => otp.LockoutUntil,
                    otp => otp.Attempts + 1 >= maxAttempts
                        ? lockoutUntil
                        : otp.LockoutUntil));
    }
}
