using Microsoft.EntityFrameworkCore;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public class OtpRepository : IOtpRepository
{
    private readonly IdentityDbContext _dbContext;

    public OtpRepository(IdentityDbContext dbContext) => _dbContext = dbContext;

    public Task<OtpEntity?> GetAsync(
        Guid appRegistrationId,
        string phone,
        CancellationToken cancellationToken = default) =>
        _dbContext.Otps.FirstOrDefaultAsync(otp =>
            otp.AppRegistrationId == appRegistrationId && otp.Phone == phone,
            cancellationToken);

    public Task AddAsync(OtpEntity otp, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.Otps.Add(otp);
        return Task.CompletedTask;
    }

    public async Task<bool> TryConsumeAsync(
        Guid appRegistrationId,
        string phone,
        string codeMac,
        DateTimeOffset utcNow,
        int maxAttempts,
        CancellationToken cancellationToken = default)
    {
        var affectedRows = await _dbContext.Otps
            .Where(otp => otp.AppRegistrationId == appRegistrationId && otp.Phone == phone &&
                otp.CodeMac == codeMac && otp.Status == OtpStatus.Sent &&
                otp.ExpiresAt >= utcNow && otp.LockoutUntil <= utcNow && otp.Attempts < maxAttempts)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(otp => otp.Status, OtpStatus.Consumed),
                cancellationToken);
        return affectedRows == 1;
    }

    public Task<int> IncrementFailedAttemptsAsync(
        Guid appRegistrationId,
        string phone,
        string expectedCodeMac,
        DateTimeOffset utcNow,
        int maxAttempts,
        DateTimeOffset lockoutUntil,
        CancellationToken cancellationToken = default) =>
        _dbContext.Otps
            .Where(otp => otp.AppRegistrationId == appRegistrationId && otp.Phone == phone &&
                otp.CodeMac == expectedCodeMac && otp.Status == OtpStatus.Sent && otp.ExpiresAt >= utcNow &&
                otp.LockoutUntil <= utcNow && otp.Attempts < maxAttempts)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(otp => otp.Attempts, otp => otp.Attempts + 1)
                .SetProperty(otp => otp.LockoutUntil,
                    otp => otp.Attempts + 1 >= maxAttempts ? lockoutUntil : otp.LockoutUntil),
                cancellationToken);

    public Task<int> RemoveInactiveAsync(
        DateTimeOffset createdBefore,
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default) =>
        _dbContext.Otps
            .Where(otp => otp.CreatedAt < createdBefore && otp.LockoutUntil <= utcNow)
            .ExecuteDeleteAsync(cancellationToken);
}
