using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IOtpRepository
{
    Task<OtpEntity?> GetAsync(Guid appRegistrationId, string phone);
    Task AddAsync(OtpEntity otp);
    Task<bool> TryConsumeAsync(Guid appRegistrationId, string phone, string codeMac, DateTimeOffset utcNow, int maxAttempts);
    Task<int> IncrementFailedAttemptsAsync(
        Guid appRegistrationId,
        string phone,
        string expectedCodeMac,
        DateTimeOffset utcNow,
        int maxAttempts,
        DateTimeOffset lockoutUntil);
    Task<int> RemoveInactiveAsync(DateTimeOffset createdBefore, DateTimeOffset utcNow);
}
