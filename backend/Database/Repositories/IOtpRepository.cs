using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public interface IOtpRepository
{
    Task<OtpEntity?> GetByPhoneAsync(string phone);
    Task AddAsync(OtpEntity otp);
    Task<int> RemoveByPhoneAsync(string phone);
    Task<int> RemoveExpiredAsync(string phone, DateTimeOffset utcNow);
    Task<bool> TryConsumeAsync(
        string phone,
        string code,
        DateTimeOffset utcNow,
        int maxAttempts);
    Task<int> IncrementFailedAttemptsAsync(
        string phone,
        DateTimeOffset utcNow,
        int maxAttempts,
        DateTimeOffset lockoutUntil);
}
