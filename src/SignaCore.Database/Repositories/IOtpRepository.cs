using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IOtpRepository
{
    Task<OtpEntity?> GetAsync(
        Guid appRegistrationId,
        string phone,
        CancellationToken cancellationToken = default);
    Task AddAsync(OtpEntity otp, CancellationToken cancellationToken = default);
    Task<bool> TryConsumeAsync(
        Guid appRegistrationId,
        string phone,
        string codeMac,
        DateTimeOffset utcNow,
        int maxAttempts,
        CancellationToken cancellationToken = default);
    Task<int> IncrementFailedAttemptsAsync(
        Guid appRegistrationId,
        string phone,
        string expectedCodeMac,
        DateTimeOffset utcNow,
        int maxAttempts,
        DateTimeOffset lockoutUntil,
        CancellationToken cancellationToken = default);
    Task<int> RemoveInactiveAsync(
        DateTimeOffset createdBefore,
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default);
}
