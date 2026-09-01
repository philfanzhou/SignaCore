using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface ILoginAttemptRepository
{
    Task<LoginAttemptEntity?> GetByUsernameAsync(
        string username,
        CancellationToken cancellationToken = default);
    Task AddAsync(LoginAttemptEntity loginAttempt, CancellationToken cancellationToken = default);
    Task<LoginAttemptEntity> RecordFailureAsync(
        string username,
        DateTimeOffset utcNow,
        CancellationToken cancellationToken = default);
    Task RemoveAsync(
        LoginAttemptEntity loginAttempt,
        CancellationToken cancellationToken = default);
    Task RemoveExpiredAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default);
}
