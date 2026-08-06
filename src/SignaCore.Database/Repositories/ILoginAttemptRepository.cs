using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface ILoginAttemptRepository
{
    Task<LoginAttemptEntity?> GetByUsernameAsync(string username);
    Task AddAsync(LoginAttemptEntity loginAttempt);
    Task<LoginAttemptEntity> RecordFailureAsync(string username, DateTimeOffset utcNow);
    Task RemoveAsync(LoginAttemptEntity loginAttempt);
    Task RemoveExpiredAsync(DateTimeOffset cutoff);
}
