using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public interface ILoginAttemptRepository
{
    Task<LoginAttemptEntity?> GetByUsernameAsync(string username);
    Task AddAsync(LoginAttemptEntity loginAttempt);
    Task<LoginAttemptEntity> RecordFailureAsync(string username, DateTimeOffset utcNow);
    Task RemoveAsync(LoginAttemptEntity loginAttempt);
    Task RemoveExpiredAsync(DateTimeOffset cutoff);
}
