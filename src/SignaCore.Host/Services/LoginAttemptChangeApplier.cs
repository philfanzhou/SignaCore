using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Validators;

namespace SignaCore.Host.Services;

internal static class LoginAttemptChangeApplier
{
    public static async Task<LoginAttemptEntity?> ApplyAsync(
        LoginAttemptChange? change,
        ILoginAttemptRepository repository,
        CancellationToken cancellationToken = default)
    {
        if (change == null)
        {
            return null;
        }

        if (change.Kind == LoginAttemptChangeKind.RecordFailure)
        {
            return await repository.RecordFailureAsync(change.Username, DateTimeOffset.UtcNow, cancellationToken);
        }

        var attempt = await repository.GetByUsernameAsync(change.Username, cancellationToken);
        if (attempt != null)
        {
            await repository.RemoveAsync(attempt, cancellationToken);
        }

        return null;
    }
}
