namespace SignaCore.Domain.Services;

/// <summary>
/// The expiry cleanup of management bearer sessions, run by <see cref="CleanupWorker"/> and never
/// on a request path. The host's lifecycle service implements it on its own unit of work.
/// </summary>
public interface IManagementBearerSessionCleanup
{
    /// <summary>
    /// Deletes at most one bounded batch of sessions that expired at least the retention period
    /// before <paramref name="now"/>, and returns the number of deleted rows.
    /// </summary>
    Task<int> CleanupExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken);
}
