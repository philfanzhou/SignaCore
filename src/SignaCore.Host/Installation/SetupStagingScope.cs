using ServiceMantle.Installation;
using SignaCore.Database;

namespace SignaCore.Host.Installation;

/// <summary>
/// The setup transaction's unit of work as shared orchestration sees it.
/// <para>
/// Discarding clears Entity Framework's change tracker only; it never saves, commits, or rolls
/// back, because the transaction belongs to <see cref="SetupCompletionExecutor"/>. Clearing is
/// deliberately not interrupted by a caller's cancellation token, so the orchestrator's failure
/// cleanup always runs to completion.
/// </para>
/// </summary>
internal sealed class SetupStagingScope : IServiceSetupStagingScope
{
    private readonly IdentityDbContext _db;

    public SetupStagingScope(IdentityDbContext db)
    {
        _db = db;
    }

    public bool HasPendingChanges => _db.ChangeTracker.HasChanges();

    public ValueTask DiscardPendingChangesAsync(CancellationToken cancellationToken = default)
    {
        _db.ChangeTracker.Clear();
        return ValueTask.CompletedTask;
    }
}
