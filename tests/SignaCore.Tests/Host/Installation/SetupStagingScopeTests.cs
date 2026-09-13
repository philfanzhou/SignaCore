using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ServiceMantle.Installation;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host.Installation;
using Xunit;

namespace SignaCore.Tests.Host.Installation;

/// <summary>
/// The staging scope exposes the context's tracker and nothing else: discarding clears pending
/// changes without saving, is not interrupted by a canceled token, and never claims transaction
/// ownership.
/// </summary>
public sealed class SetupStagingScopeTests
{
    [Fact]
    public void HasPendingChanges_ReflectsTheChangeTracker()
    {
        using var context = CreateContext();
        var scope = new SetupStagingScope(context);

        Assert.False(scope.HasPendingChanges);

        context.Accounts.Add(new AccountEntity { Id = Guid.NewGuid(), CreatedAt = DateTimeOffset.UtcNow });

        Assert.True(scope.HasPendingChanges);
    }

    [Fact]
    public async Task DiscardPendingChangesAsync_ClearsTrackedEntities()
    {
        using var context = CreateContext();
        var scope = new SetupStagingScope(context);
        context.Accounts.Add(new AccountEntity { Id = Guid.NewGuid(), CreatedAt = DateTimeOffset.UtcNow });

        await scope.DiscardPendingChangesAsync(TestContext.Current.CancellationToken);

        Assert.False(scope.HasPendingChanges);
        Assert.Empty(context.Accounts.Local);
    }

    [Fact]
    public async Task DiscardPendingChangesAsync_IsNotInterruptedByACanceledCallerToken()
    {
        using var context = CreateContext();
        var scope = new SetupStagingScope(context);
        context.Accounts.Add(new AccountEntity { Id = Guid.NewGuid(), CreatedAt = DateTimeOffset.UtcNow });
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        // Failure cleanup must run to completion even when the caller already canceled: the
        // orchestrator relies on discarding with a token it does not want to observe here.
        await scope.DiscardPendingChangesAsync(cancellation.Token);

        Assert.False(scope.HasPendingChanges);
        Assert.Empty(context.Accounts.Local);
    }

    private static IdentityDbContext CreateContext()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        return new IdentityDbContext(
            new DbContextOptionsBuilder<IdentityDbContext>()
                .UseSqlite(connection)
                .Options);
    }
}
