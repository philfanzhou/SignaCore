using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ServiceMantle.Health;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Host.Installation;
using Xunit;

namespace SignaCore.Tests.Host.Management;

public sealed class InstallationHealthSnapshotSourceTests : IAsyncDisposable
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private IdentityDbContext? _context;

    private async Task<IdentityDbContext> CreateContextAsync()
    {
        if (_context is not null)
        {
            return _context;
        }

        await _connection.OpenAsync(TestContext.Current.CancellationToken);
        _context = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(_connection).Options);
        await _context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        return _context;
    }

    [Fact]
    public async Task CompletedInstallation_AdmitsTheManagementSession()
    {
        var db = await CreateContextAsync();
        var installationStore = InstallationStores.CreateInstallationStore(db);
        var setupCodeStore = InstallationStores.CreateSetupCodeStore(db);
        await installationStore.CreatePendingAsync(InstallationStores.ServiceId, TestContext.Current.CancellationToken);
        var issued = await setupCodeStore.CreateAsync(
            InstallationStores.ServiceId, TestContext.Current.CancellationToken);
        Assert.True(issued.IsIssued);
        var consumption = await setupCodeStore.StageConsumeAsync(
            InstallationStores.ServiceId,
            issued.SetupCode!.Reveal(),
            TestContext.Current.CancellationToken);
        Assert.True(consumption.IsStaged);
        await db.SaveChangesAsync(TestContext.Current.CancellationToken);

        var source = new InstallationHealthSnapshotSource(db);
        var snapshot = await source.GetSnapshotAsync(TestContext.Current.CancellationToken);

        Assert.Equal(ServiceStartupPhase.Completed, snapshot.Phase);
        Assert.Equal(ServiceMigrationReadinessState.Succeeded, snapshot.MigrationStatus);
        Assert.Equal(ServiceDatabaseReadinessState.Reachable, snapshot.DatabaseStatus);
    }

    [Fact]
    public async Task MissingInstallationRow_IsNotReady()
    {
        var db = await CreateContextAsync();
        var source = new InstallationHealthSnapshotSource(db);

        var snapshot = await source.GetSnapshotAsync(TestContext.Current.CancellationToken);

        Assert.NotEqual(ServiceStartupPhase.Completed, snapshot.Phase);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("pending")]
    [InlineData("completed")]
    public async Task PreHostResolutionAndPhaseGate_AgreeOnCompletion(string stateName)
    {
        var ct = TestContext.Current.CancellationToken;
        var db = await CreateContextAsync();
        var installationStore = InstallationStores.CreateInstallationStore(db);
        if (stateName != "missing")
        {
            await installationStore.CreatePendingAsync(InstallationStores.ServiceId, ct);
            var setupCodeStore = InstallationStores.CreateSetupCodeStore(db);
            var issued = await setupCodeStore.CreateAsync(InstallationStores.ServiceId, ct);
            if (stateName == "completed")
            {
                Assert.True((await setupCodeStore.StageConsumeAsync(
                    InstallationStores.ServiceId, issued.SetupCode!.Reveal(), ct)).IsStaged);
                await db.SaveChangesAsync(ct);
            }
        }

        var state = await installationStore.FindAsync(InstallationStores.ServiceId, ct);
        var shared = SharedInstallationPhase.Resolve(state);
        var snapshot = await new InstallationHealthSnapshotSource(db).GetSnapshotAsync(ct);
        db.ChangeTracker.Clear();
        var resolution = await InstallationStateResolver.ResolveAsync(db, ct);

        Assert.Equal(shared, snapshot.Phase);
        Assert.Equal(
            shared == ServiceStartupPhase.Completed,
            resolution.Phase == InstallationPhase.Completed);
    }

    public async ValueTask DisposeAsync()
    {
        if (_context is not null)
        {
            await _context.DisposeAsync();
        }

        await _connection.DisposeAsync();
    }
}
