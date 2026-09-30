using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle.Diagnostics;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using ServiceMantle.Health;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.Relational;
using SignaCore.Database;
using SignaCore.Host.Installation;
using SignaCore.Host;
using Xunit;

namespace SignaCore.Tests.Host.Management;

public sealed class InstallationHealthSnapshotSourceTests : IAsyncDisposable
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private IdentityDbContext? _context;
    private readonly ServiceProvider _metricServices = CreateMetricServices();
    private ServiceMetrics Metrics => _metricServices.GetRequiredService<ServiceMetrics>();

    private static ServiceProvider CreateMetricServices()
    {
        var services = new ServiceCollection();
        services.AddSignaCoreServiceMantle().AddServiceMantleMetrics();
        return services.BuildServiceProvider();
    }

    private void AssertPhase(string expected)
    {
        var phases = new Dictionary<string, long>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, owner) =>
        {
            if (instrument.Meter.Name == ServiceMetrics.MeterName && instrument.Name == ServiceMetrics.InstallationPhaseName)
                owner.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
        {
            foreach (var tag in tags) if (tag.Key == "phase") phases.Add((string)tag.Value!, value);
        });
        listener.Start();
        listener.RecordObservableInstruments();
        Assert.Equal(4, phases.Count);
        Assert.Equal(1, phases[expected]);
        Assert.Equal(1, phases.Values.Sum());
        Assert.All(phases.Values, value => Assert.InRange(value, 0, 1));
    }


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
    public void InitialPublisher_IsUnknown()
    {
        _ = Metrics;
        AssertPhase("unknown");
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

        var source = new InstallationHealthSnapshotSource(db, Metrics);
        var snapshot = await source.GetSnapshotAsync(TestContext.Current.CancellationToken);

        Assert.Equal(ServiceStartupPhase.Completed, snapshot.Phase);
        Assert.Equal(ServiceMigrationReadinessState.Succeeded, snapshot.MigrationStatus);
        Assert.Equal(ServiceDatabaseReadinessState.Reachable, snapshot.DatabaseStatus);
        AssertPhase("completed");
    }

    [Fact]
    public async Task MissingInstallationRow_IsNotReady()
    {
        var db = await CreateContextAsync();
        Metrics.SetPhase(ServiceStartupPhase.Completed);
        var source = new InstallationHealthSnapshotSource(db, Metrics);

        var snapshot = await source.GetSnapshotAsync(TestContext.Current.CancellationToken);

        AssertPhase("unknown");
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
        var snapshot = await new InstallationHealthSnapshotSource(db, Metrics).GetSnapshotAsync(ct);
        db.ChangeTracker.Clear();
        var resolution = await InstallationStateResolver.ResolveAsync(db, ct);

        Assert.Equal(shared, snapshot.Phase);
        AssertPhase(stateName == "completed" ? "completed" : stateName == "pending" ? "pending_setup" : "unknown");
        Assert.Equal(
            shared == ServiceStartupPhase.Completed,
            resolution.Phase == InstallationPhase.Completed);
    }

    [Fact]
    public async Task CallerCancellation_ClearsMetricsAndPreservesCancellation()
    {
        var db = await CreateContextAsync();
        Metrics.SetPhase(ServiceStartupPhase.Completed);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var source = new InstallationHealthSnapshotSource(db, Metrics);
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await source.GetSnapshotAsync(cancellation.Token));
        Assert.Equal(cancellation.Token, error.CancellationToken);
        AssertPhase("unknown");
    }

    [Fact]
    public async Task DatabaseFailure_ClearsMetricsAndPreservesTheFailure()
    {
        var db = await CreateContextAsync();
        await db.Database.ExecuteSqlRawAsync("DROP TABLE service_installations", TestContext.Current.CancellationToken);
        Metrics.SetPhase(ServiceStartupPhase.Completed);
        var source = new InstallationHealthSnapshotSource(db, Metrics);
        var error = await Assert.ThrowsAsync<ServiceInstallationStoreException>(async () => await source.GetSnapshotAsync(TestContext.Current.CancellationToken));
        Assert.IsType<SqliteException>(error.InnerException);
        AssertPhase("unknown");
    }

    public async ValueTask DisposeAsync()
    {
        if (_context is not null)
        {
            await _context.DisposeAsync();
        }

        await _connection.DisposeAsync();
        await _metricServices.DisposeAsync();
    }
}
