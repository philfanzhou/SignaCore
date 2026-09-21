extern alias BffSample;
using BffSample::SignaCore.ReferenceBff;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.ReferenceBff.Database;
using Xunit;
using SilentTerminal = SignaCore.ReferenceBff.Tests.ReferenceBffSetupCodeTests.SilentTerminal;

namespace SignaCore.ReferenceBff.Tests;

public sealed partial class ReferenceBffDatabaseContractTests
{
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task SetupCode_CreateRotateAndExpiredRotation_UseSharedLifecycle(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        var terminal = new SilentTerminal();
        Assert.Equal(0, await RunCode(database, "create", terminal));
        Assert.Equal(1, terminal.Displays);
        var first = terminal.Code!;
        await using (var read = database.CreateContext())
        {
            var row = await read.ServiceInstallations.SingleAsync(TestContext.Current.CancellationToken);
            Assert.Equal(ReferenceBffServiceMantle.ServiceIdValue, row.ServiceId);
            Assert.Equal(InstallationStatus.PendingSetup, row.Status);
            Assert.Equal(1, row.SetupCodeGeneration);
            Assert.Equal(2, row.Version);
            Assert.Equal(TimeSpan.FromMinutes(30), row.SetupCodeExpiresAtUtc - row.SetupCodeIssuedAtUtc);
            Assert.True(await ValidCode(read, first));
            Assert.Empty(await read.ManagementRoleBindings.ToListAsync(TestContext.Current.CancellationToken));
            Assert.Equal(0, await CountSharedAuditRowsAsync(read));
            Assert.False(read.Database.HasPendingModelChanges());
        }
        var snapshot = await CodeSnapshot(database);
        Assert.Equal(3, await RunCode(database, "create", new SilentTerminal()));
        Assert.True(snapshot == await CodeSnapshot(database));
        var rotated = new SilentTerminal();
        Assert.Equal(0, await RunCode(database, "rotate", rotated));
        await using (var expire = database.CreateContext())
        {
            Assert.False(await ValidCode(expire, first));
            Assert.True(await ValidCode(expire, rotated.Code!));
            var row = await expire.ServiceInstallations.SingleAsync(TestContext.Current.CancellationToken);
            row.CreatedAtUtc = DateTime.UtcNow.AddHours(-2);
            row.SetupCodeIssuedAtUtc = DateTime.UtcNow.AddHours(-1);
            row.SetupCodeExpiresAtUtc = DateTime.UtcNow.AddMinutes(-30);
            await expire.SaveChangesAsync(TestContext.Current.CancellationToken);
        }
        var recovered = new SilentTerminal();
        Assert.Equal(0, await RunCode(database, "rotate", recovered));
        await using var final = database.CreateContext();
        Assert.False(await ValidCode(final, rotated.Code!));
        Assert.True(await ValidCode(final, recovered.Code!));
        var finalRow = await final.ServiceInstallations.SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(3, finalRow.SetupCodeGeneration);
        Assert.Equal(4, finalRow.Version);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task SetupCode_RefusedStates_PreserveAllData(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        foreach (var state in new[] { "missing", "never-issued", "completed", "active", "inactive", "bad-state", "bad-digest" })
        {
            await using (var seed = database.CreateContext())
            {
                await seed.ManagementRoleBindings.ExecuteDeleteAsync(TestContext.Current.CancellationToken);
                await seed.ServiceInstallations.ExecuteDeleteAsync(TestContext.Current.CancellationToken);
                if (state != "missing")
                {
                    await new EfCoreServiceInstallationStore<ReferenceBffDbContext>(seed)
                        .CreatePendingAsync(ReferenceBffServiceMantle.ServiceId, TestContext.Current.CancellationToken);
                    if (state != "never-issued")
                    {
                        var code = await new EfCoreServiceSetupCodeStore<ReferenceBffDbContext>(seed)
                            .CreateAsync(ReferenceBffServiceMantle.ServiceId, TestContext.Current.CancellationToken);
                        if (state == "completed")
                            await new EfCoreServiceSetupCodeStore<ReferenceBffDbContext>(seed)
                                .StageConsumeAsync(ReferenceBffServiceMantle.ServiceId, code.SetupCode!.Reveal(), TestContext.Current.CancellationToken);
                        var row = await seed.ServiceInstallations.SingleAsync(TestContext.Current.CancellationToken);
                        if (state == "bad-state") row.Version = 0;
                        if (state == "bad-digest") row.SetupCodeDigest = "invalid";
                        if (state is "active" or "inactive")
                        {
                            await new ManagementRoleBindingStore(seed).StageInitialAdministratorAsync(Issuer, Subject, TestContext.Current.CancellationToken);
                            seed.ManagementRoleBindings.Local.Single().IsActive = state == "active";
                        }
                        await seed.SaveChangesAsync(TestContext.Current.CancellationToken);
                    }
                }
            }
            var before = await CodeSnapshot(database);
            foreach (var verb in state is "missing" or "never-issued" ? new[] { "rotate" } : new[] { "create", "rotate" })
            {
                var terminal = new SilentTerminal();
                Assert.Equal(3, await RunCode(database, verb, terminal));
                Assert.Equal(0, terminal.Displays);
                Assert.True(before == await CodeSnapshot(database));
            }
        }
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task SetupCode_MissingSchema_DoesNotMigrate(string provider)
    {
        await using var database = await BffDatabase.CreateAsync(provider);
        var terminal = new SilentTerminal();
        Assert.Equal(4, await RunCode(database, "create", terminal));
        Assert.Equal(0, terminal.Displays);
        await using var read = database.CreateContext();
        Assert.Empty(await read.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task SetupCode_SaveCommitCleanupAndDeliveryFailures_HaveNoPartialState(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        foreach (var boundary in new[] { "save", "commit-before", "commit-after", "dispose", "display", "cancel-before", "cancel-after" })
        {
            await using (var reset = database.CreateContext())
                await reset.ServiceInstallations.ExecuteDeleteAsync(TestContext.Current.CancellationToken);
            using var caller = new CancellationTokenSource();
            var terminal = new SilentTerminal();
            if (boundary == "display") terminal.After = () => throw new IOException("Synthetic failure.");
            var session = new ObservedSession(new SetupCodeSession(boundary == "save"
                ? database.CreateContext(new FailSecondSave()) : database.CreateContext()))
            {
                BeforeCommit = () =>
                {
                    if (boundary == "commit-before") throw new IOException("Synthetic failure.");
                    if (boundary == "cancel-before") { caller.Cancel(); caller.Token.ThrowIfCancellationRequested(); }
                },
                AfterCommit = () =>
                {
                    if (boundary == "commit-after") throw new IOException("Synthetic unknown commit outcome.");
                    if (boundary == "cancel-after") caller.Cancel();
                },
                AfterDispose = () => { if (boundary == "dispose") throw new IOException("Synthetic cleanup failure."); }
            };
            Assert.Equal(boundary.StartsWith("cancel", StringComparison.Ordinal) ? 130 : 4,
                await SetupCodeCommand.RunAsync(["--setup-code", "create"], terminal, () => session, caller.Token));
            Assert.Equal(boundary == "display" ? 1 : 0, terminal.Displays);
            await using var read = database.CreateContext();
            Assert.Equal(boundary is "save" or "commit-before" or "cancel-before" ? 0 : 1,
                await read.ServiceInstallations.CountAsync(TestContext.Current.CancellationToken));
            Assert.Empty(await read.ManagementRoleBindings.ToListAsync(TestContext.Current.CancellationToken));
            Assert.Equal(0, await CountSharedAuditRowsAsync(read));
        }
    }

    [Theory]
    [InlineData("SQLite", "create")]
    [InlineData("PostgreSQL", "create")]
    [InlineData("SQLite", "rotate")]
    [InlineData("PostgreSQL", "rotate")]
    public async Task SetupCode_OverlappingWriters_CannotOverwriteTheWinningVersion(string provider, string verb)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        if (verb == "rotate") Assert.Equal(0, await RunCode(database, "create", new SilentTerminal()));
        var gate = new SaveGate(provider == "SQLite" ? 1 : 2);
        var terminals = new[] { new SilentTerminal(), new SilentTerminal() };
        ReferenceBffDbContext Context()
        {
            var context = database.CreateContext(gate);
            if (provider == "SQLite")
            {
                var connection = context.Database.GetDbConnection();
                var settings = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(connection.ConnectionString) { DefaultTimeout = 1 };
                connection.ConnectionString = settings.ToString();
            }
            return context;
        }
        var first = Task.Run(() => SetupCodeCommand.RunAsync(["--setup-code", verb], terminals[0],
            () => new SetupCodeSession(Context()), TestContext.Current.CancellationToken));
        if (provider == "SQLite") await gate.Arrived.Task.WaitAsync(TimeSpan.FromSeconds(20), TestContext.Current.CancellationToken);
        var second = Task.Run(() => SetupCodeCommand.RunAsync(["--setup-code", verb], terminals[1],
            () => new SetupCodeSession(Context()), TestContext.Current.CancellationToken));
        try
        {
            if (provider == "SQLite") Assert.Equal(4, await second.WaitAsync(TimeSpan.FromSeconds(20), TestContext.Current.CancellationToken));
            else await gate.Arrived.Task.WaitAsync(TimeSpan.FromSeconds(20), TestContext.Current.CancellationToken);
        }
        finally { gate.Release.TrySetResult(); }
        var outcomes = await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(20), TestContext.Current.CancellationToken);
        Assert.Equal(1, outcomes.Count(value => value == 0));
        Assert.Contains(outcomes, value => value is 3 or 4);
        Assert.Equal(1, terminals.Sum(terminal => terminal.Displays));
        await using var read = database.CreateContext();
        var row = await read.ServiceInstallations.SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(verb == "create" ? 1 : 2, row.SetupCodeGeneration);
        Assert.True(await ValidCode(read, terminals.Single(terminal => terminal.Displays == 1).Code!));
    }

    private static Task<int> RunCode(BffDatabase database, string verb, SilentTerminal terminal) =>
        SetupCodeCommand.RunAsync(["--setup-code", verb], terminal,
            () => new SetupCodeSession(database.CreateContext()), TestContext.Current.CancellationToken);

    private static async Task<bool> ValidCode(ReferenceBffDbContext context, SetupCode code) =>
        (await new EfCoreServiceSetupCodeStore<ReferenceBffDbContext>(context).ValidateAsync(
            ReferenceBffServiceMantle.ServiceId, code.Reveal(), TestContext.Current.CancellationToken)).IsValid;

    // Compare snapshots only as booleans so a failing assertion cannot print a digest or identity.
    private static async Task<string> CodeSnapshot(BffDatabase database)
    {
        await using var read = database.CreateContext();
        return System.Text.Json.JsonSerializer.Serialize(new
        {
            Installation = await read.ServiceInstallations.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken),
            Roles = await read.ManagementRoleBindings.AsNoTracking().ToListAsync(TestContext.Current.CancellationToken),
            Audit = await CountSharedAuditRowsAsync(read)
        });
    }

    private sealed class FailSecondSave : SaveChangesInterceptor
    {
        private int count;
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (++count == 2) throw new IOException("Synthetic save failure.");
            return ValueTask.FromResult(result);
        }
    }

    private sealed class SaveGate(int participants) : SaveChangesInterceptor
    {
        private int count;
        public TaskCompletionSource Arrived { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref count) <= participants)
            {
                if (Volatile.Read(ref count) == participants) Arrived.TrySetResult();
                await Release.Task.WaitAsync(cancellationToken);
            }
            return result;
        }
    }

    private sealed class ObservedSession(ISetupCodeSession inner) : ISetupCodeSession
    {
        public Action? BeforeCommit { get; init; }
        public Action? AfterCommit { get; init; }
        public Action? AfterDispose { get; init; }
        public ValueTask BeginAsync(CancellationToken token) => inner.BeginAsync(token);
        public ValueTask<bool> HasBindingAsync(CancellationToken token) => inner.HasBindingAsync(token);
        public ValueTask<ServiceInstallationState?> FindAsync(CancellationToken token) => inner.FindAsync(token);
        public ValueTask InitializeAsync(CancellationToken token) => inner.InitializeAsync(token);
        public ValueTask<SetupCodeIssueResult> IssueAsync(bool rotate, CancellationToken token) => inner.IssueAsync(rotate, token);
        public async ValueTask CommitAsync(CancellationToken token) { BeforeCommit?.Invoke(); await inner.CommitAsync(token); AfterCommit?.Invoke(); }
        public async ValueTask DisposeAsync() { await inner.DisposeAsync(); AfterDispose?.Invoke(); }
    }
}
