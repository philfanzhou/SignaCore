extern alias BffSample;
using BffSample::SignaCore.ReferenceBff;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle.AspNetCore.ManagementApi.Setup;
using ServiceMantle.Installation;
using SignaCore.ReferenceBff.Database;
using Xunit;
using SilentTerminal = SignaCore.ReferenceBff.Tests.ReferenceBffSetupCodeTests.SilentTerminal;

namespace SignaCore.ReferenceBff.Tests;

public sealed partial class ReferenceBffDatabaseContractTests
{
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task SetupTransactions_EveryCompletedBoundaryObservesCallerAndDiscardsScope(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        await using var services = SetupServices(database);
        foreach (var boundary in new[] { "begin", "find", "validate", "identity", "stage", "consume", "save", "commit", "dispose" })
        foreach (var cancel in new[] { false, true })
        foreach (var outcome in new[] { "return", "throw", "internal-cancel" })
        {
            if (!cancel && outcome == "return") continue;
            await ClearSetup(database);
            var terminal = new SilentTerminal();
            Assert.Equal(0, await RunCode(database, "create", terminal));
            using var caller = new CancellationTokenSource();
            var fault = new SetupBoundaryFault(boundary, outcome, cancel, caller);
            var session = new ObservedSetupSession(new BffSetupSession(services.CreateAsyncScope()), fault);
            var operation = BffSetupExecutor.RunAsync(terminal.Code!, () => session,
                () => { fault.Complete("identity"); return ValueTask.FromResult(ConfirmedSetupIdentity()); },
                () => throw new InvalidOperationException("A confirmed identity must never be signed out."), caller.Token).AsTask();
            if (cancel)
            {
                var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);
                Assert.Equal(caller.Token, exception.CancellationToken);
            }
            else Assert.Equal(SetupCompletionStatus.Unavailable, (await operation).Status);
            Assert.True(fault.Observed);
            Assert.Equal(1, session.Disposals);
            Assert.InRange(session.Saves, 0, 1);
            await using var read = database.CreateContext();
            var committed = boundary is "commit" or "dispose";
            Assert.Equal(committed ? 1 : 0, await read.ManagementRoleBindings.CountAsync(TestContext.Current.CancellationToken));
            Assert.Equal(committed ? 1 : 0, await CountSharedAuditRowsAsync(read));
            Assert.Equal(committed ? InstallationStatus.Completed : InstallationStatus.PendingSetup,
                (await read.ServiceInstallations.SingleAsync(TestContext.Current.CancellationToken)).Status);
        }
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task SetupTransactions_InsertFailuresAndLateCodeRejectionRollbackAllStaging(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        var clock = new SetupClock();
        await using var services = SetupServices(database, clock);
        foreach (var failure in new[] { "management_role_bindings", "service_audit_logs", "expired", "rotated", "active", "inactive" })
        {
            clock.Offset = TimeSpan.Zero;
            await ClearSetup(database);
            var terminal = new SilentTerminal();
            Assert.Equal(0, await RunCode(database, "create", terminal));
            await using (var setup = database.CreateContext())
            {
                if (failure is "active" or "inactive")
                {
                    await new ManagementRoleBindingStore(setup).StageInitialAdministratorAsync(Issuer, Subject, TestContext.Current.CancellationToken);
                    setup.ManagementRoleBindings.Local.Single().IsActive = failure == "active";
                    await setup.SaveChangesAsync(TestContext.Current.CancellationToken);
                }
                if (failure is "management_role_bindings" or "service_audit_logs")
                {
                    var sql = provider == "SQLite"
                        ? $"CREATE TRIGGER setup_fail BEFORE INSERT ON {failure} BEGIN SELECT RAISE(ABORT, 'Synthetic insertion failure'); END"
                        : $"CREATE OR REPLACE FUNCTION setup_fail_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Synthetic insertion failure'; END $$; CREATE TRIGGER setup_fail BEFORE INSERT ON {failure} FOR EACH ROW EXECUTE FUNCTION setup_fail_fn()";
                    await setup.Database.ExecuteSqlRawAsync(sql, TestContext.Current.CancellationToken);
                }
            }
            var session = new LateCodeSetupSession(new BffSetupSession(services.CreateAsyncScope()), failure, clock);
            var result = await BffSetupExecutor.RunAsync(terminal.Code!, () => session,
                () => ValueTask.FromResult(ConfirmedSetupIdentity()), () => ValueTask.CompletedTask, TestContext.Current.CancellationToken);
            Assert.Equal(failure is "active" or "inactive" ? SetupCompletionStatus.Conflict :
                failure is "expired" or "rotated" ? SetupCompletionStatus.CredentialInvalid : SetupCompletionStatus.Unavailable, result.Status);
            await using var read = database.CreateContext();
            Assert.Equal(failure is "active" or "inactive" ? 1 : 0, await read.ManagementRoleBindings.CountAsync(TestContext.Current.CancellationToken));
            Assert.Equal(0, await CountSharedAuditRowsAsync(read));
            Assert.True(await ValidCode(read, terminal.Code!));
            if (failure is "management_role_bindings" or "service_audit_logs")
                await read.Database.ExecuteSqlRawAsync(provider == "SQLite" ? "DROP TRIGGER setup_fail" : $"DROP TRIGGER setup_fail ON {failure}", TestContext.Current.CancellationToken);
        }
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task SetupTransactions_OverlappingWritersHaveAtMostOneBindingAndAudit(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        await using var services = SetupServices(database);
        var terminal = new SilentTerminal();
        Assert.Equal(0, await RunCode(database, "create", terminal));
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        async ValueTask<BffIdentityCheckResult> Hold()
        {
            entered.TrySetResult();
            await release.Task;
            return ConfirmedSetupIdentity();
        }
        var first = Task.Run(async () => await BffSetupExecutor.RunAsync(terminal.Code!,
            () => new BffSetupSession(services.CreateAsyncScope()), Hold, () => ValueTask.CompletedTask, TestContext.Current.CancellationToken));
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        var attempted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var second = Task.Run(async () => await BffSetupExecutor.RunAsync(terminal.Code!,
            () => { attempted.TrySetResult(); return new BffSetupSession(services.CreateAsyncScope()); },
            () => ValueTask.FromResult(ConfirmedSetupIdentity() with { VerifiedSubject = "second-subject" }),
            () => ValueTask.CompletedTask, TestContext.Current.CancellationToken));
        await attempted.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        release.TrySetResult();
        var results = await Task.WhenAll(first, second);
        Assert.Single(results, result => result.Status == SetupCompletionStatus.Committed);
        Assert.Single(results, result => result.Status is SetupCompletionStatus.Conflict or SetupCompletionStatus.Unavailable);
        await using var read = database.CreateContext();
        Assert.Equal(1, await read.ManagementRoleBindings.CountAsync(TestContext.Current.CancellationToken));
        Assert.Equal(1, await CountSharedAuditRowsAsync(read));
    }

    private static BffIdentityCheckResult ConfirmedSetupIdentity() =>
        new(BffIdentityCheckStatus.Confirmed, Issuer, Subject);

    private static ServiceProvider SetupServices(BffDatabase database, TimeProvider? clock = null)
    {
        var services = new ServiceCollection();
        services.AddScoped(_ => database.CreateContext());
        if (clock is not null) services.AddSingleton(clock);
        services.AddScoped<ManagementRoleBindingStore>();
        BffSetupHosting.AddSetup(services);
        return services.BuildServiceProvider();
    }

    private static async Task ClearSetup(BffDatabase database)
    {
        await using var context = database.CreateContext();
        await context.ManagementRoleBindings.ExecuteDeleteAsync(TestContext.Current.CancellationToken);
        await context.ServiceInstallations.ExecuteDeleteAsync(TestContext.Current.CancellationToken);
        await context.Database.ExecuteSqlRawAsync("DELETE FROM service_audit_logs", TestContext.Current.CancellationToken);
    }

    private sealed class SetupBoundaryFault(string boundary, string outcome, bool cancel, CancellationTokenSource caller)
    {
        public bool Observed { get; private set; }
        public void Complete(string name)
        {
            if (boundary != name) return;
            Observed = true;
            if (cancel) caller.Cancel();
            if (outcome == "throw") throw new InvalidOperationException("Synthetic setup boundary failure.");
            if (outcome == "internal-cancel") throw new OperationCanceledException(new CancellationToken(true));
        }
    }

    private class ObservedSetupSession(IBffSetupSession inner, SetupBoundaryFault? fault) : IBffSetupSession
    {
        public int Saves { get; private set; }
        public int Disposals { get; private set; }
        public async ValueTask BeginAsync(CancellationToken token) { await inner.BeginAsync(token); fault?.Complete("begin"); }
        public async ValueTask<ServiceInstallationState?> FindAsync(CancellationToken token) { var result = await inner.FindAsync(token); fault?.Complete("find"); return result; }
        public async ValueTask<SetupCodeValidationResult> ValidateAsync(SetupCode code, CancellationToken token) { var result = await inner.ValidateAsync(code, token); fault?.Complete("validate"); return result; }
        public async ValueTask<ServiceSetupResult> StageAsync(BffIdentityCheckResult identity, CancellationToken token) { var result = await inner.StageAsync(identity, token); fault?.Complete("stage"); return result; }
        public virtual async ValueTask<SetupCodeConsumptionResult> ConsumeAsync(SetupCode code, CancellationToken token) { var result = await inner.ConsumeAsync(code, token); fault?.Complete("consume"); return result; }
        public async ValueTask SaveAsync(CancellationToken token) { Saves++; await inner.SaveAsync(token); fault?.Complete("save"); }
        public async ValueTask CommitAsync(CancellationToken token) { await inner.CommitAsync(token); fault?.Complete("commit"); }
        public async ValueTask DisposeAsync() { Disposals++; await inner.DisposeAsync(); fault?.Complete("dispose"); }
    }

    private sealed class SetupClock : TimeProvider
    {
        public TimeSpan Offset { get; set; }
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow + Offset;
    }

    private sealed class LateCodeSetupSession(IBffSetupSession inner, string failure, SetupClock clock) : ObservedSetupSession(inner, null)
    {
        public override ValueTask<SetupCodeConsumptionResult> ConsumeAsync(SetupCode code, CancellationToken token)
        {
            // Exercise the shared store's real second validation after the role and audit stage.
            if (failure == "expired") clock.Offset = TimeSpan.FromHours(1);
            return base.ConsumeAsync(failure == "rotated" ? SetupCode.Generate() : code, token);
        }
    }
}
