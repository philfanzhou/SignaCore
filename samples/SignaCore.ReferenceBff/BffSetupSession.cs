using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using ServiceMantle.Audit;
using ServiceMantle.Installation;
using SignaCore.ReferenceBff.Database;

namespace SignaCore.ReferenceBff;

// One attempt owns a fresh DI scope. Every asynchronous boundary is observed by the executor;
// disposing this session discards the transaction, then the entire scope, even on cleanup failure.
internal interface IBffSetupSession : IAsyncDisposable
{
    ValueTask BeginAsync(CancellationToken token);
    ValueTask<ServiceInstallationState?> FindAsync(CancellationToken token);
    ValueTask<SetupCodeValidationResult> ValidateAsync(SetupCode code, CancellationToken token);
    ValueTask<ServiceSetupResult> StageAsync(BffIdentityCheckResult identity, CancellationToken token);
    ValueTask<SetupCodeConsumptionResult> ConsumeAsync(SetupCode code, CancellationToken token);
    ValueTask SaveAsync(CancellationToken token);
    ValueTask CommitAsync(CancellationToken token);
}

internal sealed class BffSetupSession(AsyncServiceScope scope) : IBffSetupSession
{
    private ReferenceBffDbContext context => scope.ServiceProvider.GetRequiredService<ReferenceBffDbContext>();
    private IServiceInstallationStore installations => scope.ServiceProvider.GetRequiredService<IServiceInstallationStore>();
    private IServiceSetupCodeStore codes => scope.ServiceProvider.GetRequiredService<IServiceSetupCodeStore>();
    private IDbContextTransaction? transaction;

    public async ValueTask BeginAsync(CancellationToken token)
    {
        if (context.ChangeTracker.HasChanges()) throw new InvalidOperationException("Setup requires a clean scope.");
        transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable, token);
        token.ThrowIfCancellationRequested();
        if (context.Database.IsNpgsql())
        {
            // Only this sample's installation is locked. SQLite's serializable transaction takes
            // its single writer reservation. Neither provider retries this business operation.
            await context.ServiceInstallations.FromSqlRaw(
                "SELECT * FROM service_installations WHERE service_id = 'reference-bff' FOR UPDATE")
                .ToListAsync(token);
            token.ThrowIfCancellationRequested();
        }
    }

    public ValueTask<ServiceInstallationState?> FindAsync(CancellationToken token) =>
        installations.FindAsync(ReferenceBffServiceMantle.ServiceId, token);

    public ValueTask<SetupCodeValidationResult> ValidateAsync(SetupCode code, CancellationToken token) =>
        codes.ValidateAsync(ReferenceBffServiceMantle.ServiceId, code.Reveal(), token);

    public ValueTask<ServiceSetupResult> StageAsync(BffIdentityCheckResult identity, CancellationToken token) =>
        new ServiceSetupOrchestrator(
            [new InitialAdministratorContributor(context,
                scope.ServiceProvider.GetRequiredService<ManagementRoleBindingStore>(),
                scope.ServiceProvider.GetRequiredService<IManagementAuditWriter>(), identity)],
            new StagingScope(context)).OrchestrateAsync(token);

    public ValueTask<SetupCodeConsumptionResult> ConsumeAsync(SetupCode code, CancellationToken token) =>
        codes.StageConsumeAsync(ReferenceBffServiceMantle.ServiceId, code.Reveal(), token);

    public async ValueTask SaveAsync(CancellationToken token) => await context.SaveChangesAsync(token);
    public async ValueTask CommitAsync(CancellationToken token) => await transaction!.CommitAsync(token);

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (transaction is not null) await transaction.DisposeAsync();
        }
        finally { await scope.DisposeAsync(); }
    }

    private sealed class StagingScope(ReferenceBffDbContext context) : IServiceSetupStagingScope
    {
        public bool HasPendingChanges => context.ChangeTracker.HasChanges();
        public ValueTask DiscardPendingChangesAsync(CancellationToken cancellationToken = default)
        {
            context.ChangeTracker.Clear();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class InitialAdministratorContributor(
        ReferenceBffDbContext context, ManagementRoleBindingStore bindings,
        IManagementAuditWriter audit, BffIdentityCheckResult identity) : IServiceSetupContributor
    {
        public int Order => 100;
        public async ValueTask<ServiceSetupContributorResult> ValidateAsync(CancellationToken cancellationToken = default)
        {
            var occupied = await context.ManagementRoleBindings.AsNoTracking().AnyAsync(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return occupied ? ServiceSetupContributorResult.Rejected("bff.slot_occupied")
                : ServiceSetupContributorResult.Success();
        }

        public async ValueTask<ServiceSetupContributorResult> RegisterAsync(CancellationToken cancellationToken = default)
        {
            var staged = await bindings.StageInitialAdministratorAsync(
                identity.VerifiedIssuer!, identity.VerifiedSubject!, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            if (staged != ManagementRoleBindingStagingStatus.Staged)
                return ServiceSetupContributorResult.Rejected("bff.slot_occupied");
            var binding = context.ChangeTracker.Entries<ManagementRoleBindingEntity>()
                .Single(entry => entry.State == EntityState.Added).Entity;
            await audit.RecordAsync(ManagementAuditEvent.Create(
                ManagementAuditOperator.System(), WellKnownManagementAuditActions.InstallationCompleted,
                ManagementAuditTarget.Create(ManagementAuditTargetType.Parse("administrator-binding"), binding.Id.ToString("D")),
                ManagementAuditOutcome.Success, occurredAtUtc: DateTimeOffset.UtcNow), cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return ServiceSetupContributorResult.Success();
        }
    }
}
