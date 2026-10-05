using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using ServiceMantle;
using ServiceMantle.Bootstrap;
using ServiceMantle.Database.PostgreSql;
using ServiceMantle.Database.PostgreSql.Migration;
using ServiceMantle.Database.Sqlite;
using ServiceMantle.Migration;
using SignaCore.Database;
using SignaCore.Host.Migration;

namespace SignaCore.Host.Startup;

/// <summary>
/// One startup-owned core container spans target preparation and migration. It creates no host,
/// identity, hosted service, or normal-host receipt; the executor and context remain caller-owned.
/// </summary>
internal sealed class StartupDatabaseComposition : IAsyncDisposable
{
    private readonly DatabaseOptions databaseOptions;
    private readonly ServiceProvider provider;
    private readonly StartupDatabaseGate gate;
    private readonly StartupDatabaseGateOptions preparationOptions;
    private readonly StartupDatabaseGateOptions migrationOptions;
    private readonly PreparationObservationCapture preparation;

    private StartupDatabaseComposition(
        DatabaseOptions databaseOptions, ServiceProvider provider,
        StartupDatabaseGateOptions preparationOptions, PreparationObservationCapture preparation)
    {
        this.databaseOptions = databaseOptions;
        this.provider = provider;
        this.preparationOptions = preparationOptions;
        this.preparation = preparation;
        gate = provider.GetRequiredService<StartupDatabaseGate>();
        migrationOptions = new StartupDatabaseGateOptions(
            preparationOptions.Database, preparationOptions.DeploymentMode,
            preparationOptions.LockWaitBudget, enableTargetPreparation: false);
    }

    internal IServiceProvider Services => provider;

    internal static StartupDatabaseComposition Create(
        DatabaseOptions options, IDatabaseMigrationExecutor? executor = null,
        IDatabaseTargetPreparationProvider? targetPreparationProvider = null)
    {
        var target = new BootstrapDatabaseConfiguration(
            options.Provider, options.ServerVersion, options.ConnectionString);
        var services = new ServiceCollection();
        IDatabaseDeploymentCapabilityProvider capability;
        IDatabaseTargetPreparationProvider nativePreparation;
        StartupDatabaseGateOptions preparing;
        if (options.ProviderKind == DatabaseProvider.PostgreSql)
        {
            var postgres = new PostgreSqlDatabaseTargetPreparationProvider();
            capability = new PostgreSqlDatabaseDeploymentCapabilityProvider();
            nativePreparation = postgres;
            try
            {
                var preset = PostgreSqlStartupDatabaseGateOptions.Create(target, allowTargetCreation: true);
                // Preserve SignaCore's unpooled maintenance request as well as the shared preset's
                // pure connection derivation, deployment mode, and thirty-second budgets.
                var maintenance = new NpgsqlConnectionStringBuilder(preset.MaintenanceConnectionString)
                {
                    Pooling = false
                };
                preparing = new StartupDatabaseGateOptions(
                    preset.Database, preset.DeploymentMode, preset.LockWaitBudget,
                    enableTargetPreparation: true, allowTargetCreation: true,
                    maintenanceConnectionString: maintenance.ConnectionString,
                    preparationTimeout: preset.PreparationTimeout);
            }
            catch (ArgumentException)
            {
                throw StartupDatabase.PreparationFailure(
                    options.ProviderKind, WellKnownDatabaseTargetPreparationErrorCodes.InvalidTarget);
            }
            services.AddSingleton<IDatabaseMigrationLockProvider, PostgreSqlMigrationLockProvider>();
        }
        else if (options.ProviderKind == DatabaseProvider.Sqlite)
        {
            var sqlite = new SqliteDatabaseTargetPreparationProvider();
            capability = sqlite;
            nativePreparation = sqlite;
            preparing = new StartupDatabaseGateOptions(
                target, DatabaseDeploymentMode.SingleInstance, StartupMigrationGate.SharedLockWaitBudget,
                enableTargetPreparation: true, allowTargetCreation: true);
        }
        else
        {
            throw new InvalidOperationException("Unsupported database provider.");
        }

        var capture = new PreparationObservationCapture(targetPreparationProvider ?? nativePreparation);
        services.AddSingleton(capability);
        services.AddSingleton<IDatabaseTargetPreparationProvider>(capture);
        if (executor is not null)
        {
            // Instance registration transfers no disposal ownership to the container or gate scope.
            services.AddSingleton(executor);
        }
        services.AddServiceMantleStartupDatabaseGateServices();
        return new StartupDatabaseComposition(options, services.BuildServiceProvider(), preparing, capture);
    }

    internal async Task PrepareAsync(
        CancellationToken cancellationToken,
        Func<string, DirectoryInfo>? createParentDirectory = null,
        Func<string, string>? canonicalizePath = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (databaseOptions.ProviderKind == DatabaseProvider.Sqlite)
        {
            StartupDatabase.EnsureSqliteParentDirectoryExists(
                databaseOptions.ConnectionString, createParentDirectory, canonicalizePath);
        }
        preparation.Reset();
        var result = await gate.PrepareAsync(preparationOptions, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (preparation.Cancelled)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        if (result.Succeeded)
        {
            return;
        }

        // Preserve the product's dirty-file contract only on the initial observation. EF's native
        // open performs recovery; preparation never checkpoints WAL or repeats a failed probe.
        if (databaseOptions.ProviderKind == DatabaseProvider.Sqlite &&
            preparation.ObservationCount == 1 && !preparation.PreparationWasCalled &&
            preparation.Last?.Status == DatabaseTargetObservationStatus.TargetUnreachable &&
            preparation.Last.ErrorCode == WellKnownDatabaseTargetPreparationErrorCodes.TargetConflict)
        {
            return;
        }

        var errorCode = result.ErrorCode;
        if (errorCode == WellKnownDatabaseTargetPreparationErrorCodes.NotConnectableAfterPreparation)
        {
            // The shared gate intentionally reports a generic confirmation failure. Restore only
            // the already-observed closed provider classification, without a second I/O attempt.
            errorCode = preparation.Last?.ErrorCode;
        }
        throw StartupDatabase.PreparationFailure(databaseOptions.ProviderKind, errorCode);
    }

    internal async Task RunMigrationAsync(ILogger logger, CancellationToken cancellationToken)
    {
        var result = await gate.RunAsync(
            migrationOptions, new StartupDatabaseReceipt(),
            ServiceId.Parse(ServiceMantleComposition.ServiceIdentifier), cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (!result.Succeeded)
        {
            throw new StartupMigrationException(result.ErrorCode!);
        }
        logger.LogInformation(result.ExecutorWasCalled
            ? "Database schema is current after the shared migration orchestration."
            : "Database schema was already current; the migration executor was skipped.");
    }

    public ValueTask DisposeAsync() => provider.DisposeAsync();

    /// <summary>Invocation-local finite observations; no exception text or additional I/O.</summary>
    private sealed class PreparationObservationCapture(IDatabaseTargetPreparationProvider inner)
        : IDatabaseTargetPreparationProvider
    {
        public string ProviderId => inner.ProviderId;
        public BootstrapDatabaseTargetKind TargetKind => inner.TargetKind;
        public int ObservationCount { get; private set; }
        public bool PreparationWasCalled { get; private set; }
        public bool Cancelled { get; private set; }
        public DatabaseTargetObservation? Last { get; private set; }

        public void Reset()
        {
            ObservationCount = 0;
            PreparationWasCalled = false;
            Cancelled = false;
            Last = null;
        }

        public async ValueTask<DatabaseTargetObservation> ObserveAsync(
            BootstrapDatabaseConfiguration target, CancellationToken cancellationToken)
        {
            ObservationCount++;
            try
            {
                Last = await inner.ObserveAsync(target, cancellationToken);
                return Last;
            }
            catch (OperationCanceledException)
            {
                Cancelled = true;
                throw;
            }
        }

        public async ValueTask<DatabaseTargetPreparationResult> PrepareAsync(
            DatabaseTargetPreparationRequest request, TimeSpan timeout, CancellationToken cancellationToken)
        {
            PreparationWasCalled = true;
            try
            {
                return await inner.PrepareAsync(request, timeout, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                Cancelled = true;
                throw;
            }
        }
    }
}
