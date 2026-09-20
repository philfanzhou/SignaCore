using System.Data;
using Microsoft.EntityFrameworkCore;
using ServiceMantle.Audit;
using ServiceMantle.Bootstrap;
using ServiceMantle.Configuration;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.EntityFrameworkCore;
using ServiceMantle.Migration;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;
using SignaCore.Host.Migration;

namespace SignaCore.Host.Startup;

/// <summary>
/// Everything that must happen before the application phase can be composed: open the business
/// database named by the bootstrap file, migrate it, and determine the installation state.
/// <para>
/// Database unavailability is a fatal startup error. There is no local persisted fallback, because
/// an instance cannot provide correct identity behavior while its authoritative identity database is
/// unreachable — starting anyway would only serve wrong answers convincingly.
/// </para>
/// </summary>
internal static class InstallationStartup
{
    public static Task<BootstrapPhaseResult> RunAsync(
        BootstrapConfiguration bootstrap,
        IConfiguration configuration,
        IHostEnvironment environment,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken = default)
        => RunAsync(bootstrap, configuration, environment, loggerFactory, migrationExecutor: null, cancellationToken);

    /// <summary>
    /// Composition seam with an injectable migration executor for gate-level startup tests; the
    /// production entry always resolves the real SignaCore executor.
    /// </summary>
    internal static async Task<BootstrapPhaseResult> RunAsync(
        BootstrapConfiguration bootstrap,
        IConfiguration configuration,
        IHostEnvironment environment,
        ILoggerFactory loggerFactory,
        IDatabaseMigrationExecutor? migrationExecutor,
        CancellationToken cancellationToken = default)
    {
        var logger = loggerFactory.CreateLogger(typeof(InstallationStartup).FullName!);

        logger.LogInformation(
            "Bootstrap loaded from {Origin}: Provider={Provider}, Database={Database}",
            bootstrap.SourcePath ?? "the Development appsettings fallback",
            bootstrap.Database.Provider,
            BootstrapDiagnostics.DescribeEndpoint(bootstrap.Database));

        var masterKeyProvider = new BootstrapMasterKeyProvider(bootstrap.MasterKey);
        var protector = new AesGcmConfigurationProtector(masterKeyProvider);
        var settingsStore = new SystemSettingsStore(protector);
        var currentSnapshotAccessor = new ServiceSettingCurrentSnapshotAccessor();
        var databaseOptions = SignaCoreBootstrapStore.ToDatabaseOptions(bootstrap.Database);

        await using var db = CreateDbContext(databaseOptions);

        await StartupDatabase.EnsureDatabaseExistsAsync(databaseOptions, cancellationToken);
        await using (await StartupDatabase.AcquireInitializationLockAsync(databaseOptions, cancellationToken))
        {
            // The shared migration orchestration runs inside SignaCore's own outer initialization
            // lock: for PostgreSQL it acquires the service-scoped shared migration lock, runs the
            // limited observation, executes the full SignaCore migration workflow at most once, and
            // re-inspects before returning; SQLite serializes on the process-local single-instance
            // turn.
            if (migrationExecutor is null)
            {
                await StartupMigrationGate.RunAsync(db, databaseOptions, logger, cancellationToken);
            }
            else
            {
                await StartupMigrationGate.RunAsync(
                    db, databaseOptions, logger, migrationExecutor, cancellationToken);
            }

            // Completion checkpoint after the migration gate and its owned cleanup have settled:
            // original-token cancellation takes precedence over entering installation resolution.
            cancellationToken.ThrowIfCancellationRequested();

            var resolution = await InstallationStateResolver.ResolveAsync(db, cancellationToken);

            if (resolution.Phase == InstallationPhase.LegacyImportRequired)
            {
                logger.LogWarning(
                    "A database that already contains business data has no imported configuration. " +
                    "Running the protected legacy configuration import; first-run setup stays closed.");
                var importedVersion = await ImportLegacyConfigurationAsync(
                    db, configuration, masterKeyProvider, environment.IsDevelopment(), logger, cancellationToken);
                resolution = new InstallationResolution(
                    InstallationPhase.Completed, ConfigurationVersion: importedVersion, SetupCode: null);
            }

            // The durable installation identity is the service id; this Guid is only a stable
            // per-boot reference for the setup status surface.
            var runtimeState = new InstallationRuntimeState(
                resolution.Phase,
                Guid.NewGuid(),
                resolution.ConfigurationVersion);

            if (resolution.Phase != InstallationPhase.Completed)
            {
                return new BootstrapPhaseResult(
                    bootstrap,
                    resolution.Phase,
                    runtimeState,
                    masterKeyProvider,
                    protector,
                    settingsStore,
                    Snapshot: null,
                    CurrentSnapshotAccessor: currentSnapshotAccessor,
                    PlaintextSetupCode: resolution.SetupCode?.Plaintext,
                    SetupCodeExpiresAt: resolution.SetupCode?.ExpiresAtUtc);
            }

            // Legacy deployments that predate the shared aggregate are migrated once, here inside
            // the initialization lock and inside one caller-owned transaction. A refusal fails
            // startup without touching the installation state: a completed installation is never
            // rolled back to Pending.
            await MigrateLegacySettingsAsync(db, protector, masterKeyProvider, environment.IsDevelopment(), logger, cancellationToken);

            // The runtime snapshot authority is the shared loader: it reads the aggregate, decrypts
            // sensitive values with the shared protector, validates the complete candidate, and
            // activates it on the process-shared accessor instance. Failure never replaces an
            // existing snapshot and never rolls the installation back.
            var (sharedSnapshot, projectedSnapshot) = await ActivateSharedSnapshotAsync(
                databaseOptions, masterKeyProvider, currentSnapshotAccessor, environment.IsDevelopment(), cancellationToken);

            // The aggregate version is a long; the host's configuration-version surfaces are int.
            // Versions count from 1 and are monotonic, so a real deployment cannot cross
            // int.MaxValue — the activation boundary above fails closed before this cast.
            runtimeState = new InstallationRuntimeState(
                resolution.Phase,
                runtimeState.InstallationId,
                configurationVersion: (int)sharedSnapshot.Version);

            logger.LogInformation(
                "Loaded configuration snapshot: ServiceId={ServiceId}, " +
                "ConfigurationVersion={Version}, SettingCount={SettingCount}",
                InstallationStores.ServiceIdValue,
                runtimeState.ConfigurationVersion,
                sharedSnapshot.Values.Count);

            return new BootstrapPhaseResult(
                bootstrap,
                resolution.Phase,
                runtimeState,
                masterKeyProvider,
                protector,
                settingsStore,
                projectedSnapshot,
                currentSnapshotAccessor,
                PlaintextSetupCode: null,
                SetupCodeExpiresAt: null);
        }
    }

    /// <summary>
    /// Migrates the legacy <c>system_settings</c> rows into the shared aggregate when the
    /// aggregate is still empty, inside one caller-owned transaction (the shared update
    /// transaction requires the ambient transaction and a clean change tracker). An already-seeded
    /// aggregate — including one written by a concurrent instance — is left untouched. A failed
    /// migration fails startup; the installation state is never modified here.
    /// </summary>
    private static async Task MigrateLegacySettingsAsync(
        IdentityDbContext db,
        IConfigurationProtector legacyProtector,
        IMasterKeyProvider masterKeyProvider,
        bool isDevelopment,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        if (await SharedSettingAggregate.ReadVersionAsync(db, cancellationToken) is not null)
        {
            return;
        }

        var registry = SharedSettingComposition.CreateRegistry(isDevelopment);
        var updateService = new ServiceSettingUpdateService(
            InstallationStores.ServiceId,
            registry,
            new EfCoreServiceSettingUpdateTransaction<IdentityDbContext>(db),
            SharedSettingComposition.CreateRootKeySource(masterKeyProvider));
        var migrator = new SharedSettingMigrator(legacyProtector, updateService);

        // PostgreSQL runs a retrying execution strategy; explicit transactions must be wrapped in
        // it, and a retried attempt re-begins its own transaction (the migrator re-reads inside
        // the lambda, so the update transaction's read/apply pairing stays consistent).
        var strategy = db.Database.CreateExecutionStrategy();
        var result = await strategy.ExecuteAsync(async () =>
        {
            await using var transaction = await db.Database.BeginTransactionAsync(
                IsolationLevel.Serializable, cancellationToken);
            var migration = await migrator.MigrateAsync(
                db, SharedSettingComposition.MigrationOperator, cancellationToken);
            if (migration.Status == SharedSettingMigrationStatus.Failed)
            {
                await transaction.RollbackAsync(cancellationToken);
                return migration;
            }

            await transaction.CommitAsync(cancellationToken);
            return migration;
        });

        if (result.Status == SharedSettingMigrationStatus.Failed)
        {
            throw new SettingsSnapshotException(
                "The legacy system_settings rows could not be migrated into the shared " +
                $"service_settings aggregate ({result.FailureClassification}). Affected keys: " +
                $"{string.Join(", ", result.FailedKeys)}. The installation stays completed; fix " +
                "the reported problem and restart.",
                result.FailedKeys);
        }

        if (result.Status == SharedSettingMigrationStatus.Migrated)
        {
            logger.LogInformation(
                "Migrated {SettingCount} legacy setting rows into the shared aggregate.",
                result.MigratedKeyCount);
        }
    }

    /// <summary>
    /// The protected legacy configuration upgrade import: a pre-change deployment's effective
    /// configuration — appsettings, environment variables, and whatever the launcher injected — is
    /// read once through the product input adapter, mapped onto normalized keys, and written into
    /// the shared <c>service_settings</c> aggregate as its first version inside one caller-owned
    /// serializable transaction, together with the completed installation row it requires and the
    /// value-free product import audit.
    /// <para>
    /// The write goes only to the shared aggregate and the shared per-key audit rows; the legacy
    /// <c>system_settings</c> table is never written, no administrator is created, and the one-time
    /// setup code is never issued — anonymous setup stays closed. Failure rolls the whole attempt
    /// back and fails startup with key names and classification codes only.
    /// </para>
    /// <para>
    /// Idempotency and a concurrent second importer go through the optimistic-version path: the
    /// single write attempt carries expected version 0 and re-reads the authority inside its own
    /// attempt, so an aggregate another instance already committed makes this an idempotent
    /// re-run — the shared loader further down the startup path fully validates it — never a
    /// second import or a second import audit.
    /// </para>
    /// </summary>
    /// <returns>The aggregate version this startup observed after the import settled.</returns>
    private static async Task<int> ImportLegacyConfigurationAsync(
        IdentityDbContext db,
        IConfiguration configuration,
        IMasterKeyProvider masterKeyProvider,
        bool isDevelopment,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        // The product input rules live in the thin adapter; nothing is persisted while reading.
        var (legacyValues, importedKeyCount) = LegacyConfigurationInput.ReadCompleteInput(
            configuration, logger);

        var changes = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var (legacyKey, value) in legacyValues)
        {
            changes[SharedSettingKeys.NormalizedByLegacyKey[legacyKey]] = value;
        }

        var updateService = new ServiceSettingUpdateService(
            InstallationStores.ServiceId,
            SharedSettingComposition.CreateRegistry(isDevelopment),
            new EfCoreServiceSettingUpdateTransaction<IdentityDbContext>(db),
            SharedSettingComposition.CreateRootKeySource(masterKeyProvider));

        // PostgreSQL runs a retrying execution strategy; explicit transactions must be wrapped in
        // it, and every attempt starts from a cleared change tracker inside its own transaction, so
        // no tracked entity or audit row can survive into a retried attempt.
        var strategy = db.Database.CreateExecutionStrategy();
        var (importedVersion, importedThisRun) = await strategy.ExecuteAsync<(int Version, bool Imported)>(
            async () =>
        {
            db.ChangeTracker.Clear();

            await using var transaction = await db.Database.BeginTransactionAsync(
                IsolationLevel.Serializable, cancellationToken);

            // Re-read the authority inside this attempt: an aggregate committed by an earlier run
            // or a concurrent instance makes this an idempotent re-run.
            var existingVersion = await SharedSettingAggregate.ReadVersionAsync(db, cancellationToken);
            if (existingVersion is not null)
            {
                await transaction.RollbackAsync(cancellationToken);
                return ((int)existingVersion.Value, false);
            }

            var update = await updateService.UpdateAsync(
                new ServiceSettingUpdateCommand(
                    expectedVersion: 0,
                    changes,
                    SharedSettingComposition.LegacyImportOperator),
                cancellationToken);

            if (update.Status == ServiceSettingUpdateStatus.VersionConflict)
            {
                // Not a success: the committed aggregate — whoever wrote it — is only usable after
                // the authoritative re-read below; nothing is written and no audit is added here.
                await transaction.RollbackAsync(cancellationToken);
                return (await ReReadCommittedVersionAsync(db, cancellationToken), false);
            }

            if (!update.Succeeded || update.Version is not > 0)
            {
                // Validation, protection, and storage refusals are closed results; the rollback
                // below discards whatever the update staged inside its savepoint.
                throw new SettingsSnapshotException(
                    "The legacy configuration could not be imported into the shared service_settings " +
                    $"aggregate ({update.Status}). Affected keys: " +
                    $"{string.Join(", ", update.Errors.Select(error => $"{error.Key} ({error.ErrorCode})"))}. " +
                    "The installation stays unchanged; fix the reported problem and restart.",
                    update.Errors.Select(error => error.Key ?? error.ErrorCode).ToList());
            }

            var configurationVersion = checked((int)update.Version.Value);
            var now = DateTimeOffset.UtcNow;

            // The shared aggregate is written first, while the change tracker is still clean; the
            // installation row and the product audit are staged afterwards, in the same transaction
            // and the same single SaveChanges.
            var existingInstallation = await db.ServiceInstallations
                .AsNoTracking()
                .SingleOrDefaultAsync(
                    row => row.ServiceId == InstallationStores.ServiceIdValue,
                    cancellationToken);
            if (existingInstallation is null)
            {
                db.ServiceInstallations.Add(new ServiceInstallationEntity
                {
                    ServiceId = InstallationStores.ServiceIdValue,
                    Status = InstallationStatus.Completed,
                    CreatedAtUtc = now.UtcDateTime,
                    CompletedAtUtc = now.UtcDateTime,
                    Version = 1
                });
            }

            db.AuditLogs.Add(new AuditLogEntity
            {
                Id = Guid.NewGuid(),
                Action = "installation.legacy_import.completed",
                TargetType = "Installation",
                TargetId = InstallationStores.ServiceIdValue,
                ActorName = "legacy-import",
                Description =
                    $"Imported {importedKeyCount} legacy settings into the shared aggregate. " +
                    $"ConfigurationVersion={configurationVersion}.",
                CreatedAt = now
            });

            await db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return (configurationVersion, true);
        });

        db.ChangeTracker.Clear();

        if (importedThisRun)
        {
            logger.LogInformation(
                "Legacy configuration import completed: ServiceId={ServiceId}, " +
                "ImportedKeyCount={ImportedKeyCount}, ConfigurationVersion={Version}",
                InstallationStores.ServiceIdValue,
                importedKeyCount,
                importedVersion);
        }
        else
        {
            logger.LogInformation(
                "Legacy configuration import skipped: an aggregate committed by an earlier run or " +
                "a concurrent instance already exists. ServiceId={ServiceId}, " +
                "ConfigurationVersion={Version}, no second import was written.",
                InstallationStores.ServiceIdValue,
                importedVersion);
        }

        return importedVersion;
    }

    /// <summary>
    /// The authoritative re-read after a version conflict: the aggregate another writer committed
    /// is only usable when it exists at all. The shared loader further down the startup path fully
    /// validates the committed snapshot; this read only decides between an idempotent continue and
    /// a fail-closed refusal.
    /// </summary>
    private static async Task<int> ReReadCommittedVersionAsync(
        IdentityDbContext db,
        CancellationToken cancellationToken)
    {
        var committedVersion = await SharedSettingAggregate.ReadVersionAsync(db, cancellationToken);
        if (committedVersion is null)
        {
            throw new SettingsSnapshotException(
                "The legacy configuration import hit a version conflict but no committed aggregate " +
                "could be re-read. The installation stays unchanged; restart to retry the import.",
                []);
        }

        return (int)committedVersion.Value;
    }

    /// <summary>
    /// Activates the shared snapshot with a bootstrap-owned loader over the shared aggregate. The
    /// accessor instance is the one the DI hosts keep using, so the bootstrap activation and the
    /// composed snapshot services observe the same process-local snapshot.
    /// </summary>
    private static async Task<(ServiceSettingSnapshot Shared, SystemSettingsSnapshot Projected)>
        ActivateSharedSnapshotAsync(
            DatabaseOptions databaseOptions,
            IMasterKeyProvider masterKeyProvider,
            ServiceSettingCurrentSnapshotAccessor accessor,
            bool isDevelopment,
            CancellationToken cancellationToken)
    {
        var registry = SharedSettingComposition.CreateRegistry(isDevelopment);
        var store = new EfCoreServiceSettingStore<IdentityDbContext>(
            new BootstrapDbContextFactory(databaseOptions));
        using var loader = new ServiceSettingSnapshotLoader(
            InstallationStores.ServiceId,
            new ServiceSettingStoreSnapshotSource(store, registry),
            registry,
            accessor,
            SharedSettingComposition.CreateRootKeySource(masterKeyProvider));

        var refresh = await loader.RefreshAsync(cancellationToken);
        if (!refresh.Succeeded || refresh.Snapshot is null)
        {
            // Fail closed, keys and classification codes only: an incomplete, damaged, or
            // undecryptable aggregate is never activated and never replaces an existing snapshot.
            var details = string.Join(
                ", ", refresh.Errors.Select(error => $"{error.Key ?? "<snapshot>"} ({error.ErrorCode})"));
            throw new SettingsSnapshotException(
                "The stored configuration snapshot is incomplete, damaged, or could not be " +
                $"decrypted with the configured root key. Affected keys: {details}. The " +
                "installation stays completed; fix the reported problem and restart.",
                refresh.Errors.Select(error => error.Key ?? error.ErrorCode).ToList());
        }

        // Bootstrap boundary narrowing of the long aggregate version: versions start at 1 and are
        // monotonic, so overflow means a corrupt row, which fails closed like any other damage.
        if (refresh.Snapshot.Version > int.MaxValue)
        {
            throw new SettingsSnapshotException(
                $"The shared configuration version {refresh.Snapshot.Version} exceeds the supported range.",
                []);
        }

        var (values, entries) = SharedSettingConfigurationProjection.Project(refresh.Snapshot);
        return (
            refresh.Snapshot,
            new SystemSettingsSnapshot((int)refresh.Snapshot.Version, values, entries));
    }

    /// <summary>
    /// Rotates the one-time setup code for an installation that is still <c>Pending</c>. Requires
    /// access to the bootstrap secret, takes the database lock, prints the new code once, and cannot
    /// touch a <c>Completed</c> installation.
    /// </summary>
    public static async Task<int> RotateSetupCodeAsync(
        IConfiguration configuration,
        IHostEnvironment environment,
        CancellationToken cancellationToken = default)
    {
        BootstrapConfiguration bootstrap;
        try
        {
            bootstrap = SignaCoreBootstrapStore.Load(configuration, environment);
        }
        catch (SignaCore.Host.Bootstrap.BootstrapException exception)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }

        var databaseOptions = SignaCoreBootstrapStore.ToDatabaseOptions(bootstrap.Database);
        await using var db = CreateDbContext(databaseOptions);

        await using var initializationLock =
            await StartupDatabase.AcquireInitializationLockAsync(databaseOptions, cancellationToken);

        ServiceInstallationEntity? installation;
        try
        {
            installation = await db.ServiceInstallations
                .AsNoTracking()
                .FirstOrDefaultAsync(
                    row => row.ServiceId == InstallationStores.ServiceIdValue,
                    cancellationToken);
        }
        catch (Exception exception)
        {
            // Most likely the schema has not been created yet, which is not something this command
            // should do on its own — migrating is the startup path's job.
            Console.Error.WriteLine(
                "Could not read the installation state. Start SignaCore once so it can create and " +
                $"migrate the database. Details: {exception.Message}");
            return 1;
        }

        if (installation is null)
        {
            Console.Error.WriteLine(
                "No installation state exists yet. Start SignaCore once so it can initialize the database.");
            return 1;
        }

        if (installation.Status == InstallationStatus.Completed)
        {
            Console.Error.WriteLine(
                "Installation is already completed. The setup code cannot be reissued.");
            return 1;
        }

        var setupCodeStore = InstallationStores.CreateSetupCodeStore(db);
        var issued = await setupCodeStore.RotateAsync(InstallationStores.ServiceId, cancellationToken);
        if (!issued.IsIssued && issued.ErrorCode == WellKnownSetupCodeErrorCodes.NotCreated)
        {
            // A pending row whose code was never issued (the recovery window after row creation)
            // has nothing to rotate; create the first code instead.
            issued = await setupCodeStore.CreateAsync(InstallationStores.ServiceId, cancellationToken);
        }

        if (!issued.IsIssued)
        {
            Console.Error.WriteLine(
                $"The setup code could not be reissued ({issued.ErrorCode}).");
            return 1;
        }

        StartupBanner.WriteSetupCode(
            issued.SetupCode!.Reveal(),
            new DateTimeOffset(issued.ExpiresAtUtc!.Value));
        return 0;
    }

    private static IdentityDbContext CreateDbContext(DatabaseOptions databaseOptions)
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(databaseOptions);
        return new IdentityDbContext(optionsBuilder.Options);
    }

    /// <summary>
    /// A one-off factory over the bootstrap database options so the shared setting store can own
    /// its contexts during the bootstrap load, exactly like its DI registration does.
    /// </summary>
    private sealed class BootstrapDbContextFactory(DatabaseOptions databaseOptions)
        : IDbContextFactory<IdentityDbContext>
    {
        public IdentityDbContext CreateDbContext()
        {
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            return new IdentityDbContext(optionsBuilder.Options);
        }
    }
}
