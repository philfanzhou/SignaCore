using Microsoft.EntityFrameworkCore;
using ServiceMantle.Bootstrap;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.EntityFrameworkCore;
using ServiceMantle.Migration;
using SignaCore.Database;
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
                await LegacyConfigurationImporter.ImportAsync(
                    db,
                    configuration,
                    settingsStore,
                    logger,
                    environment.IsDevelopment(),
                    cancellationToken);
                resolution = new InstallationResolution(
                    InstallationPhase.Completed, ConfigurationVersion: 1, SetupCode: null);
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
                    resolution.SetupCode?.Plaintext,
                    resolution.SetupCode?.ExpiresAtUtc);
            }

            var snapshot = await settingsStore.LoadAsync(db, resolution.ConfigurationVersion, cancellationToken);

            // Fail closed. A completed installation is never rolled back to Pending because settings
            // are missing: that would reopen anonymous setup against a database that owns accounts.
            SettingsSnapshotValidator.ThrowIfInvalid(snapshot.Values, environment.IsDevelopment());

            logger.LogInformation(
                "Loaded configuration snapshot: ServiceId={ServiceId}, " +
                "ConfigurationVersion={Version}, SettingCount={SettingCount}",
                InstallationStores.ServiceIdValue,
                resolution.ConfigurationVersion,
                snapshot.Values.Count);

            return new BootstrapPhaseResult(
                bootstrap,
                resolution.Phase,
                runtimeState,
                masterKeyProvider,
                protector,
                settingsStore,
                snapshot,
                PlaintextSetupCode: null,
                SetupCodeExpiresAt: null);
        }
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
}
