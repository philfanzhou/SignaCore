using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Domain.Keys;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;

namespace SignaCore.Host.Startup;

internal sealed record BootstrapPhaseResult(
    BootstrapConfiguration Bootstrap,
    InstallationPhase Phase,
    InstallationRuntimeState RuntimeState,
    IMasterKeyProvider MasterKeyProvider,
    IConfigurationProtector ConfigurationProtector,
    SystemSettingsStore SettingsStore,
    SystemSettingsSnapshot? Snapshot,
    string? PlaintextSetupCode);

/// <summary>
/// Everything that must happen before the application phase can be composed: open the business
/// database named by the bootstrap file, migrate it, and determine the installation state.
/// <para>
/// Database unavailability is a fatal startup error. There is no local persisted fallback, because
/// an instance cannot provide correct identity behavior while its authoritative identity database is
/// unreachable — starting anyway would only serve wrong answers convincingly.
/// </para>
/// </summary>
internal static class BootstrapPhase
{
    public static async Task<BootstrapPhaseResult> RunAsync(
        BootstrapConfiguration bootstrap,
        IConfiguration configuration,
        IHostEnvironment environment,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken = default)
    {
        var logger = loggerFactory.CreateLogger(typeof(BootstrapPhase).FullName!);

        logger.LogInformation(
            "Bootstrap loaded from {Origin}: Provider={Provider}, Database={Database}",
            bootstrap.Origin,
            bootstrap.Database.Provider,
            bootstrap.DatabaseEndpointForDiagnostics);

        var masterKeyProvider = new BootstrapMasterKeyProvider(bootstrap.RootSecret);
        var protector = new AesGcmConfigurationProtector(masterKeyProvider);
        var settingsStore = new SystemSettingsStore(protector);

        await using var db = CreateDbContext(bootstrap.Database);

        await DatabaseProvisioner.EnsureDatabaseExistsAsync(bootstrap.Database, cancellationToken);
        await using (await DatabaseProvisioner.AcquireMigrationLockAsync(bootstrap.Database, cancellationToken))
        {
            var pending = (await db.Database.GetPendingMigrationsAsync(cancellationToken)).ToList();
            if (pending.Count > 0)
            {
                logger.LogInformation("Applying {Count} pending migrations...", pending.Count);
            }

            await SchemaMigrator.MigrateAsync(db, bootstrap.Database, cancellationToken);

            var (phase, state, plaintextSetupCode) =
                await InstallationStateResolver.ResolveAsync(db, cancellationToken);

            if (phase == InstallationPhase.LegacyImportRequired)
            {
                logger.LogWarning(
                    "No installation state found in a database that already contains business data. " +
                    "Running the protected legacy configuration import; first-run setup stays closed.");
                state = await LegacyConfigurationImporter.ImportAsync(
                    db,
                    configuration,
                    settingsStore,
                    logger,
                    environment.IsDevelopment(),
                    cancellationToken);
                phase = InstallationPhase.Completed;
            }

            var runtimeState = new InstallationRuntimeState(
                phase,
                state.InstallationId,
                state.ConfigurationVersion);

            if (phase != InstallationPhase.Completed)
            {
                return new BootstrapPhaseResult(
                    bootstrap,
                    phase,
                    runtimeState,
                    masterKeyProvider,
                    protector,
                    settingsStore,
                    Snapshot: null,
                    plaintextSetupCode);
            }

            var snapshot = await settingsStore.LoadAsync(db, state.ConfigurationVersion, cancellationToken);

            // Fail closed. A completed installation is never rolled back to Pending because settings
            // are missing: that would reopen anonymous setup against a database that owns accounts.
            SettingsSnapshotValidator.ThrowIfInvalid(snapshot.Values, environment.IsDevelopment());

            logger.LogInformation(
                "Loaded configuration snapshot: InstallationId={InstallationId}, " +
                "ConfigurationVersion={Version}, SettingCount={SettingCount}",
                state.InstallationId,
                state.ConfigurationVersion,
                snapshot.Values.Count);

            return new BootstrapPhaseResult(
                bootstrap,
                phase,
                runtimeState,
                masterKeyProvider,
                protector,
                settingsStore,
                snapshot,
                PlaintextSetupCode: null);
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
            bootstrap = BootstrapLoader.Load(configuration, environment);
        }
        catch (BootstrapException exception)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }

        await using var db = CreateDbContext(bootstrap.Database);

        await using var migrationLock =
            await DatabaseProvisioner.AcquireMigrationLockAsync(bootstrap.Database, cancellationToken);

        Database.Entity.InstallationStateEntity? state;
        try
        {
            state = await db.InstallationStates.FirstOrDefaultAsync(
                row => row.Id == Database.Entity.InstallationStateEntity.SingletonId,
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

        if (state is null)
        {
            Console.Error.WriteLine(
                "No installation state exists yet. Start SignaCore once so it can initialize the database.");
            return 1;
        }

        if (state.Status == Database.Entity.InstallationStatus.Completed)
        {
            Console.Error.WriteLine(
                "Installation is already completed. The setup code cannot be reissued.");
            return 1;
        }

        var code = SetupCode.Generate();
        state.SetupCodeHash = SetupCode.Hash(code);
        state.SetupCodeExpiresAt = DateTimeOffset.UtcNow.Add(SetupCode.DefaultLifetime);
        await db.SaveChangesAsync(cancellationToken);

        StartupBanner.WriteSetupCode(code, state.SetupCodeExpiresAt.Value);
        return 0;
    }

    private static IdentityDbContext CreateDbContext(DatabaseOptions databaseOptions)
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(databaseOptions);
        return new IdentityDbContext(optionsBuilder.Options);
    }
}
