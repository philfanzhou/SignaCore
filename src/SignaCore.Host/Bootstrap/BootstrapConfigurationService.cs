using ServiceMantle.Bootstrap;
using ServiceMantle.Database.PostgreSql;
using ServiceMantle.Database.Sqlite;
using SignaCore.Database;
using SignaCore.Host.Installation;
using SignaCore.Host.Models;

namespace SignaCore.Host.Bootstrap;

internal enum BootstrapOutcome
{
    Succeeded,

    /// <summary>The one-time bootstrap code was wrong or already used.</summary>
    InvalidCode,

    /// <summary>The submitted provider, version, or connection details failed validation.</summary>
    InvalidRequest,

    /// <summary>The target database could not be reached with the supplied credentials.</summary>
    TargetUnreachable,

    /// <summary>The target already holds data the supplied master key cannot decrypt.</summary>
    MasterKeyMismatch,

    /// <summary>The bootstrap file could not be written; the previous file, if any, is untouched.</summary>
    WriteFailed
}

internal sealed record BootstrapOperationResult(
    BootstrapOutcome Outcome,
    string Message,
    BootstrapTargetInspection? Inspection = null);

/// <summary>
/// Creates and replaces the bootstrap file.
/// <para>
/// Every path here validates before it writes: the provider and connection details have to bind, the
/// target has to be reachable, and a target that already holds protected data has to be readable
/// with the key being stored. Only then is the file written through the shared ServiceMantle
/// bootstrap store: creation never overwrites an existing file and replacement is atomic. A
/// rejected request never touches the file, so an operator can experiment against a live
/// installation without risking it.
/// </para>
/// </summary>
internal sealed class BootstrapConfigurationService
{
    private readonly BootstrapFileStore _store;
    private readonly ILogger<BootstrapConfigurationService> _logger;

    public BootstrapConfigurationService(
        BootstrapFileStore store,
        ILogger<BootstrapConfigurationService> logger)
    {
        _store = store;
        _logger = logger;
    }

    /// <summary>Where this instance reads and writes its bootstrap file.</summary>
    public string FilePath => _store.FilePath;

    /// <summary>
    /// Classifies a candidate database without writing anything, so the operator sees what they are
    /// about to point at before they commit to it.
    /// </summary>
    public async Task<BootstrapOperationResult> TestAsync(
        BootstrapDatabaseRequest request,
        string? candidateMasterKey,
        CancellationToken cancellationToken = default)
    {
        if (!BootstrapDatabaseRequestBinder.TryBind(request, out var database, out var error))
        {
            return new BootstrapOperationResult(BootstrapOutcome.InvalidRequest, error);
        }

        var inspection = await BootstrapTargetInspector.InspectAsync(
            database,
            candidateMasterKey,
            cancellationToken);

        return new BootstrapOperationResult(
            inspection.CanConnect ? BootstrapOutcome.Succeeded : BootstrapOutcome.TargetUnreachable,
            DescribeTarget(inspection),
            inspection);
    }

    /// <summary>
    /// Validates and writes the initial bootstrap file. Returns the generated master key only for a
    /// brand-new installation, and only so the caller can decide whether to display it once — it is
    /// never read back out of the file by any API.
    /// </summary>
    public async Task<BootstrapOperationResult> CreateAsync(
        BootstrapSaveRequest request,
        CancellationToken cancellationToken = default)
    {
        if (!BootstrapDatabaseRequestBinder.TryBind(request.Database, out var database, out var error))
        {
            return new BootstrapOperationResult(BootstrapOutcome.InvalidRequest, error);
        }

        var installMode = request.InstallMode?.Trim();
        var isNewInstallation = string.Equals(installMode, "new", StringComparison.OrdinalIgnoreCase);
        var isExistingInstallation =
            string.Equals(installMode, "existing", StringComparison.OrdinalIgnoreCase);

        if (!isNewInstallation && !isExistingInstallation)
        {
            return new BootstrapOperationResult(
                BootstrapOutcome.InvalidRequest,
                "Installation type must be either 'new' or 'existing'.");
        }

        var suppliedKey = string.IsNullOrWhiteSpace(request.MasterKey) ? null : request.MasterKey.Trim();

        if (isNewInstallation && suppliedKey is not null)
        {
            return new BootstrapOperationResult(
                BootstrapOutcome.InvalidRequest,
                "A new installation must not supply a master key; SignaCore generates it securely.");
        }

        if (!isNewInstallation && suppliedKey is null)
        {
            return new BootstrapOperationResult(
                BootstrapOutcome.InvalidRequest,
                "Connecting to an existing installation requires its master key. " +
                "Without it, the stored signing keys and secret settings cannot be decrypted.");
        }

        var inspection = await BootstrapTargetInspector.InspectAsync(
            database,
            suppliedKey,
            cancellationToken);

        if (!inspection.CanConnect)
        {
            return new BootstrapOperationResult(
                BootstrapOutcome.TargetUnreachable,
                DescribeTarget(inspection),
                inspection);
        }

        if (inspection.HasProtectedData)
        {
            if (isNewInstallation)
            {
                return new BootstrapOperationResult(
                    BootstrapOutcome.MasterKeyMismatch,
                    "The selected database already contains SignaCore data protected by an existing " +
                    "master key. Choose the existing-installation option and supply that key, or " +
                    "point this instance at an empty database.",
                    inspection);
            }

            if (inspection.KeyCompatibility == MasterKeyCompatibility.Incompatible)
            {
                return new BootstrapOperationResult(
                    BootstrapOutcome.MasterKeyMismatch,
                    "The supplied master key cannot decrypt the data already stored in this database. " +
                    "Nothing was changed. Supply the key this installation was created with; " +
                    "replacing it without rewrapping the protected data would make every stored " +
                    "signing key and secret setting unreadable.",
                    inspection);
            }
        }

        var masterKey = isNewInstallation
            ? GenerateMasterKey()
            : suppliedKey!;

        return await WriteAsync(database, masterKey, inspection, create: true, cancellationToken);
    }

    /// <summary>
    /// Replaces the database target of an already-installed instance, keeping the current master key
    /// unless the operator supplies one the new target actually requires.
    /// </summary>
    public async Task<BootstrapOperationResult> ReplaceDatabaseAsync(
        BootstrapDatabaseRequest request,
        string currentMasterKey,
        string? replacementMasterKey,
        CancellationToken cancellationToken = default)
    {
        if (!BootstrapDatabaseRequestBinder.TryBind(request, out var database, out var error))
        {
            return new BootstrapOperationResult(BootstrapOutcome.InvalidRequest, error);
        }

        var masterKey = string.IsNullOrWhiteSpace(replacementMasterKey)
            ? currentMasterKey
            : replacementMasterKey.Trim();

        var inspection = await BootstrapTargetInspector.InspectAsync(database, masterKey, cancellationToken);

        if (!inspection.CanConnect)
        {
            return new BootstrapOperationResult(
                BootstrapOutcome.TargetUnreachable,
                DescribeTarget(inspection),
                inspection);
        }

        if (inspection.KeyCompatibility == MasterKeyCompatibility.Incompatible)
        {
            return new BootstrapOperationResult(
                BootstrapOutcome.MasterKeyMismatch,
                "The target database holds data that the master key being stored cannot decrypt. " +
                "Nothing was changed.",
                inspection);
        }

        return await WriteAsync(database, masterKey, inspection, create: false, cancellationToken);
    }

    private async Task<BootstrapOperationResult> WriteAsync(
        DatabaseOptions database,
        string masterKey,
        BootstrapTargetInspection inspection,
        bool create,
        CancellationToken cancellationToken)
    {
        var configuration = new BootstrapConfiguration(
            InstallationStores.ServiceId,
            new BootstrapDatabaseConfiguration(database.Provider, database.ServerVersion, database.ConnectionString),
            masterKey);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (create)
            {
                _store.Create(configuration);
            }
            else
            {
                _store.Replace(configuration);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ServiceMantle.Bootstrap.BootstrapException exception)
        {
            // Only the closed failure kind decides what happened; the message stays in the log.
            _logger.LogError(
                "The bootstrap file could not be written: FailureKind={FailureKind}",
                exception.FailureKind);
            return new BootstrapOperationResult(
                BootstrapOutcome.WriteFailed,
                DescribeWriteFailure(exception),
                inspection);
        }

        // Provider and endpoint only. The connection string and the key never reach the log.
        _logger.LogInformation(
            "Bootstrap configuration written to {FilePath}: Provider={Provider}, Database={Endpoint}, " +
            "Target={Target}",
            _store.FilePath,
            database.Provider,
            inspection.Endpoint,
            inspection.Kind);

        return new BootstrapOperationResult(
            BootstrapOutcome.Succeeded,
            "Bootstrap configuration saved. SignaCore is restarting to load it.",
            inspection);
    }

    /// <summary>
    /// The product outcome text for each closed failure kind. Creation that finds the target
    /// already present and replacement of a missing target are both "the file could not be
    /// written"; everything unproven is reported as an unavailable write the same way.
    /// </summary>
    private static string DescribeWriteFailure(ServiceMantle.Bootstrap.BootstrapException exception) =>
        exception.FailureKind switch
        {
            BootstrapFileFailureKind.TargetAlreadyExists =>
                "A bootstrap file already exists at the configured location and is never overwritten. " +
                "Restart SignaCore to load it; replace its database target from the admin console.",
            BootstrapFileFailureKind.TargetMissing =>
                "The bootstrap file does not exist, so there is nothing to replace. Create it first " +
                "from Bootstrap Configuration Mode.",
            _ =>
                "The bootstrap file could not be written. Mount the configuration directory " +
                "read-write and make sure it is owned by the SignaCore runtime identity."
        };

    /// <summary>
    /// Generates the external root key for a new installation. Operators do not invent this value;
    /// it is the root of trust for every stored RSA signing private key and every encrypted system
    /// setting, so its entropy is not a place to accept a passphrase. Base64url without padding
    /// survives being copied through shells, YAML, and environment files.
    /// </summary>
    private static string GenerateMasterKey() =>
        Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static string DescribeTarget(BootstrapTargetInspection inspection) => inspection.Kind switch
    {
        BootstrapTargetKind.Unreachable =>
            $"The database at {inspection.Endpoint} could not be opened: " +
            $"{inspection.FailureReason ?? "the server did not accept the connection."}",
        BootstrapTargetKind.Empty =>
            $"{inspection.Endpoint} is empty. SignaCore will create its schema and then run first-run setup.",
        BootstrapTargetKind.PendingInstallation =>
            $"{inspection.Endpoint} holds a SignaCore installation that has not completed first-run setup.",
        BootstrapTargetKind.CompletedInstallation =>
            $"{inspection.Endpoint} holds a completed SignaCore installation.",
        BootstrapTargetKind.LegacyData =>
            $"{inspection.Endpoint} holds SignaCore data from before database-backed configuration. " +
            "Startup will run the protected legacy import.",
        _ => inspection.Endpoint
    };
}
