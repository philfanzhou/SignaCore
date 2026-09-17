using Npgsql;
using ServiceMantle.Bootstrap;
using ServiceMantle.Database.PostgreSql;
using ServiceMantle.Database.Sqlite;
using SignaCore.Database;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// The candidate validation SignaCore applies before a Bootstrap file is written: the shared
/// database checks first, then the local rules that decide whether this process could actually
/// open and reload the target.
/// </summary>
/// <remarks>
/// The steps run in a fixed order and the first failure decides the answer, so the rejection the
/// operator sees names the earliest rule the candidate broke. The SignaCore error codes are not
/// part of the shared contract's closed internal set, so the shared entries project them as the
/// fixed management <c>400</c>; the codes themselves never reach a response or a log. Only an
/// internal failure reuses the shared <c>candidate.validation_failed</c> code, which the shared
/// entry projects as <c>503</c>.
/// <para>
/// The shared validators accept only targets that already exist and are connectable, because a
/// missing target may be created only through explicit preparation. SignaCore's first-install
/// flow has always accepted a brand-new target and created it on the next start, so this
/// validator performs exactly that explicit preparation — through the shared preparation
/// providers, with the same maintenance-database convention the startup path uses — before the
/// shared checks are re-run once. Preparation runs only on the creation path, only for the
/// missing-target rejection, and never overwrites an existing target.
/// </para>
/// </remarks>
internal sealed class SignaCoreBootstrapCandidateValidator : IBootstrapCandidateValidator
{
    private const string TargetNotFoundErrorCode = "database.target_not_found";
    private const string DatabaseInvalidErrorCode = "signacore.bootstrap.database_invalid";
    private const string TargetUnreachableErrorCode = "signacore.bootstrap.target_unreachable";
    private const string MasterKeyMismatchErrorCode = "signacore.bootstrap.master_key_mismatch";
    private const string MasterKeyReplacementRefusedErrorCode =
        "signacore.bootstrap.master_key_replacement_refused";

    private static readonly TimeSpan PreparationTimeout = TimeSpan.FromSeconds(30);

    private readonly BootstrapDatabaseCandidateValidator sharedValidator;
    private readonly DatabaseTargetPreparationProviderRegistry preparationRegistry;
    private readonly Func<DatabaseOptions, string?, CancellationToken, Task<BootstrapTargetInspection>> inspect;
    private readonly string? currentMasterKey;

    /// <summary>
    /// Initializes the validator.
    /// </summary>
    /// <param name="providerRegistry">The registry the shared checks dispatch through.</param>
    /// <param name="currentMasterKey">
    /// The master key this process loaded at startup, or null in Bootstrap Configuration Mode,
    /// where no key exists yet. A non-null key refuses a candidate that would silently replace it.
    /// </param>
    public SignaCoreBootstrapCandidateValidator(
        BootstrapDatabaseProviderRegistry providerRegistry,
        string? currentMasterKey = null)
        : this(providerRegistry, currentMasterKey, BootstrapTargetInspector.InspectAsync)
    {
    }

    /// <summary>
    /// Initializes the validator with a target-inspection seam, so the local classification steps
    /// can be exercised deterministically without a reachable target.
    /// </summary>
    internal SignaCoreBootstrapCandidateValidator(
        BootstrapDatabaseProviderRegistry providerRegistry,
        string? currentMasterKey,
        Func<DatabaseOptions, string?, CancellationToken, Task<BootstrapTargetInspection>> inspection)
    {
        sharedValidator = new BootstrapDatabaseCandidateValidator(providerRegistry);
        preparationRegistry = new DatabaseTargetPreparationProviderRegistry(
            [
                new PostgreSqlDatabaseTargetPreparationProvider(),
                new SqliteDatabaseTargetPreparationProvider()
            ],
            providerRegistry.ProviderIdResolver);
        inspect = inspection;
        this.currentMasterKey = currentMasterKey;
    }

    public async ValueTask<BootstrapValidationResult> ValidateAsync(
        BootstrapConfiguration candidate,
        CancellationToken cancellationToken)
    {
        // 1. The shared checks: provider registration, server-version and connection-string rules,
        //    and target observability. Their failure codes pass through unchanged, except the one
        //    rejection a brand-new target produces, which the explicit preparation below resolves.
        var shared = await sharedValidator.ValidateAsync(candidate, cancellationToken);
        if (!shared.IsValid)
        {
            if (string.Equals(shared.ErrorCode, TargetNotFoundErrorCode, StringComparison.Ordinal) &&
                await TryPrepareMissingTargetAsync(candidate, cancellationToken))
            {
                shared = await sharedValidator.ValidateAsync(candidate, cancellationToken);
            }

            if (!shared.IsValid)
            {
                return shared;
            }
        }

        // 2. The local shape this process must be able to reload after the restart the write
        //    triggers; a file TryLoad would reject would turn into a restart loop.
        var options = SignaCoreBootstrapStore.ToDatabaseOptions(candidate.Database);
        var localShape = ValidateLocalShape(options);
        if (localShape is not null)
        {
            return localShape;
        }

        // 3. Open the target and classify both it and the candidate key against what it protects.
        //    A server-generated key over a target that already holds protected data is inherently
        //    incompatible, which is the "new installation pointed at a used database" refusal.
        BootstrapTargetInspection inspection;
        try
        {
            inspection = await inspect(options, candidate.MasterKey, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return BootstrapValidationResult.Failure("candidate.validation_failed");
        }

        if (!inspection.CanConnect)
        {
            return BootstrapValidationResult.Failure(TargetUnreachableErrorCode);
        }

        if (inspection.KeyCompatibility == MasterKeyCompatibility.Incompatible)
        {
            return BootstrapValidationResult.Failure(MasterKeyMismatchErrorCode);
        }

        // 4. A running host never swaps the key it loaded for one the target cannot read.
        if (currentMasterKey is not null &&
            !string.Equals(candidate.MasterKey, currentMasterKey, StringComparison.Ordinal) &&
            inspection.KeyCompatibility != MasterKeyCompatibility.Compatible)
        {
            return BootstrapValidationResult.Failure(MasterKeyReplacementRefusedErrorCode);
        }

        return BootstrapValidationResult.Success();
    }

    /// <summary>
    /// The local reload-shape rules: the shared checks accept what their providers can probe, while
    /// this process additionally has to load the written file with its own options on the next
    /// start. Returns the local failure, or null when the shape is loadable.
    /// </summary>
    internal static BootstrapValidationResult? ValidateLocalShape(DatabaseOptions options)
    {
        try
        {
            options.Validate();
        }
        catch (InvalidOperationException)
        {
            return BootstrapValidationResult.Failure(DatabaseInvalidErrorCode);
        }

        return null;
    }

    /// <summary>
    /// Creates the missing target through the shared preparation providers. The maintenance
    /// endpoint for a server target reuses the candidate's own credentials against the provider's
    /// maintenance database, the same convention the startup path applies.
    /// </summary>
    private async Task<bool> TryPrepareMissingTargetAsync(
        BootstrapConfiguration candidate,
        CancellationToken cancellationToken)
    {
        if (!preparationRegistry.TryGetProvider(candidate.Database.Provider, out var provider) ||
            provider is null)
        {
            return false;
        }

        DatabaseTargetPreparationRequest request;
        if (provider.TargetKind == BootstrapDatabaseTargetKind.File)
        {
            request = DatabaseTargetPreparationRequest.ForFile(candidate.Database);
        }
        else
        {
            var maintenance = new NpgsqlConnectionStringBuilder(candidate.Database.ConnectionString)
            {
                Database = "postgres",
                Pooling = false
            };
            request = new DatabaseTargetPreparationRequest(candidate.Database, maintenance.ConnectionString);
        }

        try
        {
            var prepared = await provider.PrepareAsync(request, PreparationTimeout, cancellationToken);
            return prepared.Succeeded;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            // A preparation failure keeps the shared rejection: the reason stays with the shared
            // code and no second classification is invented here.
            return false;
        }
    }
}

