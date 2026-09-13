using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using ServiceMantle.Audit;
using ServiceMantle.Installation;
using SignaCore.Database;
using SignaCore.Domain.Validators;
using SignaCore.Host.Configuration;

namespace SignaCore.Host.Installation;

internal enum SetupOutcome
{
    Completed,

    /// <summary>The setup code was wrong, expired, or already consumed.</summary>
    InvalidSetupCode,

    /// <summary>The submitted public base URL or administrator credentials failed validation.</summary>
    InvalidRequest,

    /// <summary>Another instance or request completed installation first.</summary>
    AlreadyCompleted
}

internal sealed record SetupRequest(
    string PublicBaseUrl,
    bool AllowNonHttpsIssuer,
    string JwtAudience,
    string AdministratorUsername,
    string AdministratorPassword,
    string SetupCodeValue);

internal sealed record SetupResult(SetupOutcome Outcome, string? Error = null);

/// <summary>
/// Performs first-run setup as one atomic transaction, orchestrated through the shared
/// ServiceMantle setup orchestration: validate the code read-only, let the initial-administrator
/// contributor validate and stage the account, stage the default settings snapshot and the
/// installation audit event, and only then re-verify and stage consumption of the code, the
/// completion status, and the version increment in one save and one commit.
/// <para>
/// This service keeps owning the transaction, the singleton row lock, the single save, and the
/// commit; the contributor and the setup audit writer only stage into the shared unit of work.
/// The administrator plaintext password is used only to produce its hash. It is never written to
/// <c>system_settings</c>, <c>service_installations</c>, logs, audit payloads, or the bootstrap
/// file.
/// </para>
/// </summary>
internal sealed class InstallationSetupService
{
    private const string SetupCancelledMessage =
        "First-run setup was cancelled before the installation could be completed.";

    private readonly IdentityDbContext _db;
    private readonly DatabaseOptions _databaseOptions;
    private readonly SystemSettingsStore _settingsStore;
    private readonly IPasswordPolicy _passwordPolicy;
    private readonly InitialAdministratorSetupContributorFactory _contributorFactory;
    private readonly ILogger<InstallationSetupService> _logger;

    public InstallationSetupService(
        IdentityDbContext db,
        DatabaseOptions databaseOptions,
        SystemSettingsStore settingsStore,
        IPasswordPolicy passwordPolicy,
        InitialAdministratorSetupContributorFactory contributorFactory,
        ILogger<InstallationSetupService> logger)
    {
        _db = db;
        _databaseOptions = databaseOptions;
        _settingsStore = settingsStore;
        _passwordPolicy = passwordPolicy;
        _contributorFactory = contributorFactory;
        _logger = logger;
    }

    public async Task<SetupResult> CompleteAsync(
        SetupRequest request,
        string? clientIp,
        CancellationToken cancellationToken = default)
    {
        // Shape checks run before the transaction so an obviously malformed request never takes the
        // singleton row lock. The authoritative re-checks still happen inside it.
        if (!SettingsSnapshotValidator.TryNormalizeBaseUrl(
                request.PublicBaseUrl, out var publicBaseUrl, out var urlReason))
        {
            return new SetupResult(SetupOutcome.InvalidRequest, $"Public base URL {urlReason}");
        }

        var audience = request.JwtAudience?.Trim() ?? string.Empty;
        if (audience.Length == 0)
        {
            return new SetupResult(SetupOutcome.InvalidRequest, "JWT audience is required.");
        }

        var username = request.AdministratorUsername?.Trim() ?? string.Empty;
        if (username.Length == 0 || username.Length > IdentityConstants.MaxUsernameLength)
        {
            return new SetupResult(
                SetupOutcome.InvalidRequest,
                $"Administrator username must contain 1 to {IdentityConstants.MaxUsernameLength} characters.");
        }

        if (!_passwordPolicy.Validate(request.AdministratorPassword, out var passwordError))
        {
            return new SetupResult(SetupOutcome.InvalidRequest, passwordError);
        }

        // Build and validate the whole proposed snapshot before touching the database. The snapshot
        // is all-or-nothing, and everything that can be rejected from the request alone should be
        // rejected as a bad request rather than as a failed transaction.
        var values = BuildSnapshot(
            publicBaseUrl,
            request.AllowNonHttpsIssuer,
            audience,
            username);
        var snapshotErrors = SettingsSnapshotValidator.Validate(values);
        if (snapshotErrors.Count > 0)
        {
            return new SetupResult(SetupOutcome.InvalidRequest, string.Join(" ", snapshotErrors));
        }

        // The explicit transaction has to run inside CreateExecutionStrategy(): PostgreSQL enables
        // EnableRetryOnFailure(), and a retrying strategy refuses to execute commands
        // inside a caller-opened transaction — the first command throws
        // "does not support user-initiated transactions" and setup fails. SQLite has no retry
        // configured, so its strategy runs the lambda exactly once and behaves as before.
        var strategy = _db.Database.CreateExecutionStrategy();
        try
        {
            // An already-canceled entry does zero work: no transaction, no lock, no contributor.
            cancellationToken.ThrowIfCancellationRequested();

            return await strategy.ExecuteAsync(
                () => CompleteInTransactionAsync(request, clientIp, username, values, cancellationToken));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The caller's cancellation is authoritative wherever it is observed. Whatever internal
            // cancellation detail escaped the transaction is replaced here with a fixed safe
            // exception that carries the original token and no inner exception.
            throw new OperationCanceledException(SetupCancelledMessage, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // An internal cancellation is an ordinary staging failure, not a caller cancellation.
            throw new SetupStagingException();
        }
        catch (SetupStagingException)
        {
            throw;
        }
        catch (Exception)
        {
            // Database, cryptographic, and provider failures carry constraint names and values in
            // their messages; setup reports only the fixed safe failure.
            throw new SetupStagingException();
        }
    }

    /// <summary>
    /// The transactional half of <see cref="CompleteAsync"/>, written so a retrying execution
    /// strategy can replay it whole: the orchestrator, its contributor, and every entity tracked
    /// are created inside, and the change tracker is reset up front so a rolled-back attempt
    /// cannot leak pending inserts into the next one.
    /// </summary>
    private async Task<SetupResult> CompleteInTransactionAsync(
        SetupRequest request,
        string? clientIp,
        string username,
        Dictionary<string, string> values,
        CancellationToken cancellationToken)
    {
        _db.ChangeTracker.Clear();

        SetupResult result;
        await using (var transaction = await _db.Database.BeginTransactionAsync(
                         IsolationLevel.Serializable,
                         cancellationToken))
        {
            result = await StageCompletionAsync(
                request, clientIp, username, values, transaction, cancellationToken);
        }

        // The transaction has been released — committed or rolled back — and its cleanup has
        // settled. Tracking state from a discarded attempt must not survive into a retry or a
        // later request, so it is cleared before the single exit point.
        _db.ChangeTracker.Clear();

        // The one place caller cancellation is observed once the work has settled. Data committed
        // before this observation stays committed; nothing uncommitted is saved by this check.
        cancellationToken.ThrowIfCancellationRequested();

        return result;
    }

    private async Task<SetupResult> StageCompletionAsync(
        SetupRequest request,
        string? clientIp,
        string username,
        Dictionary<string, string> values,
        IDbContextTransaction transaction,
        CancellationToken cancellationToken)
    {
        var state = await InstallationStateLock.LoadLockedAsync(_db, _databaseOptions, cancellationToken);
        if (state is null)
        {
            return new SetupResult(
                SetupOutcome.InvalidRequest,
                "Installation state is missing. Restart the service to reinitialize it.");
        }

        if (state.Status == InstallationStatus.Completed)
        {
            return new SetupResult(SetupOutcome.AlreadyCompleted);
        }

        // Read-only validation of the setup code: format, expiry, and digest are compared without
        // tracking or staging anything. The authoritative consumption re-check happens only after
        // every product artifact is staged, so an expiring code can still be refused at the last
        // moment with nothing committed.
        var setupCodeStore = InstallationStores.CreateSetupCodeStore(_db);
        var validation = await setupCodeStore.ValidateAsync(
            InstallationStores.ServiceId,
            request.SetupCodeValue,
            cancellationToken);
        if (!validation.IsValid)
        {
            return MapSetupCodeRejection(validation.ErrorCode);
        }

        // One orchestrator and one contributor per transaction attempt, staging into this request
        // scope's context through the shared staging scope. The orchestrator validates read-only
        // first and refuses to run on a context with pending changes, which is what pins the
        // consume-last order below.
        var contributor = _contributorFactory.Create(
            new InitialAdministratorSetupInput(username, request.AdministratorPassword));
        var orchestration = await new ServiceSetupOrchestrator(
            [contributor],
            new SetupStagingScope(_db))
            .OrchestrateAsync(cancellationToken);
        if (!orchestration.Succeeded)
        {
            return orchestration.ErrorCode switch
            {
                InitialAdministratorSetupContributor.UsernameTakenErrorCode => new SetupResult(
                    SetupOutcome.InvalidRequest,
                    "An account with this administrator username already exists."),
                InitialAdministratorSetupContributor.InvalidPasswordErrorCode => new SetupResult(
                    SetupOutcome.InvalidRequest,
                    "The administrator password does not satisfy the password policy."),
                _ => throw new SetupStagingException()
            };
        }

        var configurationVersion =
            await SystemSettingsStore.ReadConfigurationVersionAsync(_db, cancellationToken) + 1;

        await _settingsStore.WriteAsync(_db, values, configurationVersion, username, cancellationToken);

        // The installation event is expressed with the shared audit model and staged once, after
        // the administrator and the settings succeeded. The closed projection into the existing
        // audit row is the only audit write this transaction performs.
        var auditEvent = ManagementAuditEvent.Create(
            ManagementAuditOperator.Create(
                SetupAuditWriter.OperatorSource,
                contributor.AccountId.ToString("D")),
            WellKnownManagementAuditActions.InstallationCompleted,
            ManagementAuditTarget.Create(
                WellKnownManagementAuditTargetTypes.Service,
                InstallationStores.ServiceIdValue),
            ManagementAuditOutcome.Success,
            occurredAtUtc: DateTimeOffset.UtcNow,
            clientIp: clientIp,
            securityDescription:
                $"First-run setup completed. ConfigurationVersion={configurationVersion}.");
        await new SetupAuditWriter(_db, username).RecordAsync(auditEvent, cancellationToken);

        // The final re-check: the shared store re-validates the candidate, then stages the
        // completed status, the completion timestamp, the code clearing, and the version increment
        // into this transaction's unit of work. A refusal here discards everything staged above,
        // because nothing has been saved yet.
        var consumption = await setupCodeStore.StageConsumeAsync(
            InstallationStores.ServiceId,
            request.SetupCodeValue,
            cancellationToken);
        if (!consumption.IsStaged)
        {
            return MapSetupCodeRejection(consumption.ErrorCode);
        }

        await _db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        _logger.LogInformation(
            "First-run setup completed: ServiceId={ServiceId}, ConfigurationVersion={Version}",
            InstallationStores.ServiceIdValue,
            configurationVersion);

        return new SetupResult(SetupOutcome.Completed);
    }

    private static SetupResult MapSetupCodeRejection(string? errorCode) =>
        errorCode switch
        {
            WellKnownSetupCodeErrorCodes.InstallationNotFound => new SetupResult(
                SetupOutcome.InvalidRequest,
                "Installation state is missing. Restart the service to reinitialize it."),
            WellKnownSetupCodeErrorCodes.InstallationCompleted =>
                new SetupResult(SetupOutcome.AlreadyCompleted),
            _ => new SetupResult(SetupOutcome.InvalidSetupCode)
        };

    /// <summary>
    /// The default snapshot for a new installation, plus the two values that have no safe default
    /// and the administrator username the form supplied.
    /// </summary>
    private static Dictionary<string, string> BuildSnapshot(
        string publicBaseUrl,
        bool allowNonHttpsIssuer,
        string jwtAudience,
        string username)
    {
        var values = SystemSettingsCatalog.BuildDefaults();
        values[SystemSettingKeys.PublicBaseUrl] = publicBaseUrl;
        // The issuer is not a duplicate field on the form: a discovery document served from one URL
        // and an `iss` claim naming another is rejected by every conforming client.
        values[SystemSettingKeys.JwtIssuer] = publicBaseUrl;
        values[SystemSettingKeys.JwtAudience] = jwtAudience;
        values[SystemSettingKeys.SecurityAllowNonHttpsIssuer] =
            allowNonHttpsIssuer ? "true" : "false";
        values[SystemSettingKeys.AdminWebAllowedOrigins] =
            $"[{System.Text.Json.JsonSerializer.Serialize(publicBaseUrl)}]";
        values[SystemSettingKeys.AdminUsername] = username;
        return values;
    }

}
