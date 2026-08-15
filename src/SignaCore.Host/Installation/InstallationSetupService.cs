using System.Data;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
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
/// Performs first-run setup as one atomic transaction: validate, seed the default settings snapshot,
/// create the initial administrator, audit, and flip the installation to <c>Completed</c>.
/// <para>
/// The administrator plaintext password is used only to produce its hash. It is never written to
/// <c>system_settings</c>, <c>installation_state</c>, logs, audit payloads, or the bootstrap file.
/// </para>
/// </summary>
internal sealed class InstallationSetupService
{
    private readonly IdentityDbContext _db;
    private readonly DatabaseOptions _databaseOptions;
    private readonly SystemSettingsStore _settingsStore;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IPasswordPolicy _passwordPolicy;
    private readonly ILogger<InstallationSetupService> _logger;

    public InstallationSetupService(
        IdentityDbContext db,
        DatabaseOptions databaseOptions,
        SystemSettingsStore settingsStore,
        IPasswordHasher passwordHasher,
        IPasswordPolicy passwordPolicy,
        ILogger<InstallationSetupService> logger)
    {
        _db = db;
        _databaseOptions = databaseOptions;
        _settingsStore = settingsStore;
        _passwordHasher = passwordHasher;
        _passwordPolicy = passwordPolicy;
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

        await using var transaction = await _db.Database.BeginTransactionAsync(
            IsolationLevel.Serializable,
            cancellationToken);

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

        var now = DateTimeOffset.UtcNow;
        if (state.SetupCodeExpiresAt is null || state.SetupCodeExpiresAt <= now ||
            !SetupCode.Verify(request.SetupCodeValue, state.SetupCodeHash))
        {
            return new SetupResult(SetupOutcome.InvalidSetupCode);
        }

        var configurationVersion = state.ConfigurationVersion + 1;

        await _settingsStore.WriteAsync(_db, values, configurationVersion, username, cancellationToken);

        var account = new AccountEntity
        {
            Id = Guid.NewGuid(),
            IsActive = true,
            CreatedAt = now,
            Remark = "Initial administrator created by first-run setup"
        };
        _db.Accounts.Add(account);
        _db.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            Username = username,
            PasswordHash = _passwordHasher.HashPassword(request.AdministratorPassword),
            CreatedAt = now
        });

        _db.AuditLogs.Add(new AuditLogEntity
        {
            Id = Guid.NewGuid(),
            Action = "installation.setup.completed",
            TargetType = "Installation",
            TargetId = state.InstallationId.ToString(),
            ActorId = account.Id,
            ActorName = username,
            // Deliberately no before/after snapshots: they would carry setting values, and some of
            // those settings are secrets.
            Description =
                $"First-run setup completed. PublicBaseUrl={publicBaseUrl}; " +
                $"ConfigurationVersion={configurationVersion}.",
            ClientIp = clientIp,
            CreatedAt = now
        });

        state.Status = InstallationStatus.Completed;
        state.CompletedAt = now;
        state.ConfigurationVersion = configurationVersion;
        state.SetupCodeHash = null;
        state.SetupCodeExpiresAt = null;
        _db.InstallationStates.Update(state);

        await _db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        _logger.LogInformation(
            "First-run setup completed: InstallationId={InstallationId}, ConfigurationVersion={Version}",
            state.InstallationId,
            configurationVersion);

        return new SetupResult(SetupOutcome.Completed);
    }

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
