using System.Data;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services;
using SignaCore.Host.Configuration;
using SignaCore.Host.Http;
using SignaCore.Host.Installation;
using SignaCore.Host.Models;

namespace SignaCore.Host.Controllers;

/// <summary>
/// Authenticated management of the global settings snapshot.
/// <para>
/// Every change is validated as a whole snapshot before it is committed, written transactionally
/// with an incremented configuration version, and audited by key — never by value, because some of
/// those values are secrets.
/// </para>
/// </summary>
[Route("api/admin/settings")]
[ApiController]
[Authorize(Policy = "AdminSession")]
public sealed class AdminSettingsController : ControllerBase
{
    private readonly IdentityDbContext _db;
    private readonly DatabaseOptions _databaseOptions;
    private readonly IHostEnvironment _environment;
    private readonly ILogger<AdminSettingsController> _logger;
    private readonly SystemSettingsStore _settingsStore;
    private readonly InstallationRuntimeState _runtimeState;

    // The settings store and the installation runtime state are internal types, so they come from
    // the request scope rather than from declared constructor parameters — MVC activates controllers
    // through a public constructor.
    public AdminSettingsController(
        IdentityDbContext db,
        DatabaseOptions databaseOptions,
        IServiceProvider services,
        IHostEnvironment environment,
        ILogger<AdminSettingsController> logger)
    {
        _db = db;
        _databaseOptions = databaseOptions;
        _settingsStore = services.GetRequiredService<SystemSettingsStore>();
        _runtimeState = services.GetRequiredService<InstallationRuntimeState>();
        _environment = environment;
        _logger = logger;
    }

    [HttpGet]
    public async Task<ActionResult<SettingsListResponse>> GetAsync(CancellationToken cancellationToken)
    {
        var rows = await _db.SystemSettings
            .AsNoTracking()
            .ToDictionaryAsync(setting => setting.Key, StringComparer.OrdinalIgnoreCase, cancellationToken);

        var state = await _db.InstallationStates
            .AsNoTracking()
            .FirstOrDefaultAsync(row => row.Id == InstallationStateEntity.SingletonId, cancellationToken);
        var storedVersion = state?.ConfigurationVersion ?? _runtimeState.ConfigurationVersion;

        var snapshot = await _settingsStore.LoadAsync(_db, storedVersion, cancellationToken);

        var items = SystemSettingsCatalog.Definitions
            .Select(definition =>
            {
                rows.TryGetValue(definition.Key, out var row);
                var value = snapshot.Get(definition.Key);

                return new SettingItemResponse
                {
                    Key = definition.Key,
                    ValueType = definition.ValueType,
                    IsSecret = definition.IsSecret,
                    // A secret's value never leaves the service; the console only learns whether one
                    // is set, which is all it needs to render "leave blank to keep unchanged".
                    Value = definition.IsSecret ? null : value,
                    HasValue = !string.IsNullOrEmpty(value),
                    RestartRequired = definition.RestartRequired,
                    UpdatedAt = row?.UpdatedAt.ToUnixTimeSeconds(),
                    UpdatedBy = row?.UpdatedBy
                };
            })
            .ToList();

        return Ok(new SettingsListResponse
        {
            ConfigurationVersion = storedVersion,
            RunningConfigurationVersion = _runtimeState.ConfigurationVersion,
            RestartPending = storedVersion != _runtimeState.ConfigurationVersion,
            Items = items
        });
    }

    [HttpPut]
    public async Task<ActionResult<UpdateSettingsResponse>> UpdateAsync(
        [FromBody] UpdateSettingsRequest request,
        [FromServices] IAuditService auditService,
        CancellationToken cancellationToken)
    {
        if (request.Values.Count == 0)
        {
            return BadRequest(new ErrorResponse("No settings were supplied."));
        }

        var unknown = request.Values.Keys
            .Where(key => !SystemSettingsCatalog.IsManaged(key))
            .ToList();
        if (unknown.Count > 0)
        {
            return BadRequest(new ErrorResponse(
                $"These keys are not database-backed settings: {string.Join(", ", unknown)}."));
        }

        // The explicit transaction has to run inside CreateExecutionStrategy(): PostgreSQL enables
        // EnableRetryOnFailure(), and a retrying strategy refuses to execute commands
        // inside a caller-opened transaction. The lambda is replayed as a unit, so it re-reads the
        // snapshot on every attempt and starts from a cleared change tracker.
        var strategy = _db.Database.CreateExecutionStrategy();
        var outcome = await strategy.ExecuteAsync(ApplyAsync);

        if (outcome.Error is not null)
        {
            return outcome.IsConflict
                ? Conflict(new ErrorResponse(outcome.Error))
                : BadRequest(new ErrorResponse(outcome.Error));
        }

        if (outcome.ChangedKeys.Count == 0)
        {
            return Ok(new UpdateSettingsResponse
            {
                ConfigurationVersion = outcome.ConfigurationVersion,
                ChangedKeys = [],
                RestartRequired = false,
                Message = "No settings changed."
            });
        }

        var configurationVersion = outcome.ConfigurationVersion;
        var changedKeys = outcome.ChangedKeys;

        var actorId = Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : (Guid?)null;
        // Keys only. Recording old or new values here would put secrets into the audit trail.
        await auditService.RecordActionAsync(
            "settings_updated",
            "Settings",
            configurationVersion.ToString(),
            actorId,
            User.Identity?.Name,
            $"Updated {changedKeys.Count} settings: {string.Join(", ", changedKeys)}",
            HttpContext.GetClientIp());

        _logger.LogInformation(
            "Settings updated to version {Version}: {Keys}",
            configurationVersion,
            string.Join(", ", changedKeys));

        return Ok(new UpdateSettingsResponse
        {
            ConfigurationVersion = configurationVersion,
            ChangedKeys = changedKeys,
            // Every setting is restart-required until its subsystem gains explicit reload support.
            // Security-sensitive settings should favour a controlled restart over clever hot reload.
            RestartRequired = true,
            Message =
                "Settings saved. Restart every SignaCore instance to activate them; with multiple " +
                "instances, use a rolling restart."
        });

        async Task<SettingsUpdateOutcome> ApplyAsync()
        {
            _db.ChangeTracker.Clear();

            await using var transaction = await _db.Database.BeginTransactionAsync(
                IsolationLevel.Serializable,
                cancellationToken);

            var state = await InstallationStateLock.LoadLockedAsync(_db, _databaseOptions, cancellationToken);
            if (state is null)
            {
                return SettingsUpdateOutcome.Failed("Installation state is missing.", isConflict: true);
            }

            var current = await _settingsStore.LoadAsync(_db, state.ConfigurationVersion, cancellationToken);

            // Merge onto the full current snapshot: a settings change is still validated as one
            // snapshot, so a value that only becomes invalid in combination with an untouched one is
            // rejected here rather than at the next startup.
            var proposed = SystemSettingsCatalog.BuildDefaults();
            foreach (var (key, value) in current.Values)
            {
                proposed[key] = value;
            }

            var pendingKeys = new List<string>();
            foreach (var (key, value) in request.Values)
            {
                var normalized = value ?? string.Empty;
                if (proposed.TryGetValue(key, out var existing) &&
                    string.Equals(existing, normalized, StringComparison.Ordinal))
                {
                    continue;
                }

                proposed[key] = normalized;
                pendingKeys.Add(key);
            }

            if (pendingKeys.Count == 0)
            {
                return SettingsUpdateOutcome.Unchanged(state.ConfigurationVersion);
            }

            var errors = SettingsSnapshotValidator.Validate(proposed, _environment.IsDevelopment());
            if (errors.Count > 0)
            {
                return SettingsUpdateOutcome.Failed(string.Join(" ", errors), isConflict: false);
            }

            var nextVersion = state.ConfigurationVersion + 1;
            await _settingsStore.WriteAsync(
                _db,
                proposed.Where(pair => pendingKeys.Contains(pair.Key, StringComparer.OrdinalIgnoreCase))
                    .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase),
                nextVersion,
                User.Identity?.Name,
                cancellationToken);

            state.ConfigurationVersion = nextVersion;
            _db.InstallationStates.Update(state);
            await _db.SaveChangesAsync(cancellationToken);
            await transaction.CommitAsync(cancellationToken);

            return SettingsUpdateOutcome.Applied(nextVersion, pendingKeys);
        }
    }

    /// <summary>
    /// What the retriable transaction decided, kept separate from the HTTP result so the audit entry
    /// and the response are written once after it commits rather than on every replayed attempt.
    /// </summary>
    private sealed record SettingsUpdateOutcome(
        string? Error,
        bool IsConflict,
        int ConfigurationVersion,
        List<string> ChangedKeys)
    {
        public static SettingsUpdateOutcome Failed(string error, bool isConflict) =>
            new(error, isConflict, 0, []);

        public static SettingsUpdateOutcome Unchanged(int configurationVersion) =>
            new(null, false, configurationVersion, []);

        public static SettingsUpdateOutcome Applied(int configurationVersion, List<string> changedKeys) =>
            new(null, false, configurationVersion, changedKeys);
    }
}
