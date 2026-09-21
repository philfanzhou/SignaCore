using System.Data;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ServiceMantle.Audit;
using ServiceMantle.AspNetCore.ManagementApi.Setup;
using ServiceMantle.Configuration;
using ServiceMantle.Installation;
using SignaCore.Database;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host.Configuration;

namespace SignaCore.Host.Installation;

/// <summary>
/// The consumer-owned completion transaction behind the shared ServiceMantle setup entry.
/// <para>
/// The shared endpoint hands over a strictly shape-checked body: the candidate setup code and the
/// opaque <see cref="SetupInput"/> object. This executor owns the one serializable transaction that
/// everything first-run setup writes — the default settings snapshot into the shared
/// <c>service_settings</c> aggregate, the initial administrator, the installation audit
/// projection, and the consumption of the code — and answers with the closed
/// <see cref="SetupCompletionResult"/> only after the transaction settled.
/// </para>
/// <para>
/// Per the shared contract, the work runs in a fresh asynchronous scope with its own
/// <see cref="IdentityDbContext"/>, is attempted exactly once (never under a retrying execution
/// strategy), and is never retried or resumed after a failure. The administrator plaintext password
/// is used only to produce its hash: it is never written to <c>system_settings</c>,
/// <c>service_settings</c>, <c>service_installations</c>, logs, audit payloads, or the bootstrap
/// file.
/// </para>
/// </summary>
internal static class SetupCompletionExecutor
{
    public static async ValueTask<SetupCompletionResult> ExecuteAsync(
        HttpContext httpContext,
        SetupCode setupCode,
        SetupInput input,
        CancellationToken cancellationToken)
    {
        // A fresh scope per request: the shared endpoint's own request scope may already carry a
        // tracked installation read, and the contract forbids reusing it for the transaction.
        var scopeFactory = httpContext.RequestServices.GetRequiredService<IServiceScopeFactory>();
        await using (var scope = scopeFactory.CreateAsyncScope())
        {
            var services = scope.ServiceProvider;
            return await CompleteAsync(
                services.GetRequiredService<IdentityDbContext>(),
                services.GetRequiredService<DatabaseOptions>(),
                services.GetRequiredService<ServiceSettingUpdateService>(),
                services.GetRequiredService<IPasswordPolicy>(),
                services.GetRequiredService<InitialAdministratorSetupContributorFactory>(),
                services.GetRequiredService<ILoggerFactory>()
                    .CreateLogger("SignaCore.Host.Installation.SetupCompletionExecutor"),
                httpContext.Connection.RemoteIpAddress?.ToString(),
                setupCode,
                input.RootElement,
                cancellationToken);
        }
    }

    /// <summary>
    /// The transactional core, separated from the HTTP boundary so the database contract tests can
    /// drive it with their own contexts. Everything it needs is passed in explicitly; the one
    /// transaction it opens is its own.
    /// </summary>
    internal static async Task<SetupCompletionResult> CompleteAsync(
        IdentityDbContext db,
        DatabaseOptions databaseOptions,
        ServiceSettingUpdateService settingsUpdateService,
        IPasswordPolicy passwordPolicy,
        InitialAdministratorSetupContributorFactory contributorFactory,
        ILogger logger,
        string? clientIp,
        SetupCode setupCode,
        JsonElement input,
        CancellationToken cancellationToken)
    {
        try
        {
            SetupCompletionResult result;
            await using (var transaction = await db.Database.BeginTransactionAsync(
                             IsolationLevel.Serializable,
                             cancellationToken))
            {
                result = await StageCompletionAsync(
                    db, databaseOptions, settingsUpdateService, passwordPolicy, contributorFactory,
                    logger, clientIp, setupCode, input, transaction, cancellationToken);
            }

            // The one checkpoint after the transaction settled: committed facts stay committed, and
            // an uncommitted attempt never saves anything after this observation.
            cancellationToken.ThrowIfCancellationRequested();
            return result;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The caller's own cancellation is authoritative wherever it is observed; the shared
            // endpoint classifies it. An internal cancellation with a live caller token falls
            // through to the fixed safe failure below, like any other failure.
            throw;
        }
        catch
        {
            // Database, cryptographic, and provider failures carry constraint names and values in
            // their messages; setup reports only the fixed safe outcome.
            return SetupCompletionResult.Unavailable();
        }
    }

    private static async Task<SetupCompletionResult> StageCompletionAsync(
        IdentityDbContext db,
        DatabaseOptions databaseOptions,
        ServiceSettingUpdateService settingsUpdateService,
        IPasswordPolicy passwordPolicy,
        InitialAdministratorSetupContributorFactory contributorFactory,
        ILogger logger,
        string? clientIp,
        SetupCode setupCode,
        JsonElement input,
        IDbContextTransaction transaction,
        CancellationToken cancellationToken)
    {
        // The singleton row lock serializes concurrent completions before anything else runs.
        var state = await InstallationStateLock.LoadLockedAsync(db, databaseOptions, cancellationToken);
        if (state is null)
        {
            // A migrated database must own its installation row; a missing row is a state the
            // caller cannot repair by retrying the submission, but the host can by restarting.
            return SetupCompletionResult.Unavailable();
        }

        if (state.Status == InstallationStatus.Completed)
        {
            return SetupCompletionResult.Conflict();
        }

        // Read-only validation of the setup code: format, expiry, and digest are compared without
        // tracking or staging anything, and — per the shared entry contract — before any semantic
        // content of the input may influence the answer.
        var candidate = setupCode.Reveal();
        var setupCodeStore = InstallationStores.CreateSetupCodeStore(db);
        var validation = await setupCodeStore.ValidateAsync(
            InstallationStores.ServiceId, candidate, cancellationToken);
        if (!validation.IsValid)
        {
            return SetupCompletionResult.CredentialInvalid();
        }

        if (!TryReadInput(input, out var publicBaseUrl, out var allowNonHttpsIssuer,
                out var jwtAudience, out var username, out var password))
        {
            return SetupCompletionResult.ValidationFailed();
        }

        if (!PublicBaseUrlNormalizer.TryNormalizeBaseUrl(publicBaseUrl, out var normalizedBaseUrl, out _))
        {
            return SetupCompletionResult.ValidationFailed();
        }

        var audience = jwtAudience.Trim();
        if (audience.Length == 0)
        {
            return SetupCompletionResult.ValidationFailed();
        }

        var administratorUsername = username.Trim();
        if (administratorUsername.Length == 0 ||
            administratorUsername.Length > IdentityConstants.MaxUsernameLength)
        {
            return SetupCompletionResult.ValidationFailed();
        }

        if (!passwordPolicy.Validate(password, out _))
        {
            return SetupCompletionResult.ValidationFailed();
        }

        // Build and validate the whole proposed snapshot before staging anything: everything that
        // can be rejected from the request alone is a validation failure, not a failed transaction.
        var values = BuildSnapshot(normalizedBaseUrl, allowNonHttpsIssuer, audience, administratorUsername);
        if (SharedSettingComposition.ValidateCompleteCandidate(values).Count > 0)
        {
            return SetupCompletionResult.ValidationFailed();
        }

        // The shared aggregate is written first, while the change tracker is still clean: the
        // shared update transaction refuses a context that already carries pending work, and the
        // administrator contributor stages its entities afterwards. The shared validation and
        // sensitive re-protection are authoritative; a refusal here is discarded whole with the
        // transaction, so the safe outcome is the fixed unavailable answer.
        var normalizedChanges = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var (settingKey, value) in values)
        {
            normalizedChanges[SharedSettingKeys.NormalizedByLegacyKey[settingKey]] = value;
        }

        var settingsOperator = ManagementAuditOperator.Create(
            SetupAuditWriter.OperatorSource,
            administratorUsername);
        var settingsUpdate = await settingsUpdateService.UpdateAsync(
            new ServiceSettingUpdateCommand(0, normalizedChanges, settingsOperator),
            cancellationToken);
        if (!settingsUpdate.Succeeded)
        {
            return SetupCompletionResult.Unavailable();
        }

        // The aggregate counts its own versions from 1; the bootstrap boundary has already narrowed
        // the value range, and a first completion is version 1 by construction.
        var configurationVersion = checked((int)settingsUpdate.Version!.Value);

        // One orchestrator and one contributor per completion, staging into this scope's context.
        // The orchestrator validates read-only first and refuses to run on a context with pending
        // changes, which is what pins the consume-last order below.
        var contributor = contributorFactory.Create(
            new InitialAdministratorSetupInput(administratorUsername, password));
        var orchestration = await new ServiceSetupOrchestrator(
            [contributor],
            new SetupStagingScope(db))
            .OrchestrateAsync(cancellationToken);
        if (!orchestration.Succeeded)
        {
            return orchestration.ErrorCode switch
            {
                InitialAdministratorSetupContributor.UsernameTakenErrorCode =>
                    SetupCompletionResult.ValidationFailed(),
                InitialAdministratorSetupContributor.InvalidPasswordErrorCode =>
                    SetupCompletionResult.ValidationFailed(),
                // An unexpected orchestration failure is a safe-unavailable outcome, never a
                // validation verdict the caller could act on.
                _ => SetupCompletionResult.Unavailable()
            };
        }

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
        await new SetupAuditWriter(db, administratorUsername).RecordAsync(auditEvent, cancellationToken);

        // The final re-check: the shared store re-validates the candidate, then stages the
        // completed status, the completion timestamp, the code clearing, and the version increment
        // into this transaction's unit of work. A refusal here discards everything staged above,
        // because nothing has been saved yet.
        var consumption = await setupCodeStore.StageConsumeAsync(
            InstallationStores.ServiceId, candidate, cancellationToken);
        if (!consumption.IsStaged)
        {
            return consumption.ErrorCode switch
            {
                WellKnownSetupCodeErrorCodes.InstallationCompleted => SetupCompletionResult.Conflict(),
                _ => SetupCompletionResult.CredentialInvalid()
            };
        }

        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        logger.LogInformation(
            "First-run setup completed: ServiceId={ServiceId}, ConfigurationVersion={Version}",
            InstallationStores.ServiceIdValue,
            configurationVersion);

        return SetupCompletionResult.Committed();
    }

    /// <summary>
    /// Reads the fixed five-property input shape: exactly <c>publicBaseUrl</c> (string),
    /// <c>allowNonHttpsIssuer</c> (bool), <c>jwtAudience</c> (string), <c>username</c> (string),
    /// and <c>password</c> (string). A missing, extra, duplicated, or wrongly typed property is a
    /// validation failure; values are returned verbatim (trimming is a semantic step).
    /// </summary>
    private static bool TryReadInput(
        JsonElement input,
        out string publicBaseUrl,
        out bool allowNonHttpsIssuer,
        out string jwtAudience,
        out string username,
        out string password)
    {
        publicBaseUrl = string.Empty;
        allowNonHttpsIssuer = false;
        jwtAudience = string.Empty;
        username = string.Empty;
        password = string.Empty;

        if (input.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var seenBaseUrl = false;
        var seenAllowNonHttps = false;
        var seenAudience = false;
        var seenUsername = false;
        var seenPassword = false;
        foreach (var property in input.EnumerateObject())
        {
            switch (property.Name)
            {
                case "publicBaseUrl":
                    if (seenBaseUrl || property.Value.ValueKind != JsonValueKind.String)
                    {
                        return false;
                    }

                    publicBaseUrl = property.Value.GetString()!;
                    seenBaseUrl = true;
                    break;
                case "allowNonHttpsIssuer":
                    if (seenAllowNonHttps ||
                        property.Value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                    {
                        return false;
                    }

                    allowNonHttpsIssuer = property.Value.GetBoolean();
                    seenAllowNonHttps = true;
                    break;
                case "jwtAudience":
                    if (seenAudience || property.Value.ValueKind != JsonValueKind.String)
                    {
                        return false;
                    }

                    jwtAudience = property.Value.GetString()!;
                    seenAudience = true;
                    break;
                case "username":
                    if (seenUsername || property.Value.ValueKind != JsonValueKind.String)
                    {
                        return false;
                    }

                    username = property.Value.GetString()!;
                    seenUsername = true;
                    break;
                case "password":
                    if (seenPassword || property.Value.ValueKind != JsonValueKind.String)
                    {
                        return false;
                    }

                    password = property.Value.GetString()!;
                    seenPassword = true;
                    break;
                default:
                    return false;
            }
        }

        return seenBaseUrl && seenAllowNonHttps && seenAudience && seenUsername && seenPassword;
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
