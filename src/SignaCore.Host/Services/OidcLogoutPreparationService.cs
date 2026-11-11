using Microsoft.EntityFrameworkCore;
using ServiceMantle.Audit;
using SignaCore.Database;
using SignaCore.Host.Audit;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;

namespace SignaCore.Host.Services;

/// <summary>
/// The single success outcome of <see cref="OidcLogoutPreparationService.PrepareAsync"/>: the
/// relative <c>logout_uri</c> whose only query value is the one-time <c>logout_handle</c>
/// (<c>IN-34</c>). The plaintext handle exists in this value and in the stored digest's preimage
/// only; it is never logged (<c>DF-10</c>). A <c>null</c> result is the single local failure
/// answer — which check failed is never disclosed on the wire.
/// </summary>
public sealed record OidcLogoutPreparationSuccess(string LogoutUri);

/// <summary>
/// Step 1 of the prepared logout (<c>PS-08</c>/<c>IN-30</c>–<c>IN-34</c>): an authenticated
/// confidential BFF exchanges a validated <c>id_token_hint</c>, an optional exactly-registered
/// post-logout URI, and an optional bounded state for one five-minute logout handle. Every
/// authentication, token, URI, state, or form rejection is one local JSON 400 and creates no row;
/// the ID token is validated in request memory and never stored (<c>DF-08</c>).
/// </summary>
public sealed class OidcLogoutPreparationService(
    IServiceScopeFactory scopeFactory,
    IKeyManager keyManager,
    JwtOptions jwtOptions,
    ILogger<OidcLogoutPreparationService> logger,
    SignaCore.Domain.Validators.OidcRedirectUriPolicy? uriPolicy = null)
{
    public const string CompletionPath = "/oauth2/logout";

    private const string PreparedAuditAction = "oidc.logout.prepared";
    private const string LogoutRequestAuditTargetType = "LogoutRequest";

    /// <summary>The admitted form fields (<c>IN-30</c>–<c>IN-33</c>) plus the two client-credential transport fields.</summary>
    public static readonly IReadOnlySet<string> AdmittedFormFields = new HashSet<string>(StringComparer.Ordinal)
    {
        "id_token_hint",
        "post_logout_redirect_uri",
        "state",
        // client_secret_post transport of IN-30; consumed by the authentication handler, not by
        // the logout contract itself.
        "client_id",
        "client_secret"
    };

    /// <summary>
    /// Runs the whole preparation decision under one caller-captured UTC instant
    /// (<c>PS-22</c>). The caller has already authenticated the client and rejected the
    /// Basic-plus-form credential mix (<c>IN-20</c>/<c>IN-30</c>).
    /// </summary>
    public async Task<OidcLogoutPreparationSuccess?> PrepareAsync(
        AppRegistrationEntity app,
        IReadOnlyDictionary<string, string> fields,
        string? clientIp,
        string? correlationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(fields);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = await PrepareCoreAsync(app, fields, clientIp, correlationId, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return result;
        }
        catch
        {
            cancellationToken.ThrowIfCancellationRequested();
            logger.LogError("Logout preparation failed: AppRowId={AppRowId}", app.Id);
            return null;
        }
    }

    private async Task<OidcLogoutPreparationSuccess?> PrepareCoreAsync(
        AppRegistrationEntity app,
        IReadOnlyDictionary<string, string> fields,
        string? clientIp,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;

        // EV-09: an inactive application's registration — including its post-logout set — is not
        // trusted, and no row is written.
        if (!app.IsActive)
        {
            return Fail("application_inactive");
        }

        if (!fields.TryGetValue("id_token_hint", out var idTokenHint)
            || idTokenHint.Length is < 1 or > IdentityConstants.MaxLogoutIdTokenHintLength
            || !idTokenHint.All(character => character is >= ' ' and <= '~'))
        {
            return Fail("id_token_hint_shape");
        }

        if (fields.TryGetValue("post_logout_redirect_uri", out var postLogoutUri)
            && (postLogoutUri.Length is < 1 or > IdentityConstants.MaxOidcRedirectUriLength
                || !postLogoutUri.All(character => character is >= ' ' and <= '~')))
        {
            return Fail("post_logout_redirect_uri");
        }

        if (fields.TryGetValue("state", out var state)
            && (state.Length is < IdentityConstants.MinLogoutStateLength or > IdentityConstants.MaxLogoutStateLength
                || !state.All(character =>
                    char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '~' or '-')))
        {
            return Fail("state");
        }

        // IN-31: the ID token is validated in request memory only. Only this preparation check
        // ignores exp; the iat freshness bound still applies. The 24-hour retired-key window
        // admits a token signed by a just-rotated key.
        await keyManager.RefreshKeysAsync(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        var keys = await keyManager.GetLogoutHintValidationKeysAsync(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (!OidcLogoutHintValidator.TryValidate(
                idTokenHint, app.AppId, jwtOptions.Issuer, keys, now, out var subject, out var sessionId))
        {
            return Fail("id_token_hint_validation");
        }

        var creation = await PersistAsync(app, subject, sessionId, postLogoutUri, state, now,
            clientIp, correlationId, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (creation is null) return Fail("post_logout_redirect_uri");
        // PersistAsync has finished scope cleanup. A staged handle never reaches this boundary.
        logger.LogInformation(
            "Logout request prepared: AccountId={AccountId}, AppRowId={AppRowId}, RequestId={RequestId}",
            subject, app.Id, creation.Id);
        return new OidcLogoutPreparationSuccess(
            $"{CompletionPath}?logout_handle={Uri.EscapeDataString(creation.LogoutHandle)}");
    }

    private async Task<LogoutRequestCreation?> PersistAsync(
        AppRegistrationEntity app, Guid subject, Guid sessionId, string? postLogoutUri, string? state,
        DateTimeOffset now, string? clientIp, string? correlationId, CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        cancellationToken.ThrowIfCancellationRequested();
        // This marker only controls this operation's context diagnostics; other request scopes
        // and the singleton options/factory keep their original logging and retry configuration.
        var boundary = scope.ServiceProvider.GetService<LogoutPreparationScope>();
        if (boundary is not null) boundary.IsActive = true;
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        if (dbContext.ChangeTracker.HasChanges()) throw new InvalidOperationException("A clean logout scope is required.");

        // IN-32 stays read-only and ordinal, before staging anything. This query shares the fresh
        // context so provider exception text cannot escape through request-scope EF diagnostics.
        string? verifiedPostLogoutUri = null;
        if (postLogoutUri is not null)
        {
            var registeredUris = await dbContext.AppRedirectUris.AsNoTracking()
                .Where(registration => registration.AppRegistrationId == app.Id
                    && registration.Kind == RedirectUriKind.PostLogout)
                .Select(registration => registration.CanonicalUri).ToListAsync(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            verifiedPostLogoutUri = registeredUris.SingleOrDefault(
                registered => string.Equals(registered, postLogoutUri, StringComparison.Ordinal));
            if (verifiedPostLogoutUri is null
                || !await OidcCurrentRedirectTrust.AllowsAsync(dbContext, app.Id, RedirectUriKind.PostLogout,
                    verifiedPostLogoutUri, uriPolicy ?? SignaCore.Domain.Validators.OidcRedirectUriPolicy.Default, cancellationToken)) return null;
        }

        var creation = await scope.ServiceProvider.GetRequiredService<ILogoutRequestStore>().StageCreateAsync(
            new LogoutRequestDescriptor(app.Id, subject, sessionId, verifiedPostLogoutUri, state), now, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        await ManagementActionAudit.RecordAsync(
            scope.ServiceProvider.GetRequiredService<IManagementAuditWriter>(),
            ManagementActionAudit.AccountSource,
            PreparedAuditAction, LogoutRequestAuditTargetType, creation.Id.ToString("D"),
            subject, null, $"session:{sessionId};client:{app.Id}",
            clientIp, correlationId, cancellationToken: cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        // EF's single Save owns the automatic transaction and provider execution strategy. A
        // transient retry reuses this fixed entity graph: no new handle, id or audit is generated.
        await scope.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        return creation;
    }

    private OidcLogoutPreparationSuccess? Fail(string reason)
    {
        // The reason is log/metric vocabulary only; the wire body carries one fixed description
        // and never distinguishes the failing check.
        logger.LogInformation("Logout request rejected locally. Reason={Reason}", reason);
        return null;
    }
}
