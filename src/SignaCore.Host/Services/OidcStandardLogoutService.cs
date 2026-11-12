using Microsoft.EntityFrameworkCore;
using ServiceMantle.Audit;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Host.Audit;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;

namespace SignaCore.Host.Services;

/// <summary>
/// The standard RP-Initiated Logout of <c>GET /oauth2/session/end</c> (ADR 0010, stage 1): the
/// browser arrives with an <c>id_token_hint</c> — required, fresh, and signed by this issuer —
/// plus an optional exactly-registered <c>post_logout_redirect_uri</c> and bounded
/// <c>state</c>. The flow is the prepared logout's two steps executed in one request: validate
/// the hint against the application named by its <c>aud</c> claim, stage the same one-time
/// logout request, and immediately complete it with the browser's identity cookie, so the
/// <c>EV-06</c>/<c>EV-07</c> session semantics, the <c>EV-28</c> lock order, and the audit
/// trail are byte-for-byte the prepared flow's.
/// <para>
/// Every rejection — an unusable hint, an unknown or inactive application, an unregistered or
/// malformed redirect, a duplicated or unknown query field — is one local failure with no state
/// change, mirroring the prepared flow's closed error surface. A committed success returns the
/// completion's verified redirect and state; the caller deletes the browser cookies and answers
/// with the redirect or the local signed-out page.
/// </para>
/// </summary>
public sealed class OidcStandardLogoutService(
    IServiceScopeFactory scopeFactory,
    IKeyManager keyManager,
    JwtOptions jwtOptions,
    OidcLogoutCompletionService completion,
    ILogger<OidcStandardLogoutService> logger)
{
    private const string PreparedAuditAction = "oidc.logout.prepared";
    private const string LogoutRequestAuditTargetType = "LogoutRequest";

    /// <summary>The admitted query fields of the standard request, all optional carriers aside.</summary>
    public static readonly IReadOnlySet<string> AdmittedQueryFields = new HashSet<string>(StringComparer.Ordinal)
    {
        "id_token_hint",
        "post_logout_redirect_uri",
        "state"
    };

    /// <summary>
    /// The state-only bound of the standard request (ADR 0010 stage 4): a generic framework
    /// client's sign-out state is a data-protection-protected blob of several hundred unreserved
    /// characters. The value is echoed from the validated request rather than persisted, because
    /// the standard flow stages and completes in one request, so the stored bound stays
    /// <see cref="IdentityConstants.MaxLogoutStateLength"/>.
    /// </summary>
    public const int MaxStandardLogoutStateLength = 2048;

    /// <summary>
    /// Runs the whole standard decision: shape checks, application resolution by the hint's
    /// single <c>aud</c>, the shared <c>IN-31</c> hint validation, the <c>IN-32</c> exact
    /// registration match, staging, and the immediate completion. A <c>null</c> return is the
    /// single local failure answer.
    /// </summary>
    public async Task<OidcLogoutCompletionResult?> EndAsync(
        IReadOnlyDictionary<string, string> fields,
        Guid? cookieSessionId,
        string? clientIp,
        string? correlationId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(fields);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            return await EndCoreAsync(fields, cookieSessionId, clientIp, correlationId, cancellationToken);
        }
        catch
        {
            cancellationToken.ThrowIfCancellationRequested();
            logger.LogError("Standard logout failed.");
            return null;
        }
    }

    private async Task<OidcLogoutCompletionResult?> EndCoreAsync(
        IReadOnlyDictionary<string, string> fields,
        Guid? cookieSessionId,
        string? clientIp,
        string? correlationId,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;

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
            && (state.Length is < IdentityConstants.MinLogoutStateLength or > MaxStandardLogoutStateLength
                || !state.All(character =>
                    char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '~' or '-')))
        {
            return Fail("state");
        }

        // The application is named by the hint's single aud claim; the claim alone proves
        // nothing until the signature validation below succeeds for the same audience.
        if (!OidcLogoutHintValidator.TryReadAudience(idTokenHint, out var audience)
            || audience is null)
        {
            return Fail("id_token_hint_audience");
        }

        await keyManager.RefreshKeysAsync(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        var keys = await keyManager.GetLogoutHintValidationKeysAsync(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();

        await using var scope = scopeFactory.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var app = await scope.ServiceProvider.GetRequiredService<IAppRegistrationRepository>()
            .GetByAppIdAsync(audience, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        // EV-09: an inactive application's registration — including its post-logout set — is not
        // trusted, and no row is written.
        if (app is null || !app.IsActive)
        {
            return Fail("application_inactive");
        }

        if (!OidcLogoutHintValidator.TryValidate(
                idTokenHint, app.AppId, jwtOptions.Issuer, keys, now, out var subject, out var sessionId))
        {
            return Fail("id_token_hint_validation");
        }

        // IN-32 stays read-only and ordinal, before staging anything: a supplied post-logout URI
        // must match one registered value of exactly this application and pass the current
        // redirect-trust policy, exactly as the prepared flow requires.
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
                    verifiedPostLogoutUri, SignaCore.Domain.Validators.OidcRedirectUriPolicy.Default, cancellationToken))
            {
                return Fail("post_logout_redirect_uri");
            }
        }

        var creation = await scope.ServiceProvider.GetRequiredService<ILogoutRequestStore>().StageCreateAsync(
            // The state is deliberately not persisted: the standard flow stages and completes in
            // one request, so the caller echoes the already-validated request value byte-for-byte
            // from its own copy; the stored column keeps its tighter bound.
            new LogoutRequestDescriptor(app.Id, subject, sessionId, verifiedPostLogoutUri, State: null),
            now, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        await ManagementActionAudit.RecordAsync(
            scope.ServiceProvider.GetRequiredService<IManagementAuditWriter>(),
            ManagementActionAudit.AccountSource,
            PreparedAuditAction, LogoutRequestAuditTargetType, creation.Id.ToString("D"),
            subject, null, $"session:{sessionId};client:{app.Id};flow:standard",
            clientIp, correlationId, cancellationToken: cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        await scope.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();

        logger.LogInformation(
            "Standard logout staged: AccountId={AccountId}, AppRowId={AppRowId}, RequestId={RequestId}",
            subject, app.Id, creation.Id);

        // The immediate completion owns every state transition and the audit row; its result is
        // this endpoint's result unchanged.
        return await completion.CompleteAsync(
            creation.LogoutHandle, cookieSessionId, clientIp, correlationId, cancellationToken);
    }

    private OidcLogoutCompletionResult? Fail(string reason)
    {
        // The reason is log/metric vocabulary only; the wire body carries one fixed description
        // and never distinguishes the failing check.
        logger.LogInformation("Standard logout rejected locally. Reason={Reason}", reason);
        return null;
    }
}
