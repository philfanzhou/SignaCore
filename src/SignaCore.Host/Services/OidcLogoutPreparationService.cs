using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;
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
/// authentication, token, URI, state, or form failure is one local JSON 400 and creates no row;
/// the ID token is validated in request memory and never stored (<c>DF-08</c>).
/// </summary>
public sealed class OidcLogoutPreparationService(
    ILogoutRequestStore logoutRequests,
    IKeyManager keyManager,
    IAuditService auditService,
    IdentityDbContext dbContext,
    JwtOptions jwtOptions,
    ILogger<OidcLogoutPreparationService> logger)
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
            return await PrepareCoreAsync(app, fields, clientIp, correlationId, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex,
                "Logout preparation failed: AppRowId={AppRowId}, CorrelationId={CorrelationId}",
                app.Id,
                LogValueSanitizer.Sanitize(correlationId));
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
        var keys = await keyManager.GetLogoutHintValidationKeysAsync(cancellationToken);
        if (!TryValidateIdTokenHint(idTokenHint, app.AppId, keys, now, out var subject, out var sessionId))
        {
            return Fail("id_token_hint_validation");
        }

        // IN-32: no normalization, exact ordinal match against this client's registered
        // post-logout set; the registered canonical value itself is what gets stored. The
        // authenticated entity carries an unloaded navigation, so the registrations are read
        // explicitly here.
        string? verifiedPostLogoutUri = null;
        if (postLogoutUri is not null)
        {
            var registeredUris = await dbContext.AppRedirectUris
                .AsNoTracking()
                .Where(registration => registration.AppRegistrationId == app.Id
                    && registration.Kind == RedirectUriKind.PostLogout)
                .Select(registration => registration.CanonicalUri)
                .ToListAsync(cancellationToken);
            verifiedPostLogoutUri = registeredUris
                .SingleOrDefault(registered => string.Equals(registered, postLogoutUri, StringComparison.Ordinal));
            if (verifiedPostLogoutUri is null)
            {
                return Fail("post_logout_redirect_uri");
            }
        }

        var creation = await logoutRequests.CreateAsync(
            new LogoutRequestDescriptor(app.Id, subject, sessionId, verifiedPostLogoutUri, state),
            now,
            cancellationToken);

        await auditService.RecordActionAsync(
            PreparedAuditAction,
            LogoutRequestAuditTargetType,
            creation.Id.ToString("D"),
            actorId: subject,
            actorName: null,
            description: $"session:{sessionId};client:{app.Id}",
            clientIp: clientIp,
            correlationId: correlationId,
            cancellationToken: cancellationToken);

        logger.LogInformation(
            "Logout request prepared: AccountId={AccountId}, AppRowId={AppRowId}, RequestId={RequestId}",
            subject,
            app.Id,
            creation.Id);
        return new OidcLogoutPreparationSuccess(
            $"{CompletionPath}?logout_handle={Uri.EscapeDataString(creation.LogoutHandle)}");
    }

    /// <summary>
    /// The full <c>IN-31</c> judgement: RS256 signature over the logout-hint key set, exact
    /// issuer, the authenticated client's audience, exactly one parseable <c>sub</c> and
    /// <c>sid</c>, and an <c>iat</c> no older than the freshness bound. <c>exp</c> is ignored
    /// here and nowhere else.
    /// </summary>
    private bool TryValidateIdTokenHint(
        string idTokenHint,
        string clientId,
        IReadOnlyList<RsaSecurityKey> keys,
        DateTimeOffset now,
        out Guid subject,
        out Guid sessionId)
    {
        subject = Guid.Empty;
        sessionId = Guid.Empty;
        if (keys.Count == 0)
        {
            return false;
        }

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        if (!handler.CanReadToken(idTokenHint))
        {
            return false;
        }

        ClaimsPrincipal principal;
        try
        {
            principal = handler.ValidateToken(
                idTokenHint,
                new TokenValidationParameters
                {
                    ValidIssuer = jwtOptions.Issuer,
                    ValidAudience = clientId,
                    IssuerSigningKeys = keys.Cast<SecurityKey>().ToList(),
                    ValidAlgorithms = ["RS256"],
                    ValidateLifetime = false
                },
                out var validated);
            _ = validated;
        }
        catch (Exception exception) when (exception
            is SecurityTokenValidationException or SecurityTokenMalformedException or ArgumentException)
        {
            return false;
        }

        // Exactly one sub and one sid, both parseable ids; any other shape is a failure.
        var subjectClaims = principal.FindAll("sub").ToList();
        var sessionClaims = principal.FindAll(JwtRegisteredClaimNames.Sid).ToList();
        if (subjectClaims.Count != 1
            || sessionClaims.Count != 1
            || !Guid.TryParse(subjectClaims[0].Value, out subject)
            || subject == Guid.Empty
            || !Guid.TryParse(sessionClaims[0].Value, out sessionId)
            || sessionId == Guid.Empty)
        {
            subject = Guid.Empty;
            sessionId = Guid.Empty;
            return false;
        }

        // IN-31 freshness: iat exists, is not in the future beyond clock skew, and is at most the
        // bound old. exp is deliberately not checked here.
        var issuedAtClaims = principal.FindAll(JwtRegisteredClaimNames.Iat).ToList();
        if (issuedAtClaims.Count != 1
            || !long.TryParse(issuedAtClaims[0].Value, out var issuedAtSeconds))
        {
            return false;
        }

        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedAtSeconds);
        return issuedAt <= now.AddMinutes(5)
            && issuedAt >= now.AddHours(-IdentityConstants.LogoutHintMaximumAgeHours);
    }

    private OidcLogoutPreparationSuccess? Fail(string reason)
    {
        // The reason is log/metric vocabulary only; the wire body carries one fixed description
        // and never distinguishes the failing check.
        logger.LogInformation("Logout request rejected locally. Reason={Reason}", reason);
        return null;
    }
}
