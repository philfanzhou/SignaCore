using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;

namespace SignaCore.Host.Services;

/// <summary>
/// The closed error classification of <see cref="OidcUserInfoService.ReadAsync"/> — the four
/// <c>IN-28</c>/<c>IN-29</c> rows. Which predicate failed is never part of the wire answer: each
/// classification carries its fixed English description.
/// </summary>
public enum OidcUserInfoRejection
{
    /// <summary>401 with the bare <c>Bearer</c> challenge: no Authorization header at all.</summary>
    MissingBearer,

    /// <summary>400 <c>invalid_request</c>: a malformed, multiple, or alternate carrier input.</summary>
    InvalidRequest,

    /// <summary>
    /// 401 <c>invalid_token</c>: a failed <c>typ</c>, signature, issuer, time, client/audience
    /// binding, or rejected current application/account/session state.
    /// </summary>
    InvalidToken,

    /// <summary>
    /// 403 <c>insufficient_scope</c>: a signature-valid access token without the interactive
    /// claims or <c>openid</c>.
    /// </summary>
    InsufficientScope
}

/// <summary>
/// The single outcome of <see cref="OidcUserInfoService.ReadAsync"/>: either the <c>PS-16</c>
/// claim set of one live interactive access token, or one closed rejection classification.
/// </summary>
public sealed class OidcUserInfoOutcome
{
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(true, nameof(Subject))]
    public bool IsSuccess { get; private init; }

    /// <summary>The stable account id as the <c>PS-16</c> <c>sub</c> value.</summary>
    public string? Subject { get; private init; }

    /// <summary>The bound Password username, present only when <c>profile</c> survived the intersection.</summary>
    public string? Name { get; private init; }

    /// <summary>The current non-null account nickname, present only when <c>profile</c> survived.</summary>
    public string? Nickname { get; private init; }

    public OidcUserInfoRejection? Rejection { get; private init; }

    public static OidcUserInfoOutcome Success(string subject, string? name, string? nickname) => new()
    {
        IsSuccess = true,
        Subject = subject,
        Name = name,
        Nickname = nickname
    };

    public static OidcUserInfoOutcome Failed(OidcUserInfoRejection rejection) => new()
    {
        IsSuccess = false,
        Rejection = rejection
    };
}

/// <summary>
/// The scope-controlled UserInfo read of the interactive Authorization Code flow
/// (<c>AC-08</c>/<c>IN-28</c>/<c>IN-29</c>/<c>PS-16</c>): one server-to-server projection for a
/// confidential BFF holding an interactive access token. The pipeline is deliberately standalone
/// — it shares no JWT bearer configuration with the management API and no audience rule with the
/// <c>/api/profile</c> <c>UserProfile</c> policy: the access token must carry <c>typ: at+jwt</c>,
/// an allowed RS256 signature over the current validation key set (<c>EV-16</c>), the exact
/// issuer, valid times under one captured instant, and the exact per-application audience/client
/// binding; the current application, account, and identity session must still be live. The
/// response is the closed <c>PS-16</c> set — <c>sub</c> byte-for-byte equal to the ID-token
/// subject, plus <c>name</c>/<c>nickname</c> only when <c>profile</c> survives the intersection
/// of the token scope with the application's current allow list (<c>SC-11</c>). The read slides
/// no idle deadline, writes no session, code, token, or audit artifact, and never invokes a
/// business callback (<c>PS-16</c>/<c>DF-15</c>).
/// </summary>
public sealed class OidcUserInfoService(
    IKeyManager keyManager,
    IAccountRepository accounts,
    IPasswordCredentialRepository passwordCredentials,
    IdentityDbContext dbContext,
    JwtOptions jwtOptions,
    ILogger<OidcUserInfoService> logger)
{
    /// <summary>The wire path this endpoint serves; also the Discovery activation value (<c>AC-08</c>).</summary>
    public const string RoutePath = "/oauth2/userinfo";


    private const string OpenIdScope = OidcScopeValidator.OpenId;
    private const string ProfileScope = OidcScopeValidator.Profile;

    private const int MaximumBearerTokenLength = IdentityConstants.InteractiveTokenMaxSerializedLength;

    /// <summary>
    /// Runs the whole read decision under one caller-captured UTC instant (<c>PS-22</c>). The
    /// caller passes the raw Authorization header values; every structure, cryptographic,
    /// binding, and live-state predicate belongs to this service.
    /// </summary>
    public async Task<OidcUserInfoOutcome> ReadAsync(
        Microsoft.Extensions.Primitives.StringValues authorizationHeaders,
        bool alternateCarrierPresent,
        CancellationToken cancellationToken = default)
    {
        // IN-28: a presented alternate carrier is invalid_request whatever the header state; the
        // bare Bearer challenge answers only a request that carries no credential at all.
        if (alternateCarrierPresent)
        {
            return OidcUserInfoOutcome.Failed(OidcUserInfoRejection.InvalidRequest);
        }

        if (authorizationHeaders.Count == 0)
        {
            return OidcUserInfoOutcome.Failed(OidcUserInfoRejection.MissingBearer);
        }

        if (authorizationHeaders.Count > 1)
        {
            return OidcUserInfoOutcome.Failed(OidcUserInfoRejection.InvalidRequest);
        }

        var header = authorizationHeaders.ToString();
        if (!AuthenticationHeaderValue.TryParse(header, out var parsed)
            || !string.Equals(parsed.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(parsed.Parameter))
        {
            return OidcUserInfoOutcome.Failed(OidcUserInfoRejection.InvalidRequest);
        }

        var token = parsed.Parameter;
        if (token.Length > MaximumBearerTokenLength
            || !token.All(character => character is >= ' ' and <= '~'))
        {
            return OidcUserInfoOutcome.Failed(OidcUserInfoRejection.InvalidRequest);
        }

        // One captured instant drives every time predicate and live-state comparison (PS-22).
        var now = DateTimeOffset.UtcNow;

        var keys = await keyManager.GetValidKeysAsync(cancellationToken);
        if (keys.Count == 0)
        {
            return Fail(OidcUserInfoRejection.InvalidToken, "validation_keys_empty");
        }

        // Steps 1–2 (IN-29): typ, RS256 signature over the current validation key set, exact
        // issuer, and token times. The audience is checked against the token's own client
        // binding after the signature — never through the broader profile-policy rules.
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        if (!handler.CanReadToken(token))
        {
            return Fail(OidcUserInfoRejection.InvalidToken, "unreadable_token");
        }

        ClaimsPrincipal principal;
        try
        {
            principal = handler.ValidateToken(
                token,
                new TokenValidationParameters
                {
                    ValidIssuer = jwtOptions.Issuer,
                    ValidateAudience = false,
                    IssuerSigningKeys = keys.Cast<SecurityKey>().ToList(),
                    ValidAlgorithms = ["RS256"],
                    ValidTypes = [JwtTokenService.AccessTokenType],
                    // The captured instant — not the validator's own clock — drives the time
                    // predicates; the boundaries are inclusive like every other deadline.
                    LifetimeValidator = (notBefore, expires, _, _) =>
                        (notBefore is null || now >= notBefore)
                        && expires is not null
                        && now < expires.Value,
                    ValidateIssuerSigningKey = true
                },
                out _);
        }
        catch (Exception exception) when (exception
            is SecurityTokenValidationException or SecurityTokenMalformedException or ArgumentException)
        {
            return Fail(OidcUserInfoRejection.InvalidToken, "token_validation");
        }

        // Step 3 (IN-29): the interactive claim presence first — sub, client_id, sid, and the
        // canonical scope with openid; a signature-valid token that lacks any of them answers
        // insufficient_scope, never invalid_token.
        var subjectClaims = principal.FindAll(IdentityConstants.ClaimSubject).ToList();
        var clientIdClaims = principal.FindAll(IdentityConstants.ClaimClientId).ToList();
        var scopeClaims = principal.FindAll("scope").ToList();
        var sessionClaims = principal.FindAll(JwtRegisteredClaimNames.Sid).ToList();
        if (subjectClaims.Count != 1
            || !Guid.TryParse(subjectClaims[0].Value, out var subject)
            || subject == Guid.Empty
            || clientIdClaims.Count != 1
            || string.IsNullOrEmpty(clientIdClaims[0].Value)
            || scopeClaims.Count != 1
            || sessionClaims.Count != 1
            || !Guid.TryParse(sessionClaims[0].Value, out var sessionId)
            || sessionId == Guid.Empty
            || !TryReadGrantedScopes(scopeClaims[0].Value, out var grantedScopes)
            || !grantedScopes.Contains(OpenIdScope))
        {
            return Fail(OidcUserInfoRejection.InsufficientScope, "interactive_claims");
        }

        // The audience/client/subject binding: exactly one aud, equal to the client_id the
        // token names, with no inference or fallback to a shared audience.
        var clientId = clientIdClaims[0].Value;
        var audiences = (principal.Claims
            .Where(claim => claim.Type == JwtRegisteredClaimNames.Aud)
            .Select(claim => claim.Value)).ToList();
        if (audiences.Count != 1
            || !string.Equals(audiences[0], clientId, StringComparison.Ordinal))
        {
            return Fail(OidcUserInfoRejection.InvalidToken, "audience_binding");
        }

        // Step 4 (IN-29): the live reads — current application (exact per-application audience
        // and client binding), active account, and a live session bound to the same subject.
        // A malformed request has already returned above; only from here may state be read.
        var application = await dbContext.AppRegistrations
            .AsNoTracking()
            .SingleOrDefaultAsync(app => app.AppId == clientId, cancellationToken);
        if (application is null
            || !application.IsActive
            || !string.Equals(audiences[0], application.AppId, StringComparison.Ordinal))
        {
            return Fail(OidcUserInfoRejection.InvalidToken, "application_state");
        }

        var account = await accounts.GetByIdAsync(subject, cancellationToken);
        if (account is null || !account.IsActive)
        {
            return Fail(OidcUserInfoRejection.InvalidToken, "account_state");
        }

        var session = await dbContext.IdentitySessions
            .AsNoTracking()
            .FirstOrDefaultAsync(row => row.Id == sessionId, cancellationToken);
        if (session is null
            || session.AccountId != subject
            || IdentitySessionStore.Classify(session, now) != IdentitySessionState.Active
            || FailsApplicationSessionPolicy(application, session, now))
        {
            return Fail(OidcUserInfoRejection.InvalidToken, "session_state");
        }

        // Step 5 (PS-16): the optional claims are the token scope intersected with the
        // application's current allow list — scope removal narrows the response (SC-11) without
        // any other effect.
        string? name = null;
        string? nickname = null;
        var currentAllowed = OidcScopeValidator.ParseCanonical(application.AllowedScopes);
        if (grantedScopes.Contains(ProfileScope) && currentAllowed.Contains(ProfileScope))
        {
            var credential = await passwordCredentials.GetByAccountIdAsync(subject, cancellationToken);
            name = credential?.Username;
            nickname = account.Nickname;
        }

        return OidcUserInfoOutcome.Success(subject.ToString("D"), name, nickname);
    }

    /// <summary>
    /// The canonical interactive scope representation: space-delimited members of the closed
    /// vocabulary, <c>openid</c> present, no duplicates.
    /// </summary>
    private static bool TryReadGrantedScopes(string value, out IReadOnlySet<string> scopes)
    {
        var members = new HashSet<string>(StringComparer.Ordinal);
        scopes = members;
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        foreach (var member in value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (member is not (OpenIdScope or ProfileScope or OidcScopeValidator.OfflineAccess)
                || !members.Add(member))
            {
                scopes = new HashSet<string>(StringComparer.Ordinal);
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// <c>EV-05</c>: the per-application session max-age — the same predicate the redemption and
    /// rotation transactions apply, kept as a semantic copy rather than a cross-layer reference.
    /// </summary>
    private static bool FailsApplicationSessionPolicy(
        AppRegistrationEntity application,
        IdentitySessionEntity session,
        DateTimeOffset now) =>
        application.IdentitySessionMaxAgeSeconds is int maxAgeSeconds
            && now >= session.AuthTime.AddSeconds(maxAgeSeconds);

    private OidcUserInfoOutcome Fail(OidcUserInfoRejection rejection, string reason)
    {
        // The reason is log vocabulary only; the wire answer never distinguishes the predicate.
        logger.LogInformation("UserInfo request rejected. Reason={Reason}", reason);
        return OidcUserInfoOutcome.Failed(rejection);
    }
}
