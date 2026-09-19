using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Domain.Validators;

namespace SignaCore.Domain.Services;

/// <summary>
/// The validated server-side inputs of one interactive ID token (<c>PS-12</c>). Every field is a
/// value the calling transaction already resolved and verified — the account, the interactive
/// client (whose AppId is the token audience), the live identity session with its authentication
/// facts, the canonical granted scope, the exact authorization-request nonce snapshot, and the two
/// profile sources. <paramref name="Nonce"/> is <c>null</c> only on the refresh variant
/// (<c>PS-15</c>): a refreshed ID token omits the nonce claim entirely while keeping every other
/// closed-set member. Callback enrichment, bootstrap roles, and every access-token binding claim
/// are deliberately not representable here: an ID token is an authentication statement, never a
/// downstream authorization (<c>PS-12</c>).
/// </summary>
public sealed record InteractiveIdTokenDescriptor(
    Guid AccountId,
    string ClientId,
    Guid SessionId,
    string AuthMethod,
    string Scope,
    string? Nonce,
    DateTimeOffset AuthTime,
    string? PasswordUsername,
    string? Nickname);

/// <summary>
/// The unique two-way outcome of <see cref="IInteractiveIdTokenFactory.Create"/>: either the issued
/// token with its expiry, or the single failure <see cref="ExceedsMaximumLength"/>. The failure
/// shape carries no token fragment and no claim value — it states only that issuance was refused
/// before anything was released (<c>DF-07</c>).
/// </summary>
public abstract record InteractiveIdTokenResult
{
    private InteractiveIdTokenResult()
    {
    }

    /// <summary>
    /// The serialized compact JWS and the <see cref="ExpiresAt"/> instant the <c>exp</c> claim
    /// carries (Unix-second precision). The token bytes exist only in this return value and must be
    /// released only after the caller's issuance transaction commits (<c>PS-09</c>).
    /// </summary>
    public sealed record Issued(
        string IdToken,
        DateTimeOffset ExpiresAt) : InteractiveIdTokenResult;

    /// <summary>
    /// The serialized token would exceed
    /// <see cref="IdentityConstants.InteractiveTokenMaxSerializedLength"/>; nothing was issued.
    /// </summary>
    public sealed record ExceedsMaximumLength : InteractiveIdTokenResult;
}

/// <summary>
/// The standalone constructor of the interactive Authorization Code flow ID token (<c>PS-12</c>,
/// OIDC Core §2): a pure, stateless, synchronous function over its validated inputs with no I/O
/// and no persisted token row (<c>PS-09</c>). The header is exactly <c>alg: RS256</c>, the current
/// <c>kid</c>, and <c>typ: JWT</c> — never the access token's <c>at+jwt</c> — and the claim set is
/// the closed <c>PS-12</c> set with no enrichment path at all. Only the constructor of the
/// interactive access token (<see cref="IInteractiveAccessTokenFactory"/>) shares its signing
/// authority; the two claim and type policies are fully separate.
/// </summary>
public interface IInteractiveIdTokenFactory
{
    /// <summary>
    /// Creates one ID token signed with <paramref name="signingKey"/> under the caller-captured
    /// instant <paramref name="now"/> (<c>PS-22</c>): claims exactly <c>iss</c>, stable account-id
    /// <c>sub</c>, single-string <c>aud</c> = client id, <c>exp</c>/<c>iat</c> at the fixed
    /// 5-minute lifetime, the session's original <c>auth_time</c>, <c>sid</c>, <c>amr</c> as a JSON
    /// array, and the exact <c>nonce</c> snapshot of the initial exchange; <c>name</c> and
    /// <c>nickname</c> appear only when <c>profile</c> was granted. A <c>null</c> nonce selects the
    /// refresh variant (<c>PS-15</c>), which omits the <c>nonce</c> claim and keeps the same closed
    /// set otherwise. The only failure is the serialized-length bound; precondition violations are
    /// programming errors and throw.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// An empty id, client, auth method, key id, or empty nonce, an unsupported auth method, or a
    /// non-canonical scope. The message never carries an input value.
    /// </exception>
    InteractiveIdTokenResult Create(
        InteractiveIdTokenDescriptor descriptor,
        RsaSecurityKey signingKey,
        DateTimeOffset now);
}

/// <inheritdoc cref="IInteractiveIdTokenFactory"/>
public sealed class InteractiveIdTokenFactory : IInteractiveIdTokenFactory
{
    /// <summary>
    /// The RFC 8176 authentication-method reference of the Password identity session — the only
    /// interactive authentication method of this phase (<c>PS-12</c>: <c>amr</c> contains only
    /// <c>pwd</c>). A future interactive method must extend the mapping, not silently reuse it.
    /// </summary>
    private const string PasswordAmrValue = "pwd";

    /// <summary>
    /// The full interactive scope vocabulary the canonical-form check runs against. Membership and
    /// ordering rules are <see cref="OidcScopeValidator"/>'s — no second scope rule exists here.
    /// </summary>
    private static readonly IReadOnlySet<string> InteractiveScopeVocabulary =
        new HashSet<string>(StringComparer.Ordinal)
        {
            OidcScopeValidator.OpenId,
            OidcScopeValidator.Profile,
            OidcScopeValidator.OfflineAccess
        };

    private readonly JwtOptions _jwtOptions;

    public InteractiveIdTokenFactory(JwtOptions jwtOptions)
    {
        _jwtOptions = jwtOptions;
    }

    public InteractiveIdTokenResult Create(
        InteractiveIdTokenDescriptor descriptor,
        RsaSecurityKey signingKey,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(signingKey);

        // Preconditions are programming errors of the calling transaction, which resolved every
        // value itself. The messages name the offending concept and never an input value.
        if (descriptor.AccountId == Guid.Empty)
        {
            throw new ArgumentException(
                "The account id must not be empty.", nameof(descriptor));
        }

        if (descriptor.SessionId == Guid.Empty)
        {
            throw new ArgumentException(
                "The identity session id must not be empty.", nameof(descriptor));
        }

        if (string.IsNullOrEmpty(descriptor.ClientId))
        {
            throw new ArgumentException(
                "The client id must not be empty.", nameof(descriptor));
        }

        // A null nonce selects the PS-15 refresh variant; an empty one is always a programming
        // error, exactly like every other half-supplied snapshot.
        if (descriptor.Nonce is not null && descriptor.Nonce.Length == 0)
        {
            throw new ArgumentException(
                "The nonce snapshot must not be empty.", nameof(descriptor));
        }

        if (string.IsNullOrEmpty(signingKey.KeyId))
        {
            throw new ArgumentException(
                "The signing key id must not be empty.", nameof(signingKey));
        }

        if (descriptor.AuthMethod != IdentityConstants.AuthMethodPassword)
        {
            throw new ArgumentException(
                "The auth method has no amr mapping in this phase.", nameof(descriptor));
        }

        if (!IsCanonicalInteractiveScope(descriptor.Scope))
        {
            throw new ArgumentException(
                "The scope must be the canonical interactive scope value.", nameof(descriptor));
        }

        var issuedAtSeconds = now.ToUnixTimeSeconds();
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(
            issuedAtSeconds + IdentityConstants.InteractiveIdTokenLifetimeSeconds);

        // The closed PS-12 claim set, and nothing else: no jti, no nbf, no scope, no client_id
        // claim, no auth_method, and no enrichment of any kind. JwtPayload adds iss/aud/exp/iat
        // from its own parameters; auth_time and amr are added as native JSON values below.
        var payloadClaims = new List<Claim>
        {
            new(IdentityConstants.ClaimSubject, descriptor.AccountId.ToString("D")),
            new(JwtRegisteredClaimNames.Sid, descriptor.SessionId.ToString("D"))
        };

        // PS-15: only the initial exchange carries the nonce; the refresh variant omits the
        // claim entirely rather than emitting an empty value.
        if (descriptor.Nonce is not null)
        {
            payloadClaims.Add(new Claim(JwtRegisteredClaimNames.Nonce, descriptor.Nonce));
        }

        // PS-12: name is the bound Password username and nickname is the current account nickname
        // — a different source than the access token's display-name resolution — and both appear
        // only when profile was granted.
        if (SplitCanonicalScope(descriptor.Scope).Contains(OidcScopeValidator.Profile))
        {
            if (!string.IsNullOrEmpty(descriptor.PasswordUsername))
            {
                payloadClaims.Add(new Claim(IdentityConstants.ClaimName, descriptor.PasswordUsername));
            }

            if (!string.IsNullOrEmpty(descriptor.Nickname))
            {
                payloadClaims.Add(new Claim(IdentityConstants.ClaimNickname, descriptor.Nickname));
            }
        }

        var payload = new JwtPayload(
            issuer: _jwtOptions.Issuer,
            // OIDC Core §2: the ID-token audience is the client itself, one string, distinct in
            // meaning from the access token's application resource audience (PS-12/PS-13).
            audience: descriptor.ClientId,
            claims: payloadClaims,
            notBefore: null,
            expires: expiresAt.UtcDateTime,
            issuedAt: now.UtcDateTime);

        // RFC 8176 values must serialize as a JSON array and auth_time as a JSON number; claim
        // strings would serialize as JSON strings, so the native values go on the payload directly.
        payload.Add(JwtRegisteredClaimNames.Amr, new[] { PasswordAmrValue });
        payload.Add(JwtRegisteredClaimNames.AuthTime, descriptor.AuthTime.ToUnixTimeSeconds());

        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);
        var header = new JwtHeader(credentials)
        {
            // OIDC Core §2 ID tokens carry typ JWT; the access token's at+jwt is deliberately not
            // reused so a validator can never accept one kind as the other (PS-12/PS-13).
            [JwtHeaderParameterNames.Typ] = "JWT"
        };
        var token = new JwtSecurityToken(header, payload);

        var serialized = new JwtSecurityTokenHandler().WriteToken(token);
        if (serialized.Length > IdentityConstants.InteractiveTokenMaxSerializedLength)
        {
            return new InteractiveIdTokenResult.ExceedsMaximumLength();
        }

        return new InteractiveIdTokenResult.Issued(serialized, expiresAt);
    }

    /// <summary>
    /// The single canonical-form judgement: the shared requested-scope validator over the full
    /// interactive vocabulary must accept the value and its canonical output must equal the input
    /// byte for byte — <c>openid</c> present, unique members, only the three supported values, in
    /// the fixed <c>openid profile offline_access</c> order.
    /// </summary>
    private static bool IsCanonicalInteractiveScope(string? scope) =>
        OidcScopeValidator.TryValidateRequested(
            scope,
            InteractiveScopeVocabulary,
            allowRefreshToken: true,
            out var canonicalScope)
        && string.Equals(canonicalScope, scope, StringComparison.Ordinal);

    private static string[] SplitCanonicalScope(string scopeSnapshot) =>
        scopeSnapshot.Split(' ', StringSplitOptions.RemoveEmptyEntries);
}
