using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SignaCore.Database;
using SignaCore.Domain.Validators;

namespace SignaCore.Domain.Services;

/// <summary>
/// The validated server-side inputs of one interactive access token (<c>PS-13</c>). Every field is
/// a value the calling transaction already resolved and verified — the account, the interactive
/// client (whose AppId is the token audience), the live identity session, the session's auth
/// method, the canonical granted scope, the resolved display name and nickname, and the ordered
/// callback/bootstrap enrichment claims. The PKCE verifier, the nonce, and the code are never
/// part of this shape.
/// </summary>
public sealed record InteractiveAccessTokenDescriptor(
    Guid AccountId,
    string ClientId,
    Guid SessionId,
    string AuthMethod,
    string Scope,
    string? DisplayName,
    string? Nickname,
    IReadOnlyList<Claim> EnrichmentClaims);

/// <summary>
/// The unique two-way outcome of <see cref="IInteractiveAccessTokenFactory.Create"/>: either the
/// issued token with its id and expiry, or the single failure <see cref="ExceedsMaximumLength"/>.
/// The failure shape carries no token fragment, no claim value, and no length — it states only
/// that issuance was refused before anything was released (<c>DF-07</c>).
/// </summary>
public abstract record InteractiveAccessTokenResult
{
    private InteractiveAccessTokenResult()
    {
    }

    /// <summary>
    /// The serialized compact JWS, its <c>jti</c> as <see cref="TokenId"/>, and the
    /// <see cref="ExpiresAt"/> instant the <c>exp</c> claim carries (Unix-second precision). The
    /// token bytes exist only in this return value and must be released only after the caller's
    /// issuance transaction commits (<c>PS-09</c>).
    /// </summary>
    public sealed record Issued(
        string AccessToken,
        Guid TokenId,
        DateTimeOffset ExpiresAt) : InteractiveAccessTokenResult;

    /// <summary>
    /// The serialized token would exceed
    /// <see cref="IdentityConstants.InteractiveTokenMaxSerializedLength"/>; nothing was issued.
    /// </summary>
    public sealed record ExceedsMaximumLength : InteractiveAccessTokenResult;
}

/// <summary>
/// The standalone constructor of the interactive Authorization Code flow access token
/// (<c>PS-13</c>, RFC 9068 profile): a pure, stateless, synchronous function over its validated
/// inputs with no I/O and no persisted token row (<c>PS-09</c>). The existing
/// <see cref="JwtTokenService"/> of the current grants stays byte-for-byte untouched; this factory
/// is the only place the interactive header, the claim set, and the reserved-claim policy exist.
/// </summary>
public interface IInteractiveAccessTokenFactory
{
    /// <summary>
    /// Creates one interactive access token signed with <paramref name="signingKey"/> under the
    /// caller-captured instant <paramref name="now"/> (<c>PS-22</c>): header exactly
    /// <c>alg: RS256</c>, <c>kid</c>, <c>typ: at+jwt</c>; audience always the application AppId,
    /// never the deployment-wide shared audience; a fixed 15-minute lifetime; a fresh
    /// <c>jti</c>; and the enrichment claims appended in input order after every reserved claim
    /// type was dropped. The only failure is the serialized-length bound; precondition violations
    /// are programming errors and throw.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// An empty id, client, auth method, or key id, or a non-canonical scope. The message never
    /// carries an input value.
    /// </exception>
    InteractiveAccessTokenResult Create(
        InteractiveAccessTokenDescriptor descriptor,
        RsaSecurityKey signingKey,
        DateTimeOffset now);
}

/// <inheritdoc cref="IInteractiveAccessTokenFactory"/>
public sealed class InteractiveAccessTokenFactory : IInteractiveAccessTokenFactory
{
    /// <summary>
    /// The closed reserved-claim set of <c>PS-13</c>: binding claims only this constructor writes,
    /// each exactly once. Enrichment claims of any of these types (case-insensitive) are dropped
    /// as defense in depth — the current callback whitelist cannot produce them — and only the
    /// dropped count is logged, never a type or a value.
    /// </summary>
    private static readonly HashSet<string> ReservedClaimTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
        "client_id", "scope", "sid", "auth_method", "typ",
        "name", "nickname", "nonce", "auth_time", "amr", "azp", "acr"
    };

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
    private readonly ILogger<InteractiveAccessTokenFactory> _logger;

    public InteractiveAccessTokenFactory(
        JwtOptions jwtOptions,
        ILogger<InteractiveAccessTokenFactory> logger)
    {
        _jwtOptions = jwtOptions;
        _logger = logger;
    }

    public InteractiveAccessTokenResult Create(
        InteractiveAccessTokenDescriptor descriptor,
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

        if (string.IsNullOrEmpty(descriptor.AuthMethod))
        {
            throw new ArgumentException(
                "The auth method must not be empty.", nameof(descriptor));
        }

        if (string.IsNullOrEmpty(signingKey.KeyId))
        {
            throw new ArgumentException(
                "The signing key id must not be empty.", nameof(signingKey));
        }

        if (!IsCanonicalInteractiveScope(descriptor.Scope))
        {
            throw new ArgumentException(
                "The scope must be the canonical interactive scope value.", nameof(descriptor));
        }

        var tokenId = Guid.NewGuid();
        var issuedAtSeconds = now.ToUnixTimeSeconds();
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(
            issuedAtSeconds + IdentityConstants.InteractiveAccessTokenLifetimeSeconds);

        // The bound claims first, then the optional basic claims, then the surviving enrichment
        // in input order. JwtPayload adds iss/aud/nbf/exp/iat from its own parameters, so no
        // reserved type may reach the claim list twice.
        var payloadClaims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Jti, tokenId.ToString("D")),
            new(IdentityConstants.ClaimSubject, descriptor.AccountId.ToString("D")),
            new(IdentityConstants.ClaimClientId, descriptor.ClientId),
            new(JwtRegisteredClaimNames.Sid, descriptor.SessionId.ToString("D")),
            new(IdentityConstants.ClaimAuthMethod, descriptor.AuthMethod),
            new("scope", descriptor.Scope)
        };
        if (!string.IsNullOrEmpty(descriptor.DisplayName))
        {
            payloadClaims.Add(new Claim(IdentityConstants.ClaimName, descriptor.DisplayName));
        }

        if (!string.IsNullOrEmpty(descriptor.Nickname))
        {
            payloadClaims.Add(new Claim(IdentityConstants.ClaimNickname, descriptor.Nickname));
        }

        var droppedCount = 0;
        foreach (var claim in descriptor.EnrichmentClaims)
        {
            ArgumentNullException.ThrowIfNull(claim);
            if (ReservedClaimTypes.Contains(claim.Type))
            {
                droppedCount++;
                continue;
            }

            payloadClaims.Add(claim);
        }

        if (droppedCount > 0)
        {
            // Defense in depth against a reserved-claim injection: the count is an aggregate,
            // never a claim type or value (DF-07/DF-11 discipline).
            _logger.LogWarning(
                "Dropped {DroppedCount} reserved enrichment claims while creating an interactive access token.",
                droppedCount);
        }

        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);
        var header = new JwtHeader(credentials)
        {
            [JwtHeaderParameterNames.Typ] = JwtTokenService.AccessTokenType
        };
        var token = new JwtSecurityToken(
            header,
            new JwtPayload(
                issuer: _jwtOptions.Issuer,
                // The interactive flow requires PerApplication, so the AppId is the audience and
                // there is deliberately no fallback to the deployment-wide shared audience.
                audience: descriptor.ClientId,
                claims: payloadClaims,
                notBefore: now.UtcDateTime,
                expires: expiresAt.UtcDateTime,
                issuedAt: now.UtcDateTime));

        var serialized = new JwtSecurityTokenHandler().WriteToken(token);
        if (serialized.Length > IdentityConstants.InteractiveTokenMaxSerializedLength)
        {
            return new InteractiveAccessTokenResult.ExceedsMaximumLength();
        }

        return new InteractiveAccessTokenResult.Issued(serialized, tokenId, expiresAt);
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
}
