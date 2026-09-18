namespace SignaCore.Database;

public static class IdentityConstants
{
    public const int BCryptWorkFactor = 11;

    public const int MaxFailedLoginAttempts = 5;
    public const int LoginLockoutMinutes = 15;

    public const int CallbackTimeoutSeconds = 2;

    public const int KeyRotationDays = 30;

    // HKDF derivation parameters. Each name states which position it occupies in
    // HKDF.DeriveKey(hash, ikm, len, salt, info) — the one that used to be called MasterKeyInfo is
    // in fact passed in the salt position.
    // These literals take part in key derivation. Changing a value makes stored RSA private keys
    // undecryptable, so they may be renamed but their values must never change.
    public const string MasterKeyHkdfSalt = "SignaCore.KeyProtection";
    public const string MasterKeyHkdfInfo = "RSA-Private-Key-Encryption";
    public const string PrivateKeyHkdfInfo = "RSA-Private-Key-Encrypt";

    /// <summary>
    /// HKDF info for the configuration-protection key. It is deliberately distinct from
    /// <see cref="PrivateKeyHkdfInfo"/> so the same root secret protects signing keys and settings
    /// with separate derived keys. Changing this value orphans every stored secret setting.
    /// </summary>
    public const string ConfigurationProtectionHkdfInfo = "Configuration-Setting-Encryption";

    /// <summary>
    /// Schema version bound as authenticated associated data into every protected setting. Bump it
    /// only together with a deliberate re-encryption migration.
    /// </summary>
    public const int ConfigurationProtectionSchemaVersion = 1;

    public const int CleanupIntervalHours = 24;

    public const string GrantTypePassword = "password";
    public const string GrantTypeSms = "sms";
    public const string GrantTypeWechat = "wechat_code";
    public const string GrantTypeRefreshToken = "refresh_token";
    public const string GrantTypeLdap = "ldap";

    public const string AuthMethodPassword = "Password";
    public const string AuthMethodSms = "Sms";
    public const string AuthMethodWechat = "WeChat";
    public const string AuthMethodRefreshToken = "RefreshToken";
    public const string AuthMethodLdap = "LDAP";

    public const string ClaimPermission = "Permission";
    public const string ClaimAuthMethod = "auth_method";
    public const string ClaimClientId = "client_id";

    // Issued JWTs always use the standard short names, never .NET's long ClaimTypes.* URIs.
    // JwtTokenService builds the JwtPayload directly instead of going through
    // JwtSecurityTokenHandler.CreateToken, so no outbound short-name mapping happens — a claim
    // reaches the token exactly as it is written here.
    // The long URIs are only transparent to .NET consumers with MapInboundClaims enabled; a
    // non-.NET consumer would trip over them.
    public const string ClaimSubject = "sub";
    public const string ClaimName = "name";
    public const string ClaimRole = "role";
    public const string ClaimNickname = "nickname";

    public const int MaxUsernameLength = 100;
    public const int MaxPasswordHashLength = 256;
    public const int MaxAppIdLength = 100;
    public const int MaxAppSecretLength = 256;
    public const int MaxCallbackUrlLength = 500;
    public const int MaxOidcRedirectUriLength = 500;
    public const int MaxOidcCanonicalRedirectUriLength = MaxOidcRedirectUriLength + 1;
    public const int MaxOidcRedirectUrisPerKind = 10;
    public const int MaxOidcAllowedScopesLength = 32;
    public const int MaxOidcOpaqueValueLength = 128;
    public const int MaxOidcCodeChallengeLength = 43;
    public const int LoginHandleLength = 43;
    public const int LoginHandleLifetimeMinutes = 10;
    public const int AuthorizationRequestRetentionHours = 24;
    public const int AuthorizationCodeLength = 43;
    public const int AuthorizationCodeLifetimeSeconds = 60;
    public const int AuthorizationCodeRetentionHours = 24;
    public const int MaxIdentitySessionAgeSeconds = 12 * 60 * 60;
    public const int IdentitySessionIdleTimeoutMinutes = 30;
    public const int IdentitySessionActivityThresholdMinutes = 1;
    public const int IdentitySessionRetentionHours = 24;
    public const int MaxIdentitySessionRevocationReasonLength = 32;

    public const int LogoutHandleLength = 43;
    public const int LogoutHandleLifetimeMinutes = 5;
    public const int LogoutRequestRetentionHours = 24;

    /// <summary>The <c>IN-31</c> bound of the prepared-logout <c>id_token_hint</c> in ASCII characters.</summary>
    public const int MaxLogoutIdTokenHintLength = 8192;

    /// <summary>The <c>IN-33</c> bounds of the prepared-logout <c>state</c> in ASCII characters.</summary>
    public const int MinLogoutStateLength = 22;
    public const int MaxLogoutStateLength = 128;

    /// <summary>
    /// The <c>IN-31</c> logout-hint key window: an ID token signed by a key that expired within
    /// this many hours still validates for logout preparation (only), because an ID token's short
    /// lifetime means a recently retired key may legitimately have signed it.
    /// </summary>
    public const int LogoutHintRetiredKeyHours = 24;

    /// <summary>
    /// The <c>IN-31</c> logout-hint freshness bound: the presented ID token's <c>iat</c> may be
    /// at most this many hours old. Only <c>exp</c> is ignored for this check, never this bound.
    /// </summary>
    public const int LogoutHintMaximumAgeHours = 24;

    /// <summary>
    /// The fixed 15-minute lifetime of the interactive Authorization Code flow access token
    /// (<c>PS-13</c>); it never reads <see cref="JwtOptions.TokenExpirationHours"/>.
    /// </summary>
    public const int InteractiveAccessTokenLifetimeSeconds = 900;

    /// <summary>
    /// The fixed 5-minute lifetime of the interactive Authorization Code flow ID token
    /// (<c>PS-12</c>); an ID token is an authentication statement, not a bearer credential,
    /// so it outlives the code exchange only briefly.
    /// </summary>
    public const int InteractiveIdTokenLifetimeSeconds = 300;

    /// <summary>
    /// The bound on the serialized compact JWS of an interactive access token (<c>PS-13</c>).
    /// A longer token fails issuance before anything commits; it is never truncated or issued.
    /// </summary>
    public const int InteractiveTokenMaxSerializedLength = 8192;

    /// <summary>
    /// The fixed cap of an interactive refresh family's deadline (<c>EV-21</c>): a root row's
    /// <c>expires_at</c> is exactly this many days after creation. The family is still never
    /// usable beyond its identity session — that bound is enforced by the live-family predicate
    /// at use time (<c>EV-32</c>), never by taking a minimum into the column.
    /// </summary>
    public const int InteractiveRefreshFamilyLifetimeDays = 7;
    public const int MaxRemarkLength = 500;
    public const int MaxNicknameLength = 100;
    public const int MaxKeyNameLength = 100;
    public const int MaxProviderNameLength = 100;
    public const int MaxProviderUserIdLength = 256;
    public const int MaxDirectoryKeyLength = 64;
    public const int MaxRefreshTokenLength = 256;
    public const int MaxAppNameLength = 200;
    public const int MaxPublicKeyModulusLength = 2048;
    public const int MaxEncryptedKeyLength = 4096;
    public const int MaxEncryptionSaltLength = 256;
    public const int MaxSettingKeyLength = 200;
    public const int MaxSettingValueTypeLength = 32;

    public const int DefaultCallbackTtlSeconds = 3600;

    public const int CallbackTtlNeverExpire = -1;

    public const int MaxClientIpLength = 64;
    public const int MaxAuthMethodLength = 50;
    public const int MaxEventTypeLength = 50;
    public const int MaxUserAgentLength = 512;
    public const int MaxFailureReasonLength = 500;
    public const int MaxAuditActionLength = 100;
    public const int MaxAuditTargetTypeLength = 100;
    public const int MaxAuditDescriptionLength = 1000;
    public const int MaxSnapshotLength = 4096;

    public const int LoginHistoryRetentionDays = 90;
    public const int AuditLogRetentionDays = 365;
}
