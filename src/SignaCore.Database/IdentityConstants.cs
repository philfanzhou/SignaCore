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
    public const int MaxIdentitySessionAgeSeconds = 12 * 60 * 60;
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
    public const int MaxSetupCodeHashLength = 128;

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
