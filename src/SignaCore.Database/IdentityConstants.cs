namespace SignaCore.Database;

public static class IdentityConstants
{
    public const int BCryptWorkFactor = 11;

    public const int MaxFailedLoginAttempts = 5;
    public const int LoginLockoutMinutes = 15;

    public const int CallbackTimeoutSeconds = 2;

    public const int KeyRotationDays = 30;

    // HKDF 派生参数。名字标出各自在 HKDF.DeriveKey(hash, ikm, len, salt, info) 里的位置——
    // 之前叫 MasterKeyInfo 的那个其实传在 salt 位上。
    // 这些字面值参与密钥派生，改值会导致存量 RSA 私钥无法解密，只能改名不能改值。
    public const string MasterKeyHkdfSalt = "SignaCore.KeyProtection";
    public const string MasterKeyHkdfInfo = "RSA-Private-Key-Encryption";
    public const string PrivateKeyHkdfInfo = "RSA-Private-Key-Encrypt";

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

    // 签发的 JWT 一律用标准短名，不用 .NET 的 ClaimTypes.* 长 URI。
    // JwtTokenService 直接构造 JwtPayload，不走 JwtSecurityTokenHandler.CreateToken，
    // 因此出站短名映射不会发生——claim 写成什么，token 里就是什么。
    // 长 URI 只有 .NET 下游（且开着 MapInboundClaims）能无感消费，非 .NET 下游会踩坑。
    public const string ClaimSubject = "sub";
    public const string ClaimName = "name";
    public const string ClaimRole = "role";
    public const string ClaimNickname = "nickname";

    public const int MaxUsernameLength = 100;
    public const int MaxPasswordHashLength = 256;
    public const int MaxAppIdLength = 100;
    public const int MaxAppSecretLength = 256;
    public const int MaxCallbackUrlLength = 500;
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
