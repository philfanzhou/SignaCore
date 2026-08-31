namespace SignaCore.Database.Entity;

/// <summary>
/// Business service registration for dynamic callback-based permission injection.
/// Business services register AppId/AppSecret and callback URL at startup.
/// Identity calls back to fetch user permissions and inject them into the JWT.
/// </summary>
public class AppRegistrationEntity
{
    public Guid Id { get; set; }

    /// <summary>Unique identifier for the business service.</summary>
    public string AppId { get; set; } = string.Empty;
    public string AppIdNormalized { get; set; } = string.Empty;

    /// <summary>BCrypt hash of AppSecret. Used for validation.</summary>
    public string AppSecretHash { get; set; } = string.Empty;

    /// <summary>Display name of the business service (e.g., "OrderService", "StudySystem").</summary>
    public string AppName { get; set; } = string.Empty;

    /// <summary>Callback URL. Identity calls this after login to fetch user permissions.</summary>
    public string? CallbackUrl { get; set; }

    /// <summary>Whether this registration is active.</summary>
    public bool IsActive { get; set; } = true;

    /// <summary>When this registration was created.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>When the callback registration expires.</summary>
    public DateTimeOffset? CallbackExpiresAt { get; set; }

    /// <summary>LDAP admission policy for this application. Disabled by default.</summary>
    public LdapLoginMode LdapLoginMode { get; set; } = LdapLoginMode.Disabled;

    /// <summary>SMS admission policy for this application. Disabled by default.</summary>
    public SmsLoginMode SmsLoginMode { get; set; } = SmsLoginMode.Disabled;

    /// <summary>Name of the deployment-managed SMS provider profile.</summary>
    public string? SmsProfileKey { get; set; }

    /// <summary>WeChat admission policy for this application. Disabled by default.</summary>
    public WechatLoginMode WechatLoginMode { get; set; } = WechatLoginMode.Disabled;

    /// <summary>
    /// Audience placed in access tokens issued to this application. Defaults to
    /// <see cref="AudienceMode.Shared"/> so existing downstream validators keep working.
    /// </summary>
    public AudienceMode AudienceMode { get; set; } = AudienceMode.Shared;

    /// <summary>Interactive OIDC client type. Public clients remain reserved and fail closed.</summary>
    public OidcClientType ClientType { get; set; } = OidcClientType.Confidential;

    /// <summary>Whether the interactive Authorization Code flow is enabled.</summary>
    public bool AllowAuthorizationCode { get; set; }

    /// <summary>Canonical, space-delimited interactive OIDC scope allow list.</summary>
    public string AllowedScopes { get; set; } = "openid";

    /// <summary>Whether future interactive refresh-token issuance is allowed.</summary>
    public bool AllowRefreshToken { get; set; }

    /// <summary>Optional application-specific identity-session maximum age in seconds.</summary>
    public int? IdentitySessionMaxAgeSeconds { get; set; }

    /// <summary>Browser redirect registrations, kept separate from the claims callback.</summary>
    public ICollection<AppRedirectUriEntity> RedirectUris { get; set; } = [];
}
