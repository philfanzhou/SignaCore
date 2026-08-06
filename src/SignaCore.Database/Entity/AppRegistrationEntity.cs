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
}
