namespace SignaCore.ReferenceBff;

/// <summary>
/// The complete configuration model of the reference BFF. Every member is required; the options
/// validation runs at startup so the sample never starts silently against an incomplete
/// configuration. Secrets arrive through the environment or user secrets — never through the
/// committed <c>appsettings.json</c>, which carries placeholders only.
/// </summary>
public sealed class ReferenceBffOptions
{
    public const string SectionName = "ReferenceBff";

    /// <summary>The SignaCore base address; authorization, token, and JWKS endpoints are resolved
    /// from its Discovery document and are never hardcoded.</summary>
    public string? Authority { get; set; }

    /// <summary>The registered client id of this BFF.</summary>
    public string? ClientId { get; set; }

    /// <summary>The client secret, injected through configuration providers (environment or user
    /// secrets). The sample never logs or renders it.</summary>
    public string? ClientSecret { get; set; }

    /// <summary>The redirect URI registered with SignaCore; must route to the OIDC callback
    /// path of this host.</summary>
    public string? RedirectUri { get; set; }

    /// <summary>The scope string of the login; <c>openid</c> at minimum.</summary>
    public string Scope { get; set; } = "openid profile";
}
