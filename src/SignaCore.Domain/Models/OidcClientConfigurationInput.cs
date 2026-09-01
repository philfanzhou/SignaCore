namespace SignaCore.Domain.Models;

/// <summary>
/// The complete interactive OIDC configuration an application should end up with.
/// <para>
/// Both entry points bind to this one shape: the administration API builds it from the current row
/// plus the requested change, and <c>bootstrap-apps.json</c> deserializes its optional interactive
/// section straight into it. Keeping one shape is what makes "the same configuration is accepted or
/// rejected identically through either path" a property of the code rather than of two hand-kept
/// copies.
/// </para>
/// <para>
/// It is a complete target state, not a patch: a caller passes every value the application should
/// have afterwards. The one exception is <see cref="AudienceMode"/>, which is <c>null</c> when the
/// caller is not changing the application's audience.
/// </para>
/// <para>
/// The enum-valued members are strings so an unknown value produces the same closed-set English
/// rejection on both paths instead of a model-binder failure on one and a JSON exception on the
/// other.
/// </para>
/// </summary>
public sealed class OidcClientConfigurationInput
{
    /// <summary>
    /// <c>Confidential</c> or <c>Public</c>. Null or empty means <c>Confidential</c>, which is the
    /// fail-closed upgrade default; <c>Public</c> is reserved and cannot hold any capability.
    /// </summary>
    public string? ClientType { get; set; }

    public bool AllowAuthorizationCode { get; set; }

    /// <summary>Null means the mandatory minimum, <c>openid</c> alone.</summary>
    public IReadOnlyList<string>? AllowedScopes { get; set; }

    public bool AllowRefreshToken { get; set; }

    /// <summary>Null means no application-specific cap.</summary>
    public int? IdentitySessionMaxAgeSeconds { get; set; }

    /// <summary>
    /// <c>Shared</c> or <c>PerApplication</c>. Null keeps the application's current audience mode.
    /// Enabling the code flow requires <c>PerApplication</c>, but that is a validation result rather
    /// than an implicit change made here.
    /// </summary>
    public string? AudienceMode { get; set; }

    /// <summary>Null means no browser redirect registrations.</summary>
    public IReadOnlyList<string>? RedirectUris { get; set; }

    /// <summary>Null means no post-logout registrations.</summary>
    public IReadOnlyList<string>? PostLogoutRedirectUris { get; set; }
}
