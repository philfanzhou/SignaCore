using SignaCore.Domain.Models;

namespace SignaCore.Host;

public sealed class BootstrapAppsOptions
{
    public const string SectionName = "BootstrapApps";

    public string FilePath { get; set; } = "/app/data/bootstrap-apps.json";

    public List<BootstrapAppEntry> Apps { get; set; } = new();
}

public sealed class BootstrapAppEntry
{
    public string AppId { get; set; } = string.Empty;

    public string AppSecret { get; set; } = string.Empty;

    public string AppName { get; set; } = string.Empty;

    /// <summary>
    /// Server-to-server claims callback. It is not a browser redirect registration and is never
    /// copied into <see cref="Oidc"/>.
    /// </summary>
    public string CallbackUrl { get; set; } = string.Empty;

    /// <summary>
    /// Optional interactive OIDC configuration. Omitting it leaves the application fail closed with
    /// the upgrade defaults, which is what every file written before this section existed does.
    /// <para>
    /// The section binds directly to the domain input type, so the pre-seed carries no mapping or
    /// validation rules of its own and cannot drift from the administration API.
    /// </para>
    /// </summary>
    public OidcClientConfigurationInput? Oidc { get; set; }
}
