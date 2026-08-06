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

    public string CallbackUrl { get; set; } = string.Empty;
}
