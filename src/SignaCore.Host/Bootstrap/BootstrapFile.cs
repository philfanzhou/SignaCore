using System.Text.Json.Serialization;

namespace SignaCore.Host.Bootstrap;

/// <summary>
/// On-disk schema of <c>config/signacore.bootstrap.json</c>.
/// <para>
/// The bootstrap deliberately carries only what is required to open and decrypt the business
/// database. Everything else — public URL, JWT settings, administrator credentials, SMS/WeChat/LDAP
/// settings, observability settings — lives in <c>system_settings</c> inside that database.
/// </para>
/// <para>
/// The master key is stored inline, which makes the whole file a secret: it must live on persistent
/// storage owned by the SignaCore runtime identity, with mode <c>0600</c> on Unix-like hosts, and it
/// must be backed up together with the business database.
/// </para>
/// </summary>
internal sealed class BootstrapFile
{
    [JsonPropertyName("Database")]
    public BootstrapDatabaseSection? Database { get; set; }

    /// <summary>The external root key. Required, inline, and never returned by any API.</summary>
    [JsonPropertyName("MasterKey")]
    public string? MasterKey { get; set; }
}

internal sealed class BootstrapDatabaseSection
{
    [JsonPropertyName("Provider")]
    public string? Provider { get; set; }

    [JsonPropertyName("ServerVersion")]
    public string? ServerVersion { get; set; }

    [JsonPropertyName("ConnectionString")]
    public string? ConnectionString { get; set; }
}
