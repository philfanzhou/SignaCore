using System.Text.Json.Serialization;

namespace SignaCore.Host.Models;

/// <summary>
/// Database fields of the bootstrap form. Either the structured fields or
/// <see cref="ConnectionString"/> is supplied; the complete connection string wins when both are.
/// </summary>
public sealed class BootstrapDatabaseRequest
{
    [JsonPropertyName("provider")]
    public string Provider { get; set; } = string.Empty;

    /// <summary>Required for every provider except SQLite, which has no server version.</summary>
    [JsonPropertyName("serverVersion")]
    public string? ServerVersion { get; set; }

    [JsonPropertyName("host")]
    public string? Host { get; set; }

    [JsonPropertyName("port")]
    public int? Port { get; set; }

    [JsonPropertyName("database")]
    public string? Database { get; set; }

    [JsonPropertyName("username")]
    public string? Username { get; set; }

    /// <summary>Write-only. It is never returned by any endpoint.</summary>
    [JsonPropertyName("password")]
    public string? Password { get; set; }

    /// <summary>SQLite database file path.</summary>
    [JsonPropertyName("filePath")]
    public string? FilePath { get; set; }

    /// <summary>Advanced escape hatch for options the structured fields do not model.</summary>
    [JsonPropertyName("connectionString")]
    public string? ConnectionString { get; set; }
}

/// <summary>Probe a candidate database without writing anything.</summary>
public sealed class BootstrapTestRequest
{
    [JsonPropertyName("database")]
    public BootstrapDatabaseRequest Database { get; set; } = new();

    /// <summary>
    /// Optional existing master key. Supplying it is what turns "there is protected data here" into
    /// "the key you hold can read it".
    /// </summary>
    [JsonPropertyName("masterKey")]
    public string? MasterKey { get; set; }

    [JsonPropertyName("bootstrapCode")]
    public string BootstrapCode { get; set; } = string.Empty;
}

public sealed class BootstrapTestResponse
{
    /// <summary>
    /// <c>unreachable</c>, <c>empty</c>, <c>pending_installation</c>, <c>completed_installation</c>,
    /// or <c>legacy_data</c>.
    /// </summary>
    [JsonPropertyName("target")]
    public string Target { get; set; } = string.Empty;

    /// <summary>Host and database name only — never credentials or the full connection string.</summary>
    [JsonPropertyName("endpoint")]
    public string Endpoint { get; set; } = string.Empty;

    [JsonPropertyName("canConnect")]
    public bool CanConnect { get; set; }

    [JsonPropertyName("hasProtectedData")]
    public bool HasProtectedData { get; set; }

    /// <summary><c>not_applicable</c>, <c>compatible</c>, or <c>incompatible</c>.</summary>
    [JsonPropertyName("masterKey")]
    public string MasterKey { get; set; } = string.Empty;

    [JsonPropertyName("installationId")]
    public string? InstallationId { get; set; }

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;
}

/// <summary>
/// What an authenticated operator may see about the bootstrap of the instance that served the
/// request. Neither the connection string, its password, nor the master key is included.
/// </summary>
public sealed class BootstrapSettingsResponse
{
    [JsonPropertyName("provider")]
    public string Provider { get; set; } = string.Empty;

    [JsonPropertyName("serverVersion")]
    public string? ServerVersion { get; set; }

    [JsonPropertyName("endpoint")]
    public string Endpoint { get; set; } = string.Empty;

    [JsonPropertyName("filePath")]
    public string FilePath { get; set; } = string.Empty;

    /// <summary>Always true for a running installation; the value itself is never disclosed.</summary>
    [JsonPropertyName("masterKeyConfigured")]
    public bool MasterKeyConfigured { get; set; }

    /// <summary>False when this process loaded its bootstrap from somewhere other than the file.</summary>
    [JsonPropertyName("editable")]
    public bool Editable { get; set; }

    [JsonPropertyName("singleInstanceOnly")]
    public bool SingleInstanceOnly { get; set; }

    /// <summary>States plainly that a write here changes one instance, not the cluster.</summary>
    [JsonPropertyName("scopeNotice")]
    public string ScopeNotice { get; set; } = string.Empty;
}
