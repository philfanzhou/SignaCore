namespace SignaCore.Database.Entity;

/// <summary>
/// One global application setting. The business database is the configuration authority, so every
/// instance reads the same rows and there is no per-instance configuration drift.
/// <para>
/// <see cref="Key"/> uses the ASP.NET Core colon-separated name (for example
/// <c>Endpoints:PublicBaseUrl</c>) so the loader can hand values straight to
/// <c>IConfiguration</c>. Secret values are stored encrypted; see <see cref="IsSecret"/>.
/// </para>
/// </summary>
public sealed class SystemSettingEntity
{
    public string Key { get; set; } = string.Empty;

    /// <summary>
    /// Invariant string form for scalars, canonical JSON for structured values, or the encrypted
    /// envelope produced by the configuration protector when <see cref="IsSecret"/> is true.
    /// </summary>
    public string Value { get; set; } = string.Empty;

    /// <summary>One of <see cref="SettingValueTypes"/>.</summary>
    public string ValueType { get; set; } = SettingValueTypes.String;

    /// <summary>
    /// True when <see cref="Value"/> holds an encrypted envelope. Secret values are never returned
    /// from general settings-list APIs.
    /// </summary>
    public bool IsSecret { get; set; }

    /// <summary>Configuration version this row was written under.</summary>
    public int Version { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public string? UpdatedBy { get; set; }
}
