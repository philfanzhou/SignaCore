namespace SignaCore.Host.Configuration;

/// <summary>
/// Describes one setting owned by <c>system_settings</c>.
/// </summary>
/// <param name="Key">ASP.NET Core configuration key, for example <c>Jwt:Audience</c>.</param>
/// <param name="ValueType">One of <see cref="SignaCore.Database.Entity.SettingValueTypes"/>.</param>
/// <param name="IsSecret">Stored encrypted and never returned from settings-list APIs.</param>
/// <param name="DefaultValue">
/// Safe product default used to seed a new installation. <c>null</c> means the value has no default
/// and must be supplied — currently only the canonical public base URL and the issuer derived from
/// it, both collected by first-run setup.
/// </param>
/// <param name="RestartRequired">
/// True while the owning subsystem has no explicit reload support. Every setting starts here; a
/// subsystem is moved out of this class only once it can rebuild itself safely.
/// </param>
internal sealed record SystemSettingDefinition(
    string Key,
    string ValueType,
    bool IsSecret,
    string? DefaultValue,
    bool RestartRequired = true)
{
    public bool HasDefault => DefaultValue is not null;
}
