namespace SignaCore.Database.Entity;

/// <summary>
/// Storage forms for <see cref="SystemSettingEntity.Value"/>. Persisted as strings so a new form can
/// be added without a schema migration.
/// </summary>
public static class SettingValueTypes
{
    public const string String = "String";
    public const string Number = "Number";
    public const string Boolean = "Boolean";

    /// <summary>
    /// Canonical JSON. The loader flattens the document into ASP.NET Core configuration keys so
    /// structured settings behave exactly like their appsettings.json equivalents.
    /// </summary>
    public const string Json = "Json";

    public static bool IsSupported(string valueType) =>
        valueType is String or Number or Boolean or Json;
}
