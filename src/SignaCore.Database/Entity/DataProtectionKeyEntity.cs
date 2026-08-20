namespace SignaCore.Database.Entity;

/// <summary>
/// Shared ASP.NET Core Data Protection key-ring entry. <see cref="ProtectedXml"/> is encrypted by
/// the deployment root key before it reaches the database.
/// </summary>
public sealed class DataProtectionKeyEntity
{
    public Guid Id { get; set; }

    public string FriendlyName { get; set; } = string.Empty;

    public string ProtectedXml { get; set; } = string.Empty;
}
