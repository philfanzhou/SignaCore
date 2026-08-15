namespace SignaCore.Database.Entity;

public enum InstallationStatus
{
    /// <summary>The database exists and is migrated, but first-run setup has not been completed.</summary>
    Pending = 0,

    /// <summary>First-run setup completed. This value is durable and is never reset automatically.</summary>
    Completed = 1
}
