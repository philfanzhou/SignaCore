namespace SignaCore.Database.Entity;

/// <summary>
/// Singleton row that records whether this database has been initialized.
/// <para>
/// First-run status is never inferred from missing configuration keys: deleting settings from a
/// previously initialized production database must not reopen anonymous setup and allow account
/// takeover. The <see cref="InstallationStatus.Completed"/> marker is durable.
/// </para>
/// </summary>
public sealed class InstallationStateEntity
{
    /// <summary>Fixed singleton identifier.</summary>
    public const int SingletonId = 1;

    public int Id { get; set; } = SingletonId;

    public InstallationStatus Status { get; set; }

    public Guid InstallationId { get; set; }

    /// <summary>One-way hash of the one-time setup code. Cleared when installation completes.</summary>
    public string? SetupCodeHash { get; set; }

    public DateTimeOffset? SetupCodeExpiresAt { get; set; }

    public DateTimeOffset? CompletedAt { get; set; }

    /// <summary>Incremented whenever the active settings snapshot changes.</summary>
    public int ConfigurationVersion { get; set; }
}
