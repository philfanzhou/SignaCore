namespace SignaCore.ReferenceBff.Database;

/// <summary>
/// The reference BFF's own single initial-administrator binding slot. The row is deliberately the
/// only persisted shape of this sample slice: multi-administrator support, role CRUD, and any
/// general permission model are explicit non-goals.
/// </summary>
public sealed class ManagementRoleBindingEntity
{
    /// <summary>The only role value this sample persists; the database CHECK pins the same literal.</summary>
    public const string SystemAdministratorRole = "system-administrator";

    /// <summary>Surrogate key of the binding row.</summary>
    public Guid Id { get; set; }

    /// <summary>Always <see cref="SystemAdministratorRole"/>; the unique index makes it a single slot.</summary>
    public string Role { get; set; } = SystemAdministratorRole;

    /// <summary>
    /// The raw OIDC-asserted issuer of the bound administrator. Stored and compared byte-for-byte:
    /// never trimmed, case-folded, or otherwise normalized.
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// The raw OIDC-asserted subject of the bound administrator. Stored and compared byte-for-byte;
    /// it is an opaque string, never parsed as a GUID or any other structured value.
    /// </summary>
    public string Subject { get; set; } = string.Empty;

    /// <summary>
    /// Whether the binding grants the administrator role. A deactivated row keeps occupying the
    /// slot: the first administrator cannot be re-claimed through a missing active row.
    /// </summary>
    public bool IsActive { get; set; }

    /// <summary>UTC creation instant of the binding row.</summary>
    public DateTimeOffset CreatedAtUtc { get; set; }
}
