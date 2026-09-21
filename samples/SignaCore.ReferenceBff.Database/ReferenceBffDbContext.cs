using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using ServiceMantle.Persistence.EntityFrameworkCore;

namespace SignaCore.ReferenceBff.Database;

/// <summary>
/// The reference BFF's own persistence context. It is intentionally independent of the product
/// <c>IdentityDbContext</c>: beside the single initial-administrator binding slot, this context maps
/// the shared installation, audit and Data Protection tables through library mappings:
/// <c>service_installations</c>, <c>service_audit_logs</c> and <c>service_data_protection_keys</c>.
/// No product entity and no other ServiceMantle business entity is reachable from this context.
/// </summary>
public sealed class ReferenceBffDbContext(DbContextOptions<ReferenceBffDbContext> options)
    : DbContext(options), IServiceDbContext
{
    private static readonly ValueConverter<DateTimeOffset, long> UnixMicrosecondsConverter = new(
        value => (value.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10,
        value => DateTimeOffset.UnixEpoch.AddTicks(value * 10));

    /// <summary>The binding slot table; the unique index on <see cref="ManagementRoleBindingEntity.Role"/>
    /// keeps it a single row.</summary>
    public DbSet<ManagementRoleBindingEntity> ManagementRoleBindings => Set<ManagementRoleBindingEntity>();

    /// <summary>The shared ServiceMantle installation state for this sample's service id.</summary>
    public DbSet<ServiceInstallationEntity> ServiceInstallations => Set<ServiceInstallationEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var entity = modelBuilder.Entity<ManagementRoleBindingEntity>();

        entity.ToTable("management_role_bindings", table => table.HasCheckConstraint(
            "CK_management_role_bindings_role_fixed",
            $"role = '{ManagementRoleBindingEntity.SystemAdministratorRole}'"));

        entity.HasKey(binding => binding.Id).HasName("PK_management_role_bindings");
        entity.Property(binding => binding.Id).HasColumnName("id");
        entity.Property(binding => binding.Role).HasColumnName("role").IsRequired();

        // The unique index is the real slot enforcer: two racing writers cannot both commit the
        // first administrator, whatever the store's advisory pre-check observed.
        entity.HasIndex(binding => binding.Role)
            .IsUnique()
            .HasDatabaseName("IX_management_role_bindings_role");

        // Issuer and subject keep the exact bytes the OIDC provider asserted: no length cap, no
        // index, and no database-side matching. Identity comparison happens in the CLR with
        // Ordinal semantics so no provider collation can fold or widen a stored value.
        entity.Property(binding => binding.Issuer).HasColumnName("issuer").IsRequired();
        entity.Property(binding => binding.Subject).HasColumnName("subject").IsRequired();

        entity.Property(binding => binding.IsActive).HasColumnName("is_active");
        ConfigureInstant(entity.Property(binding => binding.CreatedAtUtc).HasColumnName("created_at"));

        // Shared ServiceMantle tables, applied through the library mappings only: no local clone
        // of a shared entity. Their DateTime columns keep the library's provider-default storage —
        // the role table's DateTimeOffset/SQLite microsecond convention deliberately does not
        // propagate here, so the shared schema stays byte-identical to the product's. The audit
        // dialect is chosen per provider for its text-length check constraints.
        modelBuilder.AddServiceMantleInstallation();
        modelBuilder.AddServiceMantleDataProtectionKeys();
        modelBuilder.AddServiceMantleManagementAudit(
            string.Equals(
                Database.ProviderName,
                "Microsoft.EntityFrameworkCore.Sqlite",
                StringComparison.Ordinal)
                ? ManagementAuditDatabaseDialect.Sqlite
                : ManagementAuditDatabaseDialect.PostgreSql);
    }

    private void ConfigureInstant(PropertyBuilder property)
    {
        // Mirrors the product context: PostgreSQL stores timestamptz, SQLite stores UTC
        // microseconds so ordering never depends on text collation.
        if (Database.ProviderName == "Microsoft.EntityFrameworkCore.Sqlite")
        {
            property.HasConversion(UnixMicrosecondsConverter);
            return;
        }

        property.HasColumnType("timestamptz");
    }
}
