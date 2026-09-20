using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace SignaCore.ReferenceBff.Database;

/// <summary>
/// The reference BFF's own persistence context. It is intentionally independent of the product
/// <c>IdentityDbContext</c>: this sample database owns exactly one table — the single
/// initial-administrator binding slot — and maps no product entity and no ServiceMantle business
/// entity.
/// </summary>
public sealed class ReferenceBffDbContext(DbContextOptions<ReferenceBffDbContext> options)
    : DbContext(options)
{
    private static readonly ValueConverter<DateTimeOffset, long> UnixMicrosecondsConverter = new(
        value => (value.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10,
        value => DateTimeOffset.UnixEpoch.AddTicks(value * 10));

    /// <summary>The binding slot table; the unique index on <see cref="ManagementRoleBindingEntity.Role"/>
    /// keeps it a single row.</summary>
    public DbSet<ManagementRoleBindingEntity> ManagementRoleBindings => Set<ManagementRoleBindingEntity>();

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
