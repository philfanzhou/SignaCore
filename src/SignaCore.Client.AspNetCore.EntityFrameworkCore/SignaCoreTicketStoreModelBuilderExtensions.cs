using Microsoft.EntityFrameworkCore;

namespace SignaCore.Client.AspNetCore.EntityFrameworkCore;

/// <summary>
/// The entity mapping of the persistent ticket store, applied to the consumer's own
/// <see cref="DbContext"/>. The package deliberately ships no migrations: the database belongs to
/// the consumer, and the consumer generates and reviews the migration for its provider
/// (PostgreSQL, SQLite, or any other EF Core relational provider) exactly as it does for its own
/// tables.
/// </summary>
public static class SignaCoreTicketStoreModelBuilderExtensions
{
    /// <summary>The single table name the store occupies in the consumer's database.</summary>
    public const string TableName = "signacore_client_session_tickets";

    /// <summary>
    /// Maps <see cref="SignaCoreSessionTicketEntity"/> for a provider-neutral relational schema:
    /// one digest-keyed row per live session, an index on the plain expiry column for the sweep,
    /// and fixed column lengths so PostgreSQL and SQLite see the same shape. The timestamp
    /// columns convert to plain UTC <see cref="DateTime"/> values: SQLite stores
    /// <see cref="DateTimeOffset"/> as culture-dependent text, which would make the expiry
    /// comparisons unreliable; a uniform UTC DateTime column keeps both providers on exact
    /// ordering.
    /// </summary>
    /// <param name="modelBuilder">The consumer's <c>OnModelCreating</c> builder.</param>
    public static void ConfigureSignaCoreTicketStore(this ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.Entity<SignaCoreSessionTicketEntity>(entity =>
        {
            entity.ToTable(TableName);
            entity.HasKey(ticket => ticket.KeyDigest);
            entity.Property(ticket => ticket.KeyDigest)
                .HasMaxLength(64)
                .IsRequired();
            entity.Property(ticket => ticket.Payload)
                .IsRequired();
            entity.Property(ticket => ticket.ExpiresUtc)
                .HasConversion(
                    value => value.UtcDateTime,
                    value => new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc), TimeSpan.Zero))
                .IsRequired();
            entity.Property(ticket => ticket.IssuedUtc)
                .HasConversion(
                    value => value.UtcDateTime,
                    value => new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc), TimeSpan.Zero))
                .IsRequired();
            // The periodic sweep deletes by expiry; PostgreSQL and SQLite both use it as a
            // plain index.
            entity.HasIndex(ticket => ticket.ExpiresUtc);
        });
    }
}
