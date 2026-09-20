using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace SignaCore.ReferenceBff.Database;

/// <summary>
/// Design-time factory for the PostgreSQL migration history of the reference BFF database.
/// </summary>
public sealed class ReferenceBffDbContextFactory : IDesignTimeDbContextFactory<ReferenceBffDbContext>
{
    public ReferenceBffDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("ReferenceBffDatabase__ConnectionString")
            ?? "Host=localhost;Database=signacore_reference_bff;Username=postgres;Password=postgres";

        var optionsBuilder = new DbContextOptionsBuilder<ReferenceBffDbContext>();
        optionsBuilder.UseReferenceBffPostgreSql(connectionString);
        return new ReferenceBffDbContext(optionsBuilder.Options);
    }
}
