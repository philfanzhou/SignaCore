using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace QuantumZhou.Identity.Database;

public class IdentityDbContextFactory : IDesignTimeDbContextFactory<IdentityDbContext>
{
    public IdentityDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseNpgsql("Host=localhost;Database=quantumzhou_identity;Username=postgres;Password=postgres");

        return new IdentityDbContext(optionsBuilder.Options);
    }
}
