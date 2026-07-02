using QuantumZhou.Identity.Database;

namespace QuantumZhou.Identity.Database.Repositories;

public interface IUnitOfWork
{
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}

public class EfCoreUnitOfWork : IUnitOfWork
{
    private readonly IdentityDbContext _dbContext;

    public EfCoreUnitOfWork(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return await _dbContext.SaveChangesAsync(cancellationToken);
    }
}
