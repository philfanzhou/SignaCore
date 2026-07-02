using Microsoft.EntityFrameworkCore;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public class OtpRepository : IOtpRepository
{
    private readonly IdentityDbContext _dbContext;

    public OtpRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<OtpEntity?> GetByPhoneAsync(string phone)
    {
        return await _dbContext.Otps.FirstOrDefaultAsync(o => o.Phone == phone);
    }

    public Task AddAsync(OtpEntity otp)
    {
        _dbContext.Otps.Add(otp);
        return Task.CompletedTask;
    }

    public Task RemoveAsync(OtpEntity otp)
    {
        _dbContext.Otps.Remove(otp);
        return Task.CompletedTask;
    }
}
