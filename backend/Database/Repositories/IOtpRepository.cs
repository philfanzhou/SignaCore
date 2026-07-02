using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public interface IOtpRepository
{
    Task<OtpEntity?> GetByPhoneAsync(string phone);
    Task AddAsync(OtpEntity otp);
    Task RemoveAsync(OtpEntity otp);
}
