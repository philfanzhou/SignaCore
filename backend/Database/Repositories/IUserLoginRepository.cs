using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Database.Repositories;

public interface IUserLoginRepository
{
    Task<UserLoginEntity?> GetByProviderAsync(string providerName, string providerUserId);
    Task<UserLoginEntity?> GetBySmsPhoneAsync(string phone);
    Task AddAsync(UserLoginEntity userLogin);
    Task RemoveAsync(UserLoginEntity userLogin);
    Task<List<UserLoginEntity>> GetByAccountIdAsync(Guid accountId);
}
