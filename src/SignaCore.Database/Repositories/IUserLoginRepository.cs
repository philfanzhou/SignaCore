using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IUserLoginRepository
{
    Task<UserLoginEntity?> GetByProviderAsync(string providerName, string providerUserId);
    Task<UserLoginEntity?> GetBySmsPhoneAsync(string phone);
    Task AddAsync(UserLoginEntity userLogin);
    Task RemoveAsync(UserLoginEntity userLogin);
    Task<List<UserLoginEntity>> GetByAccountIdAsync(Guid accountId);
}
