using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IUserLoginRepository
{
    Task<UserLoginEntity?> GetByProviderAsync(
        string providerName,
        string providerUserId,
        CancellationToken cancellationToken = default);
    Task<UserLoginEntity?> GetBySmsPhoneAsync(
        string phone,
        CancellationToken cancellationToken = default);
    Task AddAsync(UserLoginEntity userLogin, CancellationToken cancellationToken = default);
    Task RemoveAsync(UserLoginEntity userLogin, CancellationToken cancellationToken = default);
    Task<List<UserLoginEntity>> GetByAccountIdAsync(
        Guid accountId,
        CancellationToken cancellationToken = default);
}
