using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public interface IUserLoginRepository
{
    Task<UserLoginEntity?> GetBySmsPhoneAsync(
        string phone,
        CancellationToken cancellationToken = default);
    Task AddAsync(UserLoginEntity userLogin, CancellationToken cancellationToken = default);
}
