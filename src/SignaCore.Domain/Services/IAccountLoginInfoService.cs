using SignaCore.Database.Entity;

namespace SignaCore.Domain.Services;

public interface IAccountLoginInfoService
{
    Task UpdateLoginInfoAsync(AccountEntity account, string? clientIp, string authMethod);
}
