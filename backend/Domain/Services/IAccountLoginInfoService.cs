using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Domain.Services;

public interface IAccountLoginInfoService
{
    Task UpdateLoginInfoAsync(AccountEntity account, string? clientIp, string authMethod);
}
