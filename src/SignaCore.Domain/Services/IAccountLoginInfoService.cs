using SignaCore.Database.Entity;

namespace SignaCore.Domain.Services;

public interface IAccountLoginInfoService
{
    /// <summary>Stages the account's login counters and metadata; the caller commits the unit of work.</summary>
    Task UpdateLoginInfoAsync(AccountEntity account, string? clientIp, string authMethod, CancellationToken cancellationToken = default);
}
