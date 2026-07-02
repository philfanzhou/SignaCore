using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Domain.Services;

public interface IRefreshTokenService
{
    Task<string?> HandleRefreshTokenAsync(string grantType, string? existingRefreshToken, AccountEntity account, string? appId);
    Task<bool> RevokeAsync(string token);
}
