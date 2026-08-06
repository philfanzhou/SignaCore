using SignaCore.Database.Entity;

namespace SignaCore.Domain.Services;

public interface IRefreshTokenService
{
    Task<string?> HandleRefreshTokenAsync(
        string grantType,
        string? existingRefreshToken,
        AccountEntity account,
        string? appId,
        Guid? ldapCredentialId = null,
        Guid? smsUserLoginId = null);
    Task<bool> RevokeAsync(string token);
}
