using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;

namespace SignaCore.Domain.Services;

public class GatewayValidationService
{
    private readonly IAppRegistrationRepository _appRegistrationRepository;

    public GatewayValidationService(IAppRegistrationRepository appRegistrationRepository)
    {
        _appRegistrationRepository = appRegistrationRepository;
    }

    public async Task<GatewayAuthResult> ValidateAsync(
        string? appId,
        string? appSecret,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(appId))
        {
            return GatewayAuthResult.Failure("AppId is required");
        }

        if (string.IsNullOrEmpty(appSecret))
        {
            return GatewayAuthResult.Failure("AppSecret is required");
        }

        var app = await _appRegistrationRepository.GetByAppIdAsync(appId, cancellationToken);
        if (app == null)
        {
            return GatewayAuthResult.Failure("AppId not registered");
        }

        if (!app.IsActive)
        {
            return GatewayAuthResult.Failure("App is disabled");
        }

        if (app.CallbackExpiresAt.HasValue && app.CallbackExpiresAt < DateTimeOffset.UtcNow)
        {
            return GatewayAuthResult.Failure("App registration has expired");
        }

        // A Public client holds no secret, and an empty hash is never a verifiable credential
        // (BCrypt throws on it instead of returning false): both fail closed with the exact shape
        // of a wrong secret — no exception, no 500, and no type or hash-state disclosure.
        if (app.ClientType == OidcClientType.Public || string.IsNullOrEmpty(app.AppSecretHash))
        {
            return GatewayAuthResult.Failure("AppSecret mismatch");
        }

        if (!BCrypt.Net.BCrypt.Verify(appSecret, app.AppSecretHash))
        {
            return GatewayAuthResult.Failure("AppSecret mismatch");
        }

        return GatewayAuthResult.Success(app);
    }
}
