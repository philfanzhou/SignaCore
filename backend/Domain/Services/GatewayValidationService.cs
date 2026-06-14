using Microsoft.Extensions.Logging;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain.Validators;

namespace QuantumZhou.Identity.Domain.Services;

public class GatewayValidationService
{
    private readonly IAppRegistrationRepository _appRegistrationRepository;
    private readonly ILogger<GatewayValidationService> _logger;

    public GatewayValidationService(
        IAppRegistrationRepository appRegistrationRepository,
        ILogger<GatewayValidationService> logger)
    {
        _appRegistrationRepository = appRegistrationRepository;
        _logger = logger;
    }

    public async Task<GatewayAuthResult> ValidateAsync(string appId, string? appSecret)
    {
        if (string.IsNullOrEmpty(appSecret))
        {
            return GatewayAuthResult.Failure("AppSecret is required");
        }

        var app = await _appRegistrationRepository.GetByAppIdAsync(appId);
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

        if (!BCrypt.Net.BCrypt.Verify(appSecret, app.AppSecretHash))
        {
            return GatewayAuthResult.Failure("AppSecret mismatch");
        }

        return GatewayAuthResult.Success(app);
    }
}
