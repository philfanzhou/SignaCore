using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SignaCore.Database;
using SignaCore.Database.Repositories;
// CallbackUrlValidator belongs to SignaCore.Domain even though its file is under Domain/Services.
using SignaCore.Domain;
using SignaCore.Host.Http;
using SignaCore.Host.Models;
using SignaCore.Host.Security;

namespace SignaCore.Host.Controllers;

/// <summary>
/// POST /api/auth/callback/register allows an application to register its claims callback URL.
/// Unlike <see cref="TokenController"/>, this endpoint requires AppId and AppSecret.
/// </summary>
[Route("api/auth")]
[ApiController]
public class CallbackRegistrationController : ControllerBase
{
    private readonly IAppRegistrationRepository _appRegistrationRepository;
    private readonly CallbackUrlValidator _callbackUrlValidator;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ILogger<CallbackRegistrationController> _logger;

    public CallbackRegistrationController(
        IAppRegistrationRepository appRegistrationRepository,
        CallbackUrlValidator callbackUrlValidator,
        IUnitOfWork unitOfWork,
        ILogger<CallbackRegistrationController> logger)
    {
        _appRegistrationRepository = appRegistrationRepository;
        _callbackUrlValidator = callbackUrlValidator;
        _unitOfWork = unitOfWork;
        _logger = logger;
    }

    [HttpPost("callback/register")]
    [Authorize(Policy = GatewayAppAuthenticationDefaults.Policy)]
    public async Task<ActionResult<RegisterCallbackResponse>> RegisterCallback(
        [FromBody] RegisterCallbackRequest request,
        CancellationToken cancellationToken = default)
    {
        var app = HttpContext.GetValidatedApp();
        var appId = app?.AppId ?? HttpContext.GetAppId();
        var appSecret = HttpContext.GetAppSecret();

        if (app is null && (string.IsNullOrEmpty(appId) || string.IsNullOrEmpty(appSecret)))
        {
            return Ok(new RegisterCallbackResponse { Success = false, Message = "AppId and AppSecret are required" });
        }

        if (!string.IsNullOrWhiteSpace(request.CallbackUrl))
        {
            var urlValidation = await _callbackUrlValidator.ValidateAsync(
                request.CallbackUrl,
                cancellationToken);
            if (!urlValidation.IsValid)
            {
                return Ok(new RegisterCallbackResponse { Success = false, Message = $"Invalid callback URL: {urlValidation.ErrorMessage}" });
            }
        }

        app ??= await _appRegistrationRepository.GetByAppIdAsync(appId!);
        if (app is null)
        {
            return Ok(new RegisterCallbackResponse { Success = false, Message = "AppId not registered" });
        }

        if (HttpContext.GetValidatedApp() is null && !BCrypt.Net.BCrypt.Verify(appSecret, app.AppSecretHash))
        {
            _logger.LogWarning("Callback registration failed: AppId={AppId}, Reason=AppSecret mismatch",
                LogValueSanitizer.Sanitize(appId));
            return Ok(new RegisterCallbackResponse { Success = false, Message = "AppSecret mismatch" });
        }

        app.CallbackUrl = request.CallbackUrl;
        app.CallbackExpiresAt = request.TtlSeconds == IdentityConstants.CallbackTtlNeverExpire
            ? null
            : DateTimeOffset.UtcNow.AddSeconds(request.TtlSeconds > 0 ? request.TtlSeconds : IdentityConstants.DefaultCallbackTtlSeconds);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        return Ok(new RegisterCallbackResponse
        {
            Success = true,
            Message = "Registered successfully",
            ExpiresAt = app.CallbackExpiresAt.HasValue ? app.CallbackExpiresAt.Value.ToUnixTimeSeconds() : 0
        });
    }
}
