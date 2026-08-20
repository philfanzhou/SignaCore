using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using SignaCore.Database;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Host.Http;
using SignaCore.Host.Models;

namespace SignaCore.Host.Security;

/// <summary>
/// Validates the calling application before gateway-facing endpoints enter business logic.
/// The validated registration is cached in <see cref="HttpContext.Items"/> so controllers
/// can reuse it without a second database lookup or BCrypt verification.
/// </summary>
public sealed class GatewayAppAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly GatewayValidationService _gatewayValidationService;

    public GatewayAppAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        GatewayValidationService gatewayValidationService)
        : base(options, logger, encoder)
    {
        _gatewayValidationService = gatewayValidationService;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var appId = Context.GetAppId();
        var appSecret = Context.GetAppSecret();

        if (string.IsNullOrWhiteSpace(appId) || string.IsNullOrWhiteSpace(appSecret))
        {
            return AuthenticateResult.Fail("Missing gateway credentials.");
        }

        var validation = await _gatewayValidationService.ValidateAsync(appId, appSecret);
        if (!validation.IsSuccess || validation.App is null)
        {
            Logger.LogWarning(
                "Gateway application authentication failed: AppId={AppId}, Reason={Reason}",
                LogValueSanitizer.Sanitize(appId),
                LogValueSanitizer.Sanitize(validation.ErrorMessage));
            return AuthenticateResult.Fail("Invalid gateway credentials.");
        }

        Context.Items[IdentityHeaders.ValidatedApp] = validation.App;

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, validation.App.Id.ToString()),
            new Claim(IdentityConstants.ClaimClientId, validation.App.AppId)
        };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        await Response.WriteAsJsonAsync(new ErrorResponse("Invalid or missing gateway credentials."));
    }
}
