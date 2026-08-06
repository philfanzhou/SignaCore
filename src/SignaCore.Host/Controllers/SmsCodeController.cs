using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SignaCore.Database.Entity;
using SignaCore.Database;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.Sms;
using SignaCore.Host.Http;
using SignaCore.Host.Models;
using SignaCore.Host.Security;

namespace SignaCore.Host.Controllers;

/// <summary>
/// POST /api/auth/sms-code —— 申请短信验证码。
/// 与 <see cref="TokenController"/> 一样，AppId/AppSecret 头必须通过统一应用认证。
/// </summary>
[Route("api/auth")]
[ApiController]
public class SmsCodeController : ControllerBase
{
    private readonly IOtpService _otpService;
    private readonly ISmsAdmissionService _admissionService;
    private readonly IAuditService _auditService;
    private readonly ILogger<SmsCodeController> _logger;

    public SmsCodeController(
        IOtpService otpService,
        ISmsAdmissionService admissionService,
        IAuditService auditService,
        ILogger<SmsCodeController> logger)
    {
        _otpService = otpService;
        _admissionService = admissionService;
        _auditService = auditService;
        _logger = logger;
    }

    /// <summary>
    /// POST /api/auth/sms-code — 申请短信验证码。失败同样返回 HTTP 200 + Success=false。
    /// </summary>
    [HttpPost("sms-code")]
    [Authorize(Policy = GatewayAppAuthenticationDefaults.Policy)]
    [EnableRateLimiting("sms-code")]
    public async Task<ActionResult<SmsCodeResponse>> RequestSmsCode(
        [FromBody] SmsCodeRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Phone))
        {
            return Ok(new SmsCodeResponse { Success = false, Message = "Phone number is required" });
        }

        var app = HttpContext.GetValidatedApp()
            ?? throw new InvalidOperationException("GatewayApp authentication did not provide a validated application.");
        var appId = app.AppId;

        if (app.SmsLoginMode == SmsLoginMode.Disabled)
            return Ok(new SmsCodeResponse { Success = false, Message = "SMS login is disabled for this application" });
        if (string.IsNullOrWhiteSpace(app.SmsProfileKey))
            return Ok(new SmsCodeResponse { Success = false, Message = "SMS provider is not configured for this application" });
        if (!MainlandChinaPhoneNumber.TryNormalize(request.Phone, out var phone))
            return Ok(new SmsCodeResponse { Success = false, Message = "Invalid mainland China mobile number" });

        var existingAdmission = await _admissionService.FindAsync(app.Id, phone, cancellationToken);
        if (existingAdmission is { Account.IsActive: false })
            return Ok(new SmsCodeResponse { Success = false, Message = "Account is disabled" });
        if (existingAdmission is { Access.IsActive: false })
            return Ok(new SmsCodeResponse { Success = false, Message = "SMS access has been revoked" });
        if (app.SmsLoginMode == SmsLoginMode.ManualApproval)
        {
            if (existingAdmission is not { Access.IsActive: true } ||
                existingAdmission.Access.ApprovalSource != SmsAccessApprovalSource.Admin)
            {
                return Ok(new SmsCodeResponse { Success = false, Message = "SMS account is not authorized for this application" });
            }
        }

        try
        {
            var maskedPhone = SensitiveDataMasker.MaskPhone(phone);
            await _otpService.GenerateAndSendAsync(app.Id, phone, app.SmsProfileKey, cancellationToken);
            _logger.LogInformation("SMS verification code sent: Phone={Phone}", maskedPhone);

            await _auditService.RecordLoginAsync(null, phone, IdentityConstants.GrantTypeSms, "sms_code_sent",
                HttpContext.GetClientIp(), HttpContext.GetUserAgent(), null, appId, HttpContext.GetCorrelationId());

            return Ok(new SmsCodeResponse { Success = true, Message = "Verification code sent" });
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning("SMS code request failed: Phone={Phone}, Reason={Reason}", SensitiveDataMasker.MaskPhone(request.Phone), ex.Message);
            return Ok(new SmsCodeResponse { Success = false, Message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SMS code request exception: Phone={Phone}", SensitiveDataMasker.MaskPhone(request.Phone));
            return Ok(new SmsCodeResponse { Success = false, Message = "Failed to send verification code" });
        }
    }
}
