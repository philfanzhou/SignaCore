using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Domain.Services.Sms;
using QuantumZhou.Identity.Host.Http;
using QuantumZhou.Identity.Host.Models;
using QuantumZhou.Identity.Host.Security;

namespace QuantumZhou.Identity.Host.Controllers;

/// <summary>
/// POST /api/auth/sms-code —— 申请短信验证码。
/// 与 <see cref="TokenController"/> 一样，AppId/AppSecret 头必须通过统一应用认证。
/// </summary>
[Route("api/auth")]
[ApiController]
public class SmsCodeController : ControllerBase
{
    private readonly IOtpService _otpService;
    private readonly ISmsSender _smsSender;
    private readonly IAuditService _auditService;
    private readonly ILogger<SmsCodeController> _logger;

    public SmsCodeController(
        IOtpService otpService,
        ISmsSender smsSender,
        IAuditService auditService,
        ILogger<SmsCodeController> logger)
    {
        _otpService = otpService;
        _smsSender = smsSender;
        _auditService = auditService;
        _logger = logger;
    }

    /// <summary>
    /// POST /api/auth/sms-code — 申请短信验证码。失败同样返回 HTTP 200 + Success=false。
    /// </summary>
    [HttpPost("sms-code")]
    [Authorize(Policy = GatewayAppAuthenticationDefaults.Policy)]
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

        try
        {
            var phone = request.Phone.Trim();
            var maskedPhone = SensitiveDataMasker.MaskPhone(phone);
            await _otpService.GenerateAndSendAsync(phone, _smsSender);
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
