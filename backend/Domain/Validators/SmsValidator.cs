using Microsoft.Extensions.Logging;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Domain.Services.Sms;

namespace QuantumZhou.Identity.Domain.Validators;

public class SmsValidator : IIdentityValidator
{
    private readonly IOtpService _otpService;
    private readonly ISmsAdmissionService _admissionService;
    private readonly ILogger<SmsValidator> _logger;
    private readonly AuthMetrics _authMetrics;
    private readonly SmsOptions _smsOptions;

    public SmsValidator(
        IOtpService otpService,
        ISmsAdmissionService admissionService,
        ILogger<SmsValidator> logger,
        AuthMetrics authMetrics,
        SmsOptions smsOptions)
    {
        _otpService = otpService;
        _admissionService = admissionService;
        _logger = logger;
        _authMetrics = authMetrics;
        _smsOptions = smsOptions;
    }

    public string GrantType => IdentityConstants.GrantTypeSms;

    public async Task<ValidationResult> ValidateAsync(ValidationRequest request)
    {
        if (request.App == null || request.App.SmsLoginMode == SmsLoginMode.Disabled)
            return ValidationResult.Failure("SMS login is disabled for this application");
        if (string.IsNullOrWhiteSpace(request.Phone) || string.IsNullOrWhiteSpace(request.Code))
            return ValidationResult.Failure("Phone or code cannot be empty");
        if (!MainlandChinaPhoneNumber.TryNormalize(request.Phone, out var phone))
            return ValidationResult.Failure("Invalid mainland China mobile number");

        var admission = await _admissionService.FindAsync(request.App.Id, phone, request.CancellationToken);
        if (request.App.SmsLoginMode == SmsLoginMode.ManualApproval &&
            (admission is not { Access.IsActive: true } || admission.Access.ApprovalSource != SmsAccessApprovalSource.Admin))
        {
            return ValidationResult.Failure("SMS account is not authorized for this application");
        }

        var verified = IsBypassAllowed(phone, request.Code) ||
            await _otpService.VerifyAsync(request.App.Id, phone, request.Code);
        if (!verified) return ValidationResult.Failure("Wrong or expired verification code");

        if (admission == null || !admission.Access.IsActive)
        {
            if (request.App.SmsLoginMode != SmsLoginMode.AutoProvision)
                return ValidationResult.Failure("SMS account is not authorized for this application");
            admission = await _admissionService.ProvisionAsync(
                request.App, phone, SmsAccessApprovalSource.AutoProvision, null, request.CancellationToken);
            if (!admission.Access.IsActive)
                return ValidationResult.Failure("SMS access has been revoked");
            if (admission.AccountCreated) _authMetrics.RecordAccountCreation("auto_register_sms");
        }

        if (!admission.Account.IsActive) return ValidationResult.Failure("Account is disabled");
        _logger.LogInformation(
            "SMS validated: AppRegistrationId={AppRegistrationId}, Phone={Phone}",
            request.App.Id, SensitiveDataMasker.MaskPhone(phone));
        return ValidationResult.Success(
            admission.Account, IdentityConstants.AuthMethodSms, phone, smsUserLoginId: admission.Login.Id);
    }

    private bool IsBypassAllowed(string phone, string code)
    {
        if (string.IsNullOrEmpty(_smsOptions.BypassCode) ||
            !string.Equals(code, _smsOptions.BypassCode, StringComparison.Ordinal)) return false;
        return _smsOptions.BypassPhones.Any(allowed =>
            MainlandChinaPhoneNumber.TryNormalize(allowed, out var normalized) && normalized == phone);
    }
}
