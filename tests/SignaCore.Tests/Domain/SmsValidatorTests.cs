using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain;
using SignaCore.Domain.Services.Sms;
using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.Tests.Domain.Validators;

public class SmsValidatorTests
{
    private static readonly Guid AppId = Guid.NewGuid();

    [Fact]
    public async Task ManualApproval_RejectsBeforeOtp_WhenUserIsNotAdminApproved()
    {
        var (validator, otp, admission) = Create(SmsLoginMode.ManualApproval, null);
        var result = await validator.ValidateAsync(Request(SmsLoginMode.ManualApproval));
        Assert.False(result.IsSuccess);
        Assert.Equal("SMS account is not authorized for this application", result.ErrorMessage);
        otp.Verify(service => service.VerifyAsync(
            It.IsAny<Guid>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<CancellationToken>()), Times.Never);
        admission.VerifyAll();
    }

    [Fact]
    public async Task AutoProvision_VerifiesOtp_AndCreatesAppAdmission()
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true };
        var login = new UserLoginEntity { Id = Guid.NewGuid(), AccountId = account.Id, ProviderUserId = "+8613800138000" };
        var access = new AppSmsAccessEntity { IsActive = true, ApprovalSource = SmsAccessApprovalSource.AutoProvision };
        var provisioned = new SmsAdmission(account, login, access);
        var (validator, otp, admission) = Create(SmsLoginMode.AutoProvision, null);
        var otpChange = Change(OtpVerificationChangeKind.Consume);
        otp.Setup(service => service.VerifyAsync(
                AppId,
                "+8613800138000",
                "123456",
                TestContext.Current.CancellationToken))
            .ReturnsAsync(new OtpVerificationResult(true, otpChange));
        admission.Setup(service => service.ProvisionAsync(
            It.IsAny<AppRegistrationEntity>(), "+8613800138000", SmsAccessApprovalSource.AutoProvision,
            null, It.IsAny<CancellationToken>())).ReturnsAsync(provisioned);

        var result = await validator.ValidateAsync(Request(SmsLoginMode.AutoProvision));

        Assert.True(result.IsSuccess);
        Assert.Equal(login.Id, result.SmsUserLoginId);
        Assert.Equal(IdentityConstants.AuthMethodSms, result.AuthMethod);
        Assert.Same(otpChange, result.OtpVerificationChange);
    }

    [Fact]
    public async Task DisabledMode_DoesNotVerifyOtp()
    {
        var (validator, otp, _) = Create(SmsLoginMode.Disabled, null);
        var result = await validator.ValidateAsync(Request(SmsLoginMode.Disabled));
        Assert.False(result.IsSuccess);
        Assert.Equal("SMS login is disabled for this application", result.ErrorMessage);
        otp.VerifyNoOtherCalls();
    }

    /// <summary>
    /// The policy check runs before the phone/code checks, so the typed reason is set under
    /// <c>Disabled</c> (or without an application) even when the phone or code is empty, and no
    /// admission lookup, OTP verification, or provisioning happens.
    /// </summary>
    [Theory]
    [InlineData(true, "13800138000", "123456")]
    [InlineData(true, "", "")]
    [InlineData(true, "13800138000", null)]
    [InlineData(true, "not-a-phone", "123456")]
    [InlineData(false, "13800138000", "123456")]
    public async Task DisabledPolicy_SetsTheSmsLoginDisabledReason_BeforeAnyOtherCheck(
        bool withApp, string? phone, string? code)
    {
        var (validator, otp, admission) = Create(SmsLoginMode.Disabled, null);
        var request = Request(SmsLoginMode.Disabled);
        request.Phone = phone;
        request.Code = code;
        if (!withApp) request.App = null;

        var result = await validator.ValidateAsync(request);

        Assert.False(result.IsSuccess);
        Assert.Equal("SMS login is disabled for this application", result.ErrorMessage);
        Assert.Equal(OAuthErrorCodes.UnauthorizedClient, result.ErrorCode);
        Assert.Equal(ValidationFailureReason.SmsLoginDisabled, result.FailureReason);
        Assert.Null(result.OtpVerificationChange);
        otp.VerifyNoOtherCalls();
        admission.VerifyNoOtherCalls();
    }

    /// <summary>Every failure after the policy check, and every success, carries no reason.</summary>
    [Theory]
    [InlineData("empty-phone", "Phone or code cannot be empty")]
    [InlineData("empty-code", "Phone or code cannot be empty")]
    [InlineData("invalid-phone", "Invalid mainland China mobile number")]
    [InlineData("not-authorized", "SMS account is not authorized for this application")]
    [InlineData("wrong-code", "Wrong or expired verification code")]
    [InlineData("account-disabled", "Account is disabled")]
    public async Task OtherFailures_CarryNoFailureReason(string scenario, string message)
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = scenario != "account-disabled" };
        var login = new UserLoginEntity { Id = Guid.NewGuid(), AccountId = account.Id };
        var access = new AppSmsAccessEntity { IsActive = true, ApprovalSource = SmsAccessApprovalSource.Admin };
        var (validator, otp, _) = Create(
            SmsLoginMode.ManualApproval,
            scenario == "not-authorized" ? null : new SmsAdmission(account, login, access));
        var verified = scenario != "wrong-code";
        otp.Setup(service => service.VerifyAsync(
                AppId, "+8613800138000", "123456", TestContext.Current.CancellationToken))
            .ReturnsAsync(new OtpVerificationResult(
                verified,
                Change(verified ? OtpVerificationChangeKind.Consume : OtpVerificationChangeKind.RecordFailure)));
        var request = Request(SmsLoginMode.ManualApproval);
        switch (scenario)
        {
            case "empty-phone": request.Phone = " "; break;
            case "empty-code": request.Code = ""; break;
            case "invalid-phone": request.Phone = "12345"; break;
        }

        var result = await validator.ValidateAsync(request);

        Assert.False(result.IsSuccess);
        Assert.Equal(message, result.ErrorMessage);
        Assert.Equal(ValidationFailureReason.None, result.FailureReason);
    }

    [Theory]
    [InlineData(SmsLoginMode.ManualApproval)]
    [InlineData(SmsLoginMode.AutoProvision)]
    public async Task Success_CarriesNoFailureReason(SmsLoginMode mode)
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true };
        var login = new UserLoginEntity { Id = Guid.NewGuid(), AccountId = account.Id };
        var access = new AppSmsAccessEntity { IsActive = true, ApprovalSource = SmsAccessApprovalSource.Admin };
        var (validator, otp, _) = Create(mode, new SmsAdmission(account, login, access));
        otp.Setup(service => service.VerifyAsync(
                AppId, "+8613800138000", "123456", TestContext.Current.CancellationToken))
            .ReturnsAsync(new OtpVerificationResult(true, Change(OtpVerificationChangeKind.Consume)));

        var result = await validator.ValidateAsync(Request(mode));

        Assert.True(result.IsSuccess);
        Assert.Equal(ValidationFailureReason.None, result.FailureReason);
    }

    [Fact]
    public void FailureReason_CannotBeAttachedToASuccess()
    {
        var success = ValidationResult.Success(new AccountEntity { Id = Guid.NewGuid() }, IdentityConstants.AuthMethodSms);

        Assert.Throws<InvalidOperationException>(() =>
            success.WithFailureReason(ValidationFailureReason.SmsLoginDisabled));
        Assert.Equal(ValidationFailureReason.None, success.FailureReason);
    }

    [Fact]
    public async Task Phone_IsNormalizedBeforeLookupAndVerification()
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true };
        var login = new UserLoginEntity { Id = Guid.NewGuid(), AccountId = account.Id, ProviderUserId = "+8613800138000" };
        var access = new AppSmsAccessEntity { IsActive = true, ApprovalSource = SmsAccessApprovalSource.Admin };
        var admissionValue = new SmsAdmission(account, login, access);
        var (validator, otp, admission) = Create(SmsLoginMode.ManualApproval, admissionValue);
        var otpChange = Change(OtpVerificationChangeKind.Consume);
        otp.Setup(service => service.VerifyAsync(
                AppId,
                "+8613800138000",
                "123456",
                TestContext.Current.CancellationToken))
            .ReturnsAsync(new OtpVerificationResult(true, otpChange));

        var result = await validator.ValidateAsync(Request(SmsLoginMode.ManualApproval));

        Assert.True(result.IsSuccess);
        Assert.Same(otpChange, result.OtpVerificationChange);
        admission.Verify(service => service.FindAsync(
            AppId,
            "+8613800138000",
            TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task WrongCode_PreservesDeferredFailureChange()
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true };
        var login = new UserLoginEntity { Id = Guid.NewGuid(), AccountId = account.Id };
        var access = new AppSmsAccessEntity { IsActive = true, ApprovalSource = SmsAccessApprovalSource.Admin };
        var (validator, otp, _) = Create(
            SmsLoginMode.ManualApproval,
            new SmsAdmission(account, login, access));
        var otpChange = Change(OtpVerificationChangeKind.RecordFailure);
        otp.Setup(service => service.VerifyAsync(
                AppId,
                "+8613800138000",
                "123456",
                TestContext.Current.CancellationToken))
            .ReturnsAsync(new OtpVerificationResult(false, otpChange));

        var result = await validator.ValidateAsync(Request(SmsLoginMode.ManualApproval));

        Assert.False(result.IsSuccess);
        Assert.Same(otpChange, result.OtpVerificationChange);
    }

    [Fact]
    public async Task BypassCode_DoesNotProduceOtpChange()
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true };
        var login = new UserLoginEntity { Id = Guid.NewGuid(), AccountId = account.Id };
        var access = new AppSmsAccessEntity { IsActive = true, ApprovalSource = SmsAccessApprovalSource.Admin };
        var (validator, otp, _) = Create(
            SmsLoginMode.ManualApproval,
            new SmsAdmission(account, login, access),
            new SmsOptions { BypassCode = "123456", BypassPhones = ["+8613800138000"] });

        var result = await validator.ValidateAsync(Request(SmsLoginMode.ManualApproval));

        Assert.True(result.IsSuccess);
        Assert.Null(result.OtpVerificationChange);
        otp.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task MatchingCode_WhenAccountIsDisabled_PreservesConsumptionForFailureAudit()
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = false };
        var login = new UserLoginEntity { Id = Guid.NewGuid(), AccountId = account.Id };
        var access = new AppSmsAccessEntity { IsActive = true, ApprovalSource = SmsAccessApprovalSource.Admin };
        var (validator, otp, _) = Create(
            SmsLoginMode.ManualApproval,
            new SmsAdmission(account, login, access));
        var otpChange = Change(OtpVerificationChangeKind.Consume);
        otp.Setup(service => service.VerifyAsync(
                AppId,
                "+8613800138000",
                "123456",
                TestContext.Current.CancellationToken))
            .ReturnsAsync(new OtpVerificationResult(true, otpChange));

        var result = await validator.ValidateAsync(Request(SmsLoginMode.ManualApproval));

        Assert.False(result.IsSuccess);
        Assert.Equal("Account is disabled", result.ErrorMessage);
        Assert.Same(otpChange, result.OtpVerificationChange);
    }

    private static (SmsValidator Validator, Mock<IOtpService> Otp, Mock<ISmsAdmissionService> Admission) Create(
        SmsLoginMode mode,
        SmsAdmission? admissionValue,
        SmsOptions? options = null)
    {
        var otp = new Mock<IOtpService>();
        var admission = new Mock<ISmsAdmissionService>();
        admission.Setup(service => service.FindAsync(AppId, "+8613800138000", It.IsAny<CancellationToken>()))
            .ReturnsAsync(admissionValue);
        var meterFactory = new Mock<System.Diagnostics.Metrics.IMeterFactory>();
        meterFactory.Setup(factory => factory.Create(It.IsAny<System.Diagnostics.Metrics.MeterOptions>()))
            .Returns(new System.Diagnostics.Metrics.Meter("sms-validator-tests"));
        return (new SmsValidator(otp.Object, admission.Object, NullLogger<SmsValidator>.Instance,
            new AuthMetrics(meterFactory.Object), options ?? new SmsOptions()), otp, admission);
    }

    private static ValidationRequest Request(SmsLoginMode mode) => new()
    {
        App = new AppRegistrationEntity { Id = AppId, SmsLoginMode = mode },
        Phone = "13800138000",
        Code = "123456",
        CancellationToken = TestContext.Current.CancellationToken
    };

    private static OtpVerificationChange Change(OtpVerificationChangeKind kind) => new(
        kind,
        AppId,
        "+8613800138000",
        "TEST-MAC-NOT-A-REAL-OTP",
        DateTimeOffset.UtcNow,
        5,
        DateTimeOffset.UtcNow.AddMinutes(1));
}
