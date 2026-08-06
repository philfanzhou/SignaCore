using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Domain;
using QuantumZhou.Identity.Domain.Services.Sms;
using QuantumZhou.Identity.Domain.Validators;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain.Validators;

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
        otp.Verify(service => service.VerifyAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);
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
        otp.Setup(service => service.VerifyAsync(AppId, "+8613800138000", "123456")).ReturnsAsync(true);
        admission.Setup(service => service.ProvisionAsync(
            It.IsAny<AppRegistrationEntity>(), "+8613800138000", SmsAccessApprovalSource.AutoProvision,
            null, It.IsAny<CancellationToken>())).ReturnsAsync(provisioned);

        var result = await validator.ValidateAsync(Request(SmsLoginMode.AutoProvision));

        Assert.True(result.IsSuccess);
        Assert.Equal(login.Id, result.SmsUserLoginId);
        Assert.Equal(IdentityConstants.AuthMethodSms, result.AuthMethod);
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

    [Fact]
    public async Task Phone_IsNormalizedBeforeLookupAndVerification()
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = true };
        var login = new UserLoginEntity { Id = Guid.NewGuid(), AccountId = account.Id, ProviderUserId = "+8613800138000" };
        var access = new AppSmsAccessEntity { IsActive = true, ApprovalSource = SmsAccessApprovalSource.Admin };
        var admissionValue = new SmsAdmission(account, login, access);
        var (validator, otp, admission) = Create(SmsLoginMode.ManualApproval, admissionValue);
        otp.Setup(service => service.VerifyAsync(AppId, "+8613800138000", "123456")).ReturnsAsync(true);

        var result = await validator.ValidateAsync(Request(SmsLoginMode.ManualApproval));

        Assert.True(result.IsSuccess);
        admission.Verify(service => service.FindAsync(AppId, "+8613800138000", It.IsAny<CancellationToken>()));
    }

    private static (SmsValidator Validator, Mock<IOtpService> Otp, Mock<ISmsAdmissionService> Admission) Create(
        SmsLoginMode mode,
        SmsAdmission? admissionValue)
    {
        var otp = new Mock<IOtpService>();
        var admission = new Mock<ISmsAdmissionService>();
        admission.Setup(service => service.FindAsync(AppId, "+8613800138000", It.IsAny<CancellationToken>()))
            .ReturnsAsync(admissionValue);
        var meterFactory = new Mock<System.Diagnostics.Metrics.IMeterFactory>();
        meterFactory.Setup(factory => factory.Create(It.IsAny<System.Diagnostics.Metrics.MeterOptions>()))
            .Returns(new System.Diagnostics.Metrics.Meter("sms-validator-tests"));
        return (new SmsValidator(otp.Object, admission.Object, NullLogger<SmsValidator>.Instance,
            new AuthMetrics(meterFactory.Object), new SmsOptions()), otp, admission);
    }

    private static ValidationRequest Request(SmsLoginMode mode) => new()
    {
        App = new AppRegistrationEntity { Id = AppId, SmsLoginMode = mode },
        Phone = "13800138000",
        Code = "123456"
    };
}
