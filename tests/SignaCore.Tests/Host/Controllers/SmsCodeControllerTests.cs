using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.Domain.Services.Sms;
using SignaCore.Host.Controllers;
using SignaCore.Host.Http;
using SignaCore.Host.Models;
using Xunit;

namespace SignaCore.Tests.Host.Controllers;

public class SmsCodeControllerTests
{
    private readonly Mock<IOtpService> _otpServiceMock = new();
    private readonly Mock<ISmsAdmissionService> _admissionServiceMock = new();
    private readonly Mock<IAuditService> _auditServiceMock = AuthTestDoubles.AuditService();
    private readonly Mock<IUnitOfWork> _unitOfWorkMock = new();

    private SmsCodeController CreateController(
        SmsLoginMode mode = SmsLoginMode.AutoProvision,
        string? profileKey = "test")
    {
        var controller = new SmsCodeController(
            _otpServiceMock.Object,
            _admissionServiceMock.Object,
            _auditServiceMock.Object,
            _unitOfWorkMock.Object,
            NullLogger<SmsCodeController>.Instance)
            .WithHttpContext();
        controller.HttpContext.Items[IdentityHeaders.ValidatedApp] = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "test-app",
            AppName = "Test App",
            AppSecretHash = "not-used-by-controller",
            IsActive = true,
            SmsLoginMode = mode,
            SmsProfileKey = profileKey
        };
        return controller;
    }

    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    private static bool HasCodeProperty(SmsCodeResponse response) =>
        JsonSerializer.SerializeToElement(response, WebJson).TryGetProperty("code", out _);

    /// <summary>
    /// With a phone present, the <c>Disabled</c> branch answers the existing message plus
    /// <c>code=SMS_LOGIN_DISABLED</c> — before the provider-profile and phone-format checks — and
    /// performs no admission lookup, OTP send, audit write, or save.
    /// </summary>
    [Theory]
    [InlineData("13800138000", "test")]
    [InlineData("13800138000", null)]
    [InlineData("12345", "test")]
    public async Task RequestSmsCode_UnderDisabledPolicy_ReturnsTheStableCode(string phone, string? profileKey)
    {
        var controller = CreateController(SmsLoginMode.Disabled, profileKey);

        var actionResult = await controller.RequestSmsCode(new SmsCodeRequest { Phone = phone }, CancellationToken.None);

        var response = Assert.IsType<SmsCodeResponse>(AuthTestDoubles.ExtractOk(actionResult).Value!);
        Assert.False(response.Success);
        Assert.Equal("SMS login is disabled for this application", response.Message);
        Assert.Equal(LegacyAuthResponseCodes.SmsLoginDisabled, response.Code);
        Assert.Equal(
            "SMS_LOGIN_DISABLED",
            JsonSerializer.SerializeToElement(response, WebJson).GetProperty("code").GetString());
        _admissionServiceMock.VerifyNoOtherCalls();
        _otpServiceMock.VerifyNoOtherCalls();
        _auditServiceMock.VerifyNoOtherCalls();
        _unitOfWorkMock.VerifyNoOtherCalls();
    }

    /// <summary>An empty phone is still checked first, so it gets the existing answer without a code.</summary>
    [Theory]
    [InlineData(SmsLoginMode.Disabled)]
    [InlineData(SmsLoginMode.AutoProvision)]
    public async Task RequestSmsCode_WithEmptyPhone_OmitsTheCodeInEveryMode(SmsLoginMode mode)
    {
        var controller = CreateController(mode);

        var actionResult = await controller.RequestSmsCode(new SmsCodeRequest { Phone = " " }, CancellationToken.None);

        var response = Assert.IsType<SmsCodeResponse>(AuthTestDoubles.ExtractOk(actionResult).Value!);
        Assert.False(response.Success);
        Assert.Equal("Phone number is required", response.Message);
        Assert.False(HasCodeProperty(response));
    }

    /// <summary>Every later failure under an enabled mode keeps its existing message and carries no code.</summary>
    [Theory]
    [InlineData("no-profile", "SMS provider is not configured for this application")]
    [InlineData("invalid-phone", "Invalid mainland China mobile number")]
    [InlineData("account-disabled", "Account is disabled")]
    [InlineData("access-revoked", "SMS access has been revoked")]
    [InlineData("not-authorized", "SMS account is not authorized for this application")]
    [InlineData("send-failure", "Failed to send verification code")]
    public async Task RequestSmsCode_OtherFailures_OmitTheCode(string scenario, string message)
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = scenario != "account-disabled" };
        var login = new UserLoginEntity { Id = Guid.NewGuid(), AccountId = account.Id };
        var access = new AppSmsAccessEntity
        {
            IsActive = scenario != "access-revoked",
            ApprovalSource = SmsAccessApprovalSource.AutoProvision
        };
        _admissionServiceMock
            .Setup(service => service.FindAsync(It.IsAny<Guid>(), "+8613800138000", It.IsAny<CancellationToken>()))
            .ReturnsAsync(scenario is "account-disabled" or "access-revoked" or "not-authorized"
                ? new SmsAdmission(account, login, access)
                : null);
        _otpServiceMock.Setup(o => o.GenerateAndSendAsync(
                It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("provider down"));
        var controller = CreateController(
            scenario == "not-authorized" ? SmsLoginMode.ManualApproval : SmsLoginMode.AutoProvision,
            scenario == "no-profile" ? null : "test");

        var actionResult = await controller.RequestSmsCode(
            new SmsCodeRequest { Phone = scenario == "invalid-phone" ? "12345" : "13800138000" },
            CancellationToken.None);

        var response = Assert.IsType<SmsCodeResponse>(AuthTestDoubles.ExtractOk(actionResult).Value!);
        Assert.False(response.Success);
        Assert.Equal(message, response.Message);
        Assert.Null(response.Code);
        Assert.False(HasCodeProperty(response));
    }

    [Fact]
    public async Task RequestSmsCode_WithEmptyPhone_ReturnsPhoneRequiredError()
    {
        var controller = CreateController();

        var request = new SmsCodeRequest { Phone = "" };

        var actionResult = await controller.RequestSmsCode(request, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<SmsCodeResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("Phone number is required", response.Message);
    }

    [Fact]
    public async Task RequestSmsCode_Success_ReturnsSentAndAudits()
    {
        using var cancellation = new CancellationTokenSource();
        _otpServiceMock.Setup(o => o.GenerateAndSendAsync(
                It.IsAny<Guid>(), "+8613800138000", "test", cancellation.Token))
            .ReturnsAsync("123456");
        _unitOfWorkMock
            .Setup(unitOfWork => unitOfWork.SaveChangesAsync(cancellation.Token))
            .ReturnsAsync(2);
        var controller = CreateController();

        var request = new SmsCodeRequest { Phone = "13800138000" };

        var actionResult = await controller.RequestSmsCode(request, cancellation.Token);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<SmsCodeResponse>(ok.Value!);
        Assert.True(response.Success);
        Assert.False(HasCodeProperty(response));
        _admissionServiceMock.Verify(service => service.FindAsync(
            It.IsAny<Guid>(), "+8613800138000", cancellation.Token), Times.Once);
        _otpServiceMock.Verify(service => service.GenerateAndSendAsync(
            It.IsAny<Guid>(), "+8613800138000", "test", cancellation.Token), Times.Once);
        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            null, "+8613800138000", "sms", "sms_code_sent",
            It.IsAny<string?>(), It.IsAny<string?>(), null,
            It.IsAny<string?>(), It.IsAny<string?>(), cancellation.Token), Times.Once);
        _unitOfWorkMock.Verify(
            unitOfWork => unitOfWork.SaveChangesAsync(cancellation.Token),
            Times.Once);
    }

    [Fact]
    public async Task RequestSmsCode_WhenFinalCommitIsCanceled_PropagatesCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        _otpServiceMock.Setup(o => o.GenerateAndSendAsync(
                It.IsAny<Guid>(), "+8613800138000", "test", cancellation.Token))
            .ReturnsAsync("123456");
        _unitOfWorkMock
            .Setup(unitOfWork => unitOfWork.SaveChangesAsync(cancellation.Token))
            .ThrowsAsync(new OperationCanceledException(cancellation.Token));
        var controller = CreateController();
        cancellation.Cancel();

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            controller.RequestSmsCode(
                new SmsCodeRequest { Phone = "13800138000" },
                cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            null, "+8613800138000", "sms", "sms_code_sent",
            It.IsAny<string?>(), It.IsAny<string?>(), null,
            It.IsAny<string?>(), It.IsAny<string?>(), cancellation.Token), Times.Once);
        _unitOfWorkMock.Verify(
            unitOfWork => unitOfWork.SaveChangesAsync(cancellation.Token),
            Times.Once);
    }

    [Fact]
    public async Task RequestSmsCode_OtpLocked_ReturnsLockMessage()
    {
        _otpServiceMock.Setup(o => o.GenerateAndSendAsync(
                It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Too many attempts. Please try again in 590 seconds."));
        var controller = CreateController();

        var request = new SmsCodeRequest { Phone = "13800138000" };

        var actionResult = await controller.RequestSmsCode(request, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<SmsCodeResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("Too many attempts. Please try again in 590 seconds.", response.Message);
        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            It.IsAny<Guid?>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
            It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<string?>(),
            It.IsAny<string?>(), It.IsAny<string?>()), Times.Never);
        _unitOfWorkMock.Verify(
            unitOfWork => unitOfWork.SaveChangesAsync(It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task RequestSmsCode_UnexpectedException_ReturnsGenericMessage()
    {
        _otpServiceMock.Setup(o => o.GenerateAndSendAsync(
                It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("smtp down"));
        var controller = CreateController();

        var request = new SmsCodeRequest { Phone = "13800138000" };

        var actionResult = await controller.RequestSmsCode(request, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<SmsCodeResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("Failed to send verification code", response.Message);
    }

    [Fact]
    public async Task RequestSmsCode_WhenAuditObservesCancellation_DoesNotCommitOrReturnSuccess()
    {
        using var cancellation = new CancellationTokenSource();
        _otpServiceMock.Setup(service => service.GenerateAndSendAsync(
                It.IsAny<Guid>(), It.IsAny<string>(), "test", cancellation.Token))
            .Callback(cancellation.Cancel)
            .ReturnsAsync("unused-code");
        _auditServiceMock.Setup(service => service.RecordLoginAsync(
                null, It.IsAny<string>(), "sms", "sms_code_sent",
                It.IsAny<string?>(), It.IsAny<string?>(), null, "test-app",
                It.IsAny<string?>(), cancellation.Token))
            .Returns(() => Task.FromCanceled(cancellation.Token));
        var controller = CreateController();

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => controller.RequestSmsCode(
            new SmsCodeRequest { Phone = "13800138000" }, cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        _admissionServiceMock.Verify(service => service.FindAsync(
            It.IsAny<Guid>(), It.IsAny<string>(), cancellation.Token), Times.Once);
        _otpServiceMock.Verify(service => service.GenerateAndSendAsync(
            It.IsAny<Guid>(), It.IsAny<string>(), "test", cancellation.Token), Times.Once);
        _auditServiceMock.Verify(service => service.RecordLoginAsync(
            null, It.IsAny<string>(), "sms", "sms_code_sent",
            It.IsAny<string?>(), It.IsAny<string?>(), null, "test-app",
            It.IsAny<string?>(), cancellation.Token), Times.Once);
        _unitOfWorkMock.VerifyNoOtherCalls();
    }
}
