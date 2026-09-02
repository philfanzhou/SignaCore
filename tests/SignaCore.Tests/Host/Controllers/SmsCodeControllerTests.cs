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

    private SmsCodeController CreateController()
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
            SmsLoginMode = SmsLoginMode.AutoProvision,
            SmsProfileKey = "test"
        };
        return controller;
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
        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            null, "+8613800138000", "sms", "sms_code_sent",
            It.IsAny<string?>(), It.IsAny<string?>(), null,
            It.IsAny<string?>(), It.IsAny<string?>()), Times.Once);
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
            It.IsAny<string?>(), It.IsAny<string?>()), Times.Once);
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
}
