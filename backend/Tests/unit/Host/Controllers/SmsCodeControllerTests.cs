using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Domain.Services.Sms;
using QuantumZhou.Identity.Host.Controllers;
using QuantumZhou.Identity.Host.Http;
using QuantumZhou.Identity.Host.Models;
using Xunit;

namespace QuantumZhou.Identity.Tests.Host.Controllers;

public class SmsCodeControllerTests
{
    private readonly Mock<IOtpService> _otpServiceMock = new();
    private readonly Mock<ISmsSender> _smsSenderMock = new();
    private readonly Mock<IAppRegistrationRepository> _appRegistrationRepoMock = new();
    private readonly Mock<IAuditService> _auditServiceMock = AuthTestDoubles.AuditService();

    private SmsCodeController CreateController() =>
        new SmsCodeController(
            _otpServiceMock.Object,
            _smsSenderMock.Object,
            AuthTestDoubles.GatewayValidator(_appRegistrationRepoMock),
            _auditServiceMock.Object,
            NullLogger<SmsCodeController>.Instance)
            .WithHttpContext();

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
        _otpServiceMock.Setup(o => o.GenerateAndSendAsync("13800138000", _smsSenderMock.Object))
            .ReturnsAsync("123456");
        var controller = CreateController();

        var request = new SmsCodeRequest { Phone = "13800138000" };

        var actionResult = await controller.RequestSmsCode(request, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<SmsCodeResponse>(ok.Value!);
        Assert.True(response.Success);
        _auditServiceMock.Verify(a => a.RecordLoginAsync(
            null, "13800138000", "sms", "sms_code_sent",
            It.IsAny<string?>(), It.IsAny<string?>(), null,
            It.IsAny<string?>(), It.IsAny<string?>()), Times.Once);
    }

    [Fact]
    public async Task RequestSmsCode_GatewayValidationFails_ReturnsFailure()
    {
        var controller = CreateController();
        controller.HttpContext.Request.Headers[IdentityHeaders.AppId] = "unregistered-app";
        controller.HttpContext.Request.Headers[IdentityHeaders.AppSecret] = "any-secret";

        var request = new SmsCodeRequest { Phone = "13800138000" };

        var actionResult = await controller.RequestSmsCode(request, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<SmsCodeResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("AppId not registered", response.Message);
        _otpServiceMock.Verify(o => o.GenerateAndSendAsync(It.IsAny<string>(), It.IsAny<ISmsSender>()), Times.Never);
    }

    [Fact]
    public async Task RequestSmsCode_OtpLocked_ReturnsLockMessage()
    {
        _otpServiceMock.Setup(o => o.GenerateAndSendAsync(It.IsAny<string>(), It.IsAny<ISmsSender>()))
            .ThrowsAsync(new InvalidOperationException("Too many attempts. Please try again in 590 seconds."));
        var controller = CreateController();

        var request = new SmsCodeRequest { Phone = "13800138000" };

        var actionResult = await controller.RequestSmsCode(request, CancellationToken.None);

        var ok = AuthTestDoubles.ExtractOk(actionResult);
        var response = Assert.IsType<SmsCodeResponse>(ok.Value!);
        Assert.False(response.Success);
        Assert.Equal("Too many attempts. Please try again in 590 seconds.", response.Message);
    }

    [Fact]
    public async Task RequestSmsCode_UnexpectedException_ReturnsGenericMessage()
    {
        _otpServiceMock.Setup(o => o.GenerateAndSendAsync(It.IsAny<string>(), It.IsAny<ISmsSender>()))
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
