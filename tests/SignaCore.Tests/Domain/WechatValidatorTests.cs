using System.Diagnostics.Metrics;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain;
using SignaCore.Domain.Services.WeChat;
using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.Tests.Domain.Validators;

public class WechatValidatorTests
{
    private const string OpenId = "test_openid";
    private static readonly Guid AppId = Guid.NewGuid();

    [Fact]
    public async Task BindRequired_WithBoundOpenId_ReturnsSuccessAndLoginId()
    {
        var admissionValue = Admission(accountActive: true, accessActive: true);
        var (validator, api, admission) = Create(admissionValue);

        var result = await validator.ValidateAsync(Request(WechatLoginMode.BindRequired));

        Assert.True(result.IsSuccess);
        Assert.Equal(IdentityConstants.AuthMethodWechat, result.AuthMethod);
        Assert.Equal(admissionValue.Account.Id, result.Account!.Id);
        Assert.Equal(admissionValue.Login.Id, result.WechatUserLoginId);
        api.Verify(client => client.CodeToSessionAsync("valid_code", It.IsAny<CancellationToken>()), Times.Once);
        admission.Verify(service => service.ProvisionAsync(
            It.IsAny<AppRegistrationEntity>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task DisabledMode_DoesNotCallWechatApi()
    {
        var (validator, api, _) = Create(null);

        var result = await validator.ValidateAsync(Request(WechatLoginMode.Disabled));

        Assert.False(result.IsSuccess);
        Assert.Equal("WeChat login is disabled for this application", result.ErrorMessage);
        api.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task BindRequired_WithUnboundOpenId_ReturnsFailureAndDoesNotProvision()
    {
        var (validator, _, admission) = Create(null);

        var result = await validator.ValidateAsync(Request(WechatLoginMode.BindRequired));

        Assert.False(result.IsSuccess);
        Assert.Equal("WeChat is not bound to any account", result.ErrorMessage);
        admission.Verify(service => service.ProvisionAsync(
            It.IsAny<AppRegistrationEntity>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task AutoProvision_WithUnknownOpenId_ProvisionsAccount()
    {
        var provisioned = Admission(accountActive: true, accessActive: true, accountCreated: true);
        var (validator, _, admission) = Create(null);
        admission.Setup(service => service.ProvisionAsync(
                It.IsAny<AppRegistrationEntity>(), OpenId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(provisioned);

        var result = await validator.ValidateAsync(Request(WechatLoginMode.AutoProvision));

        Assert.True(result.IsSuccess);
        Assert.Equal(provisioned.Login.Id, result.WechatUserLoginId);
    }

    [Fact]
    public async Task RevokedAccess_IsRejectedEvenInAutoProvisionMode()
    {
        var (validator, _, admission) = Create(Admission(accountActive: true, accessActive: false));

        var result = await validator.ValidateAsync(Request(WechatLoginMode.AutoProvision));

        Assert.False(result.IsSuccess);
        Assert.Equal("WeChat access has been revoked", result.ErrorMessage);
        admission.Verify(service => service.ProvisionAsync(
            It.IsAny<AppRegistrationEntity>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task InactiveAccount_ReturnsFailure()
    {
        var (validator, _, _) = Create(Admission(accountActive: false, accessActive: true));

        var result = await validator.ValidateAsync(Request(WechatLoginMode.BindRequired));

        Assert.False(result.IsSuccess);
        Assert.Equal("Account is disabled", result.ErrorMessage);
    }

    [Fact]
    public async Task EmptyCode_ReturnsFailure()
    {
        var (validator, api, _) = Create(null);

        var request = Request(WechatLoginMode.BindRequired);
        request.Code = "";
        var result = await validator.ValidateAsync(request);

        Assert.False(result.IsSuccess);
        Assert.Equal("WeChat code cannot be empty", result.ErrorMessage);
        api.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task FailedCodeToSession_ReturnsFailure()
    {
        var (validator, api, _) = Create(null);
        api.Setup(client => client.CodeToSessionAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string?)null);

        var result = await validator.ValidateAsync(Request(WechatLoginMode.BindRequired));

        Assert.False(result.IsSuccess);
        Assert.Equal("WeChat authentication failed", result.ErrorMessage);
    }

    [Fact]
    public void GrantType_ReturnsWechatCode()
    {
        var (validator, _, _) = Create(null);
        Assert.Equal(IdentityConstants.GrantTypeWechat, validator.GrantType);
    }

    private static WechatAdmission Admission(bool accountActive, bool accessActive, bool accountCreated = false)
    {
        var account = new AccountEntity { Id = Guid.NewGuid(), IsActive = accountActive };
        var login = new UserLoginEntity
        {
            Id = Guid.NewGuid(),
            AccountId = account.Id,
            ProviderName = IdentityConstants.AuthMethodWechat,
            ProviderUserId = OpenId
        };
        var access = new AppWechatAccessEntity
        {
            AppRegistrationId = AppId,
            UserLoginId = login.Id,
            IsActive = accessActive,
            ApprovalSource = WechatAccessApprovalSource.SelfBind
        };
        return new WechatAdmission(account, login, access, accountCreated);
    }

    private static (WechatValidator Validator, Mock<IWechatApiClient> Api, Mock<IWechatAdmissionService> Admission) Create(
        WechatAdmission? admissionValue)
    {
        var api = new Mock<IWechatApiClient>();
        api.Setup(client => client.CodeToSessionAsync("valid_code", It.IsAny<CancellationToken>()))
            .ReturnsAsync(OpenId);
        var admission = new Mock<IWechatAdmissionService>();
        admission.Setup(service => service.FindAsync(AppId, OpenId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(admissionValue);
        var meterFactory = new Mock<IMeterFactory>();
        meterFactory.Setup(factory => factory.Create(It.IsAny<MeterOptions>()))
            .Returns(new Meter("wechat-validator-tests"));
        return (
            new WechatValidator(api.Object, admission.Object, new AuthMetrics(meterFactory.Object),
                NullLogger<WechatValidator>.Instance),
            api,
            admission);
    }

    private static ValidationRequest Request(WechatLoginMode mode) => new()
    {
        GrantType = IdentityConstants.GrantTypeWechat,
        App = new AppRegistrationEntity { Id = AppId, AppId = "app-1", WechatLoginMode = mode },
        Code = "valid_code"
    };
}
