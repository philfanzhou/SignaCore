using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services.Sms;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

public class DbOtpServiceTests
{
    private readonly Guid _appId = Guid.NewGuid();
    private readonly Mock<IOtpRepository> _repository = new();
    private readonly Mock<IUnitOfWork> _unitOfWork = new();
    private readonly Mock<ISmsSender> _sender = new();
    private readonly DbOtpService _service;

    public DbOtpServiceTests()
    {
        var options = new SmsOptions
        {
            OtpHmacKey = Convert.ToBase64String(Enumerable.Range(1, 32).Select(value => (byte)value).ToArray()),
            MinSendIntervalSeconds = 60,
            MaxSendsPerHour = 5,
            MaxSendsPerDay = 10,
            Profiles = new Dictionary<string, SmsProviderProfile>(StringComparer.OrdinalIgnoreCase)
            {
                ["test"] = new() { Provider = "Test" }
            }
        };
        _sender.SetupGet(value => value.Provider).Returns("Test");
        _sender.Setup(value => value.SendAsync(
                It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SmsSendResult("Test", "message-1"));
        _unitOfWork.Setup(value => value.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);
        _service = new DbOtpService(options, NullLogger<DbOtpService>.Instance, _repository.Object,
            _unitOfWork.Object, new SmsSenderResolver([_sender.Object], options));
    }

    [Fact]
    public async Task Generate_StoresMacAndAppBinding_ThenMarksSent()
    {
        OtpEntity? stored = null;
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000")).ReturnsAsync((OtpEntity?)null);
        _repository.Setup(value => value.AddAsync(It.IsAny<OtpEntity>()))
            .Callback<OtpEntity>(value => stored = value).Returns(Task.CompletedTask);

        var code = await _service.GenerateAndSendAsync(_appId, "13800138000", "test");

        Assert.NotNull(stored);
        Assert.Equal(_appId, stored.AppRegistrationId);
        Assert.Equal(64, stored.CodeMac.Length);
        Assert.DoesNotContain(code, stored.CodeMac, StringComparison.Ordinal);
        Assert.Equal(OtpStatus.Sent, stored.Status);
        Assert.Equal("message-1", stored.ProviderMessageId);
    }

    [Fact]
    public async Task Verify_ConsumesOnlyMatchingApplicationChallenge()
    {
        OtpEntity? stored = null;
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000"))
            .ReturnsAsync(() => stored);
        _repository.Setup(value => value.AddAsync(It.IsAny<OtpEntity>()))
            .Callback<OtpEntity>(value => stored = value).Returns(Task.CompletedTask);
        var code = await _service.GenerateAndSendAsync(_appId, "+8613800138000", "test");
        _repository.Setup(value => value.TryConsumeAsync(
            _appId, "+8613800138000", stored!.CodeMac, It.IsAny<DateTimeOffset>(), It.IsAny<int>())).ReturnsAsync(true);

        Assert.True(await _service.VerifyAsync(_appId, "13800138000", code));
        _repository.Verify(value => value.TryConsumeAsync(
            _appId, "+8613800138000", stored!.CodeMac, It.IsAny<DateTimeOffset>(), It.IsAny<int>()), Times.Once);
    }

    [Fact]
    public async Task Generate_EnforcesPersistentCooldown()
    {
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000")).ReturnsAsync(new OtpEntity
        {
            AppRegistrationId = _appId,
            Phone = "+8613800138000",
            CreatedAt = DateTimeOffset.UtcNow,
            HourWindowStartedAt = DateTimeOffset.UtcNow,
            DayWindowStartedAt = DateTimeOffset.UtcNow
        });
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.GenerateAndSendAsync(_appId, "+8613800138000", "test"));
        _sender.Verify(value => value.SendAsync(
            It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
