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
            .Callback<OtpEntity, CancellationToken>((value, _) => stored = value)
            .Returns(Task.CompletedTask);

        var code = await _service.GenerateAndSendAsync(_appId, "13800138000", "test", TestContext.Current.CancellationToken);

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
            .Callback<OtpEntity, CancellationToken>((value, _) => stored = value)
            .Returns(Task.CompletedTask);
        var code = await _service.GenerateAndSendAsync(_appId, "+8613800138000", "test", TestContext.Current.CancellationToken);
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
            _service.GenerateAndSendAsync(_appId, "+8613800138000", "test", TestContext.Current.CancellationToken));
        _sender.Verify(value => value.SendAsync(
            It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Generate_WhenChallengeCreationConflicts_DoesNotSend()
    {
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000"))
            .ReturnsAsync((OtpEntity?)null);
        _repository.Setup(value => value.AddAsync(It.IsAny<OtpEntity>())).Returns(Task.CompletedTask);
        _unitOfWork.Setup(value => value.SaveChangesAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Microsoft.EntityFrameworkCore.DbUpdateException());

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.GenerateAndSendAsync(
                _appId,
                "+8613800138000",
                "test",
                TestContext.Current.CancellationToken));

        Assert.Contains("already being sent", exception.Message, StringComparison.Ordinal);
        _sender.Verify(value => value.SendAsync(
            It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Generate_WhenProviderRejects_MarksDeliveryFailedAndReturnsSafeError()
    {
        OtpEntity? stored = null;
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000"))
            .ReturnsAsync((OtpEntity?)null);
        _repository.Setup(value => value.AddAsync(It.IsAny<OtpEntity>()))
            .Callback<OtpEntity, CancellationToken>((value, _) => stored = value)
            .Returns(Task.CompletedTask);
        _sender.Setup(value => value.SendAsync(
                It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new SmsDeliveryRejectedException("Rejected", "provider-internal-detail"));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.GenerateAndSendAsync(
                _appId,
                "+8613800138000",
                "test",
                TestContext.Current.CancellationToken));

        Assert.NotNull(stored);
        Assert.Equal(OtpStatus.DeliveryFailed, stored.Status);
        Assert.DoesNotContain("provider-internal-detail", exception.Message, StringComparison.Ordinal);
        _unitOfWork.Verify(
            value => value.SaveChangesAsync(It.IsAny<CancellationToken>()),
            Times.Exactly(2));
    }

    [Fact]
    public async Task Verify_WithWrongCode_IncrementsPersistentAttempts()
    {
        OtpEntity? stored = null;
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000"))
            .ReturnsAsync(() => stored);
        _repository.Setup(value => value.AddAsync(It.IsAny<OtpEntity>()))
            .Callback<OtpEntity, CancellationToken>((value, _) => stored = value)
            .Returns(Task.CompletedTask);
        await _service.GenerateAndSendAsync(
            _appId,
            "+8613800138000",
            "test",
            TestContext.Current.CancellationToken);
        _repository.Setup(value => value.IncrementFailedAttemptsAsync(
                _appId,
                "+8613800138000",
                stored!.CodeMac,
                It.IsAny<DateTimeOffset>(),
                It.IsAny<int>(),
                It.IsAny<DateTimeOffset>()))
            .ReturnsAsync(1);

        Assert.False(await _service.VerifyAsync(_appId, "+8613800138000", "000000"));
        _repository.Verify(value => value.IncrementFailedAttemptsAsync(
            _appId,
            "+8613800138000",
            stored!.CodeMac,
            It.IsAny<DateTimeOffset>(),
            It.IsAny<int>(),
            It.IsAny<DateTimeOffset>()), Times.Once);
        _repository.Verify(value => value.TryConsumeAsync(
            It.IsAny<Guid>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<DateTimeOffset>(),
            It.IsAny<int>()), Times.Never);
    }

    [Theory]
    [InlineData(OtpStatus.PendingDelivery, false, false)]
    [InlineData(OtpStatus.Sent, true, false)]
    [InlineData(OtpStatus.Sent, false, true)]
    public async Task Verify_WhenChallengeCannotBeUsed_ReturnsFalseWithoutMutation(
        OtpStatus status,
        bool expired,
        bool locked)
    {
        var now = DateTimeOffset.UtcNow;
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000"))
            .ReturnsAsync(new OtpEntity
            {
                AppRegistrationId = _appId,
                Phone = "+8613800138000",
                Status = status,
                ExpiresAt = expired ? now.AddMinutes(-1) : now.AddMinutes(1),
                LockoutUntil = locked ? now.AddMinutes(1) : DateTimeOffset.UnixEpoch
            });

        Assert.False(await _service.VerifyAsync(_appId, "+8613800138000", "123456"));
        _repository.Verify(value => value.TryConsumeAsync(
            It.IsAny<Guid>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<DateTimeOffset>(),
            It.IsAny<int>()), Times.Never);
        _repository.Verify(value => value.IncrementFailedAttemptsAsync(
            It.IsAny<Guid>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<DateTimeOffset>(),
            It.IsAny<int>(),
            It.IsAny<DateTimeOffset>()), Times.Never);
    }

    [Fact]
    public async Task Invalidate_WithExistingChallenge_MarksItConsumed()
    {
        var existing = new OtpEntity { Status = OtpStatus.Sent };
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000"))
            .ReturnsAsync(existing);

        await _service.InvalidateAsync(_appId, "+8613800138000");

        Assert.Equal(OtpStatus.Consumed, existing.Status);
        _unitOfWork.Verify(value => value.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Invalidate_WithoutChallenge_DoesNotWrite()
    {
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000"))
            .ReturnsAsync((OtpEntity?)null);

        await _service.InvalidateAsync(_appId, "+8613800138000");

        _unitOfWork.Verify(value => value.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Generate_EnforcesPersistentHourAndDayLimits(bool hourlyLimit)
    {
        var now = DateTimeOffset.UtcNow;
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000"))
            .ReturnsAsync(new OtpEntity
            {
                AppRegistrationId = _appId,
                Phone = "+8613800138000",
                CreatedAt = now.AddHours(-2),
                LockoutUntil = DateTimeOffset.UnixEpoch,
                HourWindowStartedAt = hourlyLimit ? now.AddMinutes(-30) : now.AddHours(-2),
                HourSendCount = 5,
                DayWindowStartedAt = now.AddHours(-2),
                DaySendCount = hourlyLimit ? 5 : 10
            });

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.GenerateAndSendAsync(
                _appId,
                "+8613800138000",
                "test",
                TestContext.Current.CancellationToken));

        Assert.Contains(hourlyLimit ? "Hourly" : "Daily", exception.Message, StringComparison.Ordinal);
        _sender.Verify(value => value.SendAsync(
            It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
