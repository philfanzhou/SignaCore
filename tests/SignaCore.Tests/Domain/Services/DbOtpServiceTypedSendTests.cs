using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services.Sms;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

/// <summary>
/// The typed browser send path of <see cref="DbOtpService"/> (#444): every closed
/// <see cref="OtpSendOutcome"/> is decided at the same point, with the same writes and provider
/// contact, as the legacy <see cref="DbOtpService.GenerateAndSendAsync"/> path — which keeps its
/// exact exceptions and messages for <c>POST /api/auth/sms-code</c>.
/// </summary>
public sealed class DbOtpServiceTypedSendTests
{
    private const string Phone = "+8613800138000";

    private readonly Guid _appId = Guid.NewGuid();
    private readonly Mock<IOtpRepository> _repository = new();
    private readonly Mock<IUnitOfWork> _unitOfWork = new();
    private readonly Mock<ISmsSender> _sender = new();
    private readonly SmsOptions _options;
    private readonly DbOtpService _service;
    private OtpEntity? _stored;

    public DbOtpServiceTypedSendTests()
    {
        _options = new SmsOptions
        {
            OtpHmacKey = Convert.ToBase64String(Enumerable.Range(1, 32).Select(value => (byte)value).ToArray()),
            MinSendIntervalSeconds = 60,
            MaxSendsPerHour = 5,
            MaxSendsPerDay = 10,
            Profiles = new Dictionary<string, SmsProviderProfile>(StringComparer.OrdinalIgnoreCase)
            {
                ["test"] = new() { Provider = "Test" },
                ["unregistered-provider"] = new() { Provider = "Nobody" }
            }
        };
        _sender.SetupGet(value => value.Provider).Returns("Test");
        _sender.Setup(value => value.SendAsync(
                It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SmsSendResult("Test", "message-1"));
        _unitOfWork.Setup(value => value.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);
        _repository.Setup(value => value.AddAsync(It.IsAny<OtpEntity>(), It.IsAny<CancellationToken>()))
            .Callback<OtpEntity, CancellationToken>((value, _) => _stored = value)
            .Returns(Task.CompletedTask);
        _service = new DbOtpService(_options, NullLogger<DbOtpService>.Instance, _repository.Object,
            _unitOfWork.Object, new SmsSenderResolver([_sender.Object], _options));
    }

    [Fact]
    public async Task Sent_CommitsThePreDeliveryState_CallsTheProvider_AndOnlyStagesSent()
    {
        GivenExisting(null);
        var statuses = new List<OtpStatus>();
        _unitOfWork.Setup(value => value.SaveChangesAsync(It.IsAny<CancellationToken>()))
            .Callback(() => statuses.Add(_stored!.Status))
            .ReturnsAsync(1);

        var outcome = await _service.TrySendAsync(_appId, "13800138000", "test", TestContext.Current.CancellationToken);

        Assert.Equal(OtpSendOutcome.Sent, outcome);
        Assert.Equal([OtpStatus.PendingDelivery], statuses);
        Assert.Equal(OtpStatus.Sent, _stored!.Status);
        Assert.Equal("message-1", _stored.ProviderMessageId);
        VerifyProviderCalls(Times.Once());
    }

    public static TheoryData<string, OtpSendOutcome> Limits => new()
    {
        { "locked", OtpSendOutcome.Locked },
        { "interval", OtpSendOutcome.ResendInterval },
        { "hourly", OtpSendOutcome.HourlyWindow },
        { "daily", OtpSendOutcome.DailyWindow },
        // Lockout precedes every window; the interval precedes both windows.
        { "locked+interval+hourly+daily", OtpSendOutcome.Locked },
        { "interval+hourly+daily", OtpSendOutcome.ResendInterval },
        { "hourly+daily", OtpSendOutcome.HourlyWindow }
    };

    [Theory]
    [MemberData(nameof(Limits))]
    public async Task EachPerPhoneLimit_IsItsOwnOutcome_WithNoWriteAndNoProviderCall(string limits, OtpSendOutcome expected)
    {
        var now = DateTimeOffset.UtcNow;
        var parts = limits.Split('+');
        GivenExisting(new OtpEntity
        {
            AppRegistrationId = _appId,
            Phone = Phone,
            LockoutUntil = parts.Contains("locked") ? now.AddMinutes(5) : DateTimeOffset.UnixEpoch,
            CreatedAt = parts.Contains("interval") ? now : now.AddHours(-2),
            HourWindowStartedAt = parts.Contains("hourly") ? now.AddMinutes(-30) : now.AddHours(-2),
            HourSendCount = parts.Contains("hourly") ? 5 : 1,
            DayWindowStartedAt = now.AddHours(-2),
            DaySendCount = parts.Contains("daily") ? 10 : 1
        });

        var outcome = await _service.TrySendAsync(_appId, Phone, "test", TestContext.Current.CancellationToken);
        var legacy = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.GenerateAndSendAsync(_appId, Phone, "test", TestContext.Current.CancellationToken));

        Assert.Equal(expected, outcome);
        Assert.Equal(expected switch
        {
            OtpSendOutcome.Locked => "Too many verification attempts. Please try again later.",
            OtpSendOutcome.ResendInterval => "Verification code requested too frequently.",
            OtpSendOutcome.HourlyWindow => "Hourly verification-code limit exceeded.",
            _ => "Daily verification-code limit exceeded."
        }, legacy.Message);
        _unitOfWork.Verify(value => value.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Never);
        VerifyProviderCalls(Times.Never());
    }

    [Theory]
    [InlineData("missing-profile", "The application's SMS provider profile is not configured.")]
    [InlineData("unregistered-provider", "The configured SMS provider is unavailable.")]
    public async Task AnUnusableProfile_IsProfileMissing_BeforeAnyWrite(string profileKey, string legacyMessage)
    {
        GivenExisting(null);

        var outcome = await _service.TrySendAsync(_appId, Phone, profileKey, TestContext.Current.CancellationToken);
        var legacy = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.GenerateAndSendAsync(_appId, Phone, profileKey, TestContext.Current.CancellationToken));

        Assert.Equal(OtpSendOutcome.ProfileMissing, outcome);
        Assert.Equal(legacyMessage, legacy.Message);
        _repository.Verify(value => value.AddAsync(It.IsAny<OtpEntity>(), It.IsAny<CancellationToken>()), Times.Never);
        _unitOfWork.Verify(value => value.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Never);
        VerifyProviderCalls(Times.Never());
    }

    [Fact]
    public async Task AConcurrentPreDeliveryWrite_IsResendInterval_WithNoProviderCall()
    {
        GivenExisting(null);
        _unitOfWork.Setup(value => value.SaveChangesAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new DbUpdateException());

        var outcome = await _service.TrySendAsync(_appId, Phone, "test", TestContext.Current.CancellationToken);
        var legacy = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.GenerateAndSendAsync(_appId, Phone, "test", TestContext.Current.CancellationToken));

        Assert.Equal(OtpSendOutcome.ResendInterval, outcome);
        Assert.Equal("A verification code is already being sent. Please try again later.", legacy.Message);
        VerifyProviderCalls(Times.Never());
    }

    [Fact]
    public async Task AProviderRejection_IsProviderFailed_AndCommitsDeliveryFailed()
    {
        GivenExisting(null);
        _sender.Setup(value => value.SendAsync(
                It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new SmsDeliveryRejectedException("Rejected", "provider-internal-detail"));

        var outcome = await _service.TrySendAsync(_appId, Phone, "test", TestContext.Current.CancellationToken);

        Assert.Equal(OtpSendOutcome.ProviderFailed, outcome);
        Assert.Equal(OtpStatus.DeliveryFailed, _stored!.Status);
        _unitOfWork.Verify(value => value.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Exactly(2));
        VerifyProviderCalls(Times.Once());
    }

    [Fact]
    public async Task AnyOtherProviderFailure_IsProviderFailed_AndLeavesPendingDelivery()
    {
        GivenExisting(null);
        var failure = new InvalidOperationException("provider-internal-canary");
        _sender.Setup(value => value.SendAsync(
                It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(failure);

        var outcome = await _service.TrySendAsync(_appId, Phone, "test", TestContext.Current.CancellationToken);

        Assert.Equal(OtpSendOutcome.ProviderFailed, outcome);
        Assert.Equal(OtpStatus.PendingDelivery, _stored!.Status);
        _unitOfWork.Verify(value => value.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TheLegacyPath_RethrowsTheProvidersOwnException_Unchanged(bool invalidOperation)
    {
        // POST /api/auth/sms-code answers an InvalidOperationException with its message and any
        // other exception with its generic failure: the provider's exception must reach it as is.
        GivenExisting(null);
        Exception failure = invalidOperation
            ? new InvalidOperationException("provider-message")
            : new HttpRequestException("provider-transport");
        _sender.Setup(value => value.SendAsync(
                It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(failure);

        var thrown = await Assert.ThrowsAnyAsync<Exception>(() =>
            _service.GenerateAndSendAsync(_appId, Phone, "test", TestContext.Current.CancellationToken));

        Assert.Same(failure, thrown);
    }

    [Fact]
    public async Task CallerCancellationDuringTheProviderCall_Propagates()
    {
        using var cancellation = new CancellationTokenSource();
        GivenExisting(null, cancellation.Token);
        _sender.Setup(value => value.SendAsync(
                It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), cancellation.Token))
            .Returns(async () =>
            {
                await cancellation.CancelAsync();
                cancellation.Token.ThrowIfCancellationRequested();
                return new SmsSendResult("Test", "never");
            });

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _service.TrySendAsync(_appId, Phone, "test", cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Equal(OtpStatus.PendingDelivery, _stored!.Status);
    }

    [Fact]
    public async Task AProviderTimeoutThatIsNotCallerCancellation_IsProviderFailed()
    {
        GivenExisting(null);
        _sender.Setup(value => value.SendAsync(
                It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TaskCanceledException("provider timeout"));

        var outcome = await _service.TrySendAsync(_appId, Phone, "test", TestContext.Current.CancellationToken);

        Assert.Equal(OtpSendOutcome.ProviderFailed, outcome);
    }

    private void GivenExisting(OtpEntity? existing, CancellationToken? token = null)
    {
        if (token is { } exact)
        {
            _repository.Setup(value => value.GetAsync(_appId, Phone, exact)).ReturnsAsync(existing);
        }
        else
        {
            _repository.Setup(value => value.GetAsync(_appId, Phone, It.IsAny<CancellationToken>())).ReturnsAsync(existing);
        }
    }

    private void VerifyProviderCalls(Times times) =>
        _sender.Verify(value => value.SendAsync(
            It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), It.IsAny<CancellationToken>()), times);
}
