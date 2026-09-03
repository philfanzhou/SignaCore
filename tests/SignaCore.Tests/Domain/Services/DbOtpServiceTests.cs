using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
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
        var events = new List<string>();
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000", TestContext.Current.CancellationToken)).ReturnsAsync((OtpEntity?)null);
        _repository.Setup(value => value.AddAsync(It.IsAny<OtpEntity>(), TestContext.Current.CancellationToken))
            .Callback<OtpEntity, CancellationToken>((value, _) => stored = value)
            .Returns(Task.CompletedTask);
        _unitOfWork.Setup(value => value.SaveChangesAsync(It.IsAny<CancellationToken>()))
            .Callback<CancellationToken>(_ => events.Add($"save:{stored!.Status}"))
            .ReturnsAsync(1);
        _sender.Setup(value => value.SendAsync(
                It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), It.IsAny<CancellationToken>()))
            .Callback<SmsProviderProfile, SmsVerificationMessage, CancellationToken>(
                (_, _, _) => events.Add("send"))
            .ReturnsAsync(new SmsSendResult("Test", "message-1"));

        var code = await _service.GenerateAndSendAsync(_appId, "13800138000", "test", TestContext.Current.CancellationToken);

        Assert.NotNull(stored);
        Assert.Equal(_appId, stored.AppRegistrationId);
        Assert.Equal(64, stored.CodeMac.Length);
        Assert.DoesNotContain(code, stored.CodeMac, StringComparison.Ordinal);
        Assert.Equal(OtpStatus.Sent, stored.Status);
        Assert.Equal("message-1", stored.ProviderMessageId);
        Assert.NotNull(stored.SentAt);
        Assert.Equal(["save:PendingDelivery", "send"], events);
        _unitOfWork.Verify(
            value => value.SaveChangesAsync(TestContext.Current.CancellationToken),
            Times.Once);
    }

    [Fact]
    public async Task Verify_WithMatchingCode_ReturnsDeferredConsumptionWithoutWriting()
    {
        OtpEntity? stored = null;
        _repository.Setup(value => value.GetAsync(
                _appId,
                "+8613800138000",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => stored);
        _repository.Setup(value => value.AddAsync(It.IsAny<OtpEntity>(), TestContext.Current.CancellationToken))
            .Callback<OtpEntity, CancellationToken>((value, _) => stored = value)
            .Returns(Task.CompletedTask);
        var code = await _service.GenerateAndSendAsync(_appId, "+8613800138000", "test", TestContext.Current.CancellationToken);
        var result = await _service.VerifyAsync(
            _appId,
            "13800138000",
            code,
            TestContext.Current.CancellationToken);

        Assert.True(result.IsVerified);
        Assert.NotNull(result.Change);
        Assert.Equal(OtpVerificationChangeKind.Consume, result.Change.Kind);
        Assert.Equal(_appId, result.Change.AppRegistrationId);
        Assert.Equal("+8613800138000", result.Change.Phone);
        Assert.Equal(stored!.CodeMac, result.Change.ExpectedCodeMac);
        _repository.Verify(value => value.GetAsync(
            _appId,
            "+8613800138000",
            TestContext.Current.CancellationToken), Times.Exactly(2));
        _repository.Verify(value => value.TryConsumeAsync(
            It.IsAny<Guid>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<DateTimeOffset>(),
            It.IsAny<int>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Generate_EnforcesPersistentCooldown()
    {
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000", TestContext.Current.CancellationToken)).ReturnsAsync(new OtpEntity
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
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000", TestContext.Current.CancellationToken))
            .ReturnsAsync((OtpEntity?)null);
        _repository.Setup(value => value.AddAsync(It.IsAny<OtpEntity>(), TestContext.Current.CancellationToken)).Returns(Task.CompletedTask);
        _unitOfWork.Setup(value => value.SaveChangesAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Microsoft.EntityFrameworkCore.DbUpdateException());

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.GenerateAndSendAsync(
                _appId,
                "+8613800138000",
                "test",
                TestContext.Current.CancellationToken));

        Assert.Contains("already being sent", exception.Message, StringComparison.Ordinal);
        _unitOfWork.Verify(
            value => value.SaveChangesAsync(TestContext.Current.CancellationToken),
            Times.Once);
        _sender.Verify(value => value.SendAsync(
            It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Generate_WhenProviderRejects_MarksDeliveryFailedAndReturnsSafeError()
    {
        OtpEntity? stored = null;
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000", TestContext.Current.CancellationToken))
            .ReturnsAsync((OtpEntity?)null);
        _repository.Setup(value => value.AddAsync(It.IsAny<OtpEntity>(), TestContext.Current.CancellationToken))
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
            value => value.SaveChangesAsync(TestContext.Current.CancellationToken),
            Times.Exactly(2));
        _repository.Verify(value => value.GetAsync(
            _appId, "+8613800138000", TestContext.Current.CancellationToken), Times.Once);
        _repository.Verify(value => value.AddAsync(
            It.IsAny<OtpEntity>(), TestContext.Current.CancellationToken), Times.Once);
        _sender.Verify(value => value.SendAsync(
            It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(),
            TestContext.Current.CancellationToken), Times.Once);
    }

    [Fact]
    public async Task Verify_WithWrongCode_ReturnsDeferredFailureWithoutWriting()
    {
        OtpEntity? stored = null;
        _repository.Setup(value => value.GetAsync(
                _appId,
                "+8613800138000",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => stored);
        _repository.Setup(value => value.AddAsync(It.IsAny<OtpEntity>(), TestContext.Current.CancellationToken))
            .Callback<OtpEntity, CancellationToken>((value, _) => stored = value)
            .Returns(Task.CompletedTask);
        await _service.GenerateAndSendAsync(
            _appId,
            "+8613800138000",
            "test",
            TestContext.Current.CancellationToken);
        var result = await _service.VerifyAsync(
            _appId,
            "+8613800138000",
            "000000",
            TestContext.Current.CancellationToken);

        Assert.False(result.IsVerified);
        Assert.NotNull(result.Change);
        Assert.Equal(OtpVerificationChangeKind.RecordFailure, result.Change.Kind);
        Assert.Equal(stored!.CodeMac, result.Change.ExpectedCodeMac);
        _repository.Verify(value => value.IncrementFailedAttemptsAsync(
            It.IsAny<Guid>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<DateTimeOffset>(),
            It.IsAny<int>(),
            It.IsAny<DateTimeOffset>(),
            It.IsAny<CancellationToken>()), Times.Never);
        _repository.Verify(value => value.TryConsumeAsync(
            It.IsAny<Guid>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<DateTimeOffset>(),
            It.IsAny<int>(),
            It.IsAny<CancellationToken>()), Times.Never);
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
        _repository.Setup(value => value.GetAsync(
                _appId,
                "+8613800138000",
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new OtpEntity
            {
                AppRegistrationId = _appId,
                Phone = "+8613800138000",
                Status = status,
                ExpiresAt = expired ? now.AddMinutes(-1) : now.AddMinutes(1),
                LockoutUntil = locked ? now.AddMinutes(1) : DateTimeOffset.UnixEpoch
            });

        var result = await _service.VerifyAsync(
            _appId,
            "+8613800138000",
            "123456",
            TestContext.Current.CancellationToken);

        Assert.False(result.IsVerified);
        Assert.Null(result.Change);
        _repository.Verify(value => value.TryConsumeAsync(
            It.IsAny<Guid>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<DateTimeOffset>(),
            It.IsAny<int>(),
            It.IsAny<CancellationToken>()), Times.Never);
        _repository.Verify(value => value.IncrementFailedAttemptsAsync(
            It.IsAny<Guid>(),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<DateTimeOffset>(),
            It.IsAny<int>(),
            It.IsAny<DateTimeOffset>(),
            It.IsAny<CancellationToken>()), Times.Never);
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
    [InlineData(false)]
    [InlineData(true)]
    public async Task Invalidate_ForwardsTokenAndOnlySavesExistingChallenge(bool exists)
    {
        using var cancellation = new CancellationTokenSource();
        var entry = exists ? new OtpEntity { Status = OtpStatus.Sent } : null;
        _repository.Setup(repository => repository.GetAsync(_appId, "+8613800138000", cancellation.Token))
            .ReturnsAsync(entry);

        await _service.InvalidateAsync(_appId, "13800138000", cancellation.Token);

        _repository.Verify(repository => repository.GetAsync(_appId, "+8613800138000", cancellation.Token), Times.Once);
        _repository.VerifyNoOtherCalls();
        _unitOfWork.Verify(unit => unit.SaveChangesAsync(cancellation.Token), exists ? Times.Once() : Times.Never());
        _unitOfWork.VerifyNoOtherCalls();
        if (exists) Assert.Equal(OtpStatus.Consumed, entry!.Status);
    }

    [Fact]
    public async Task Invalidate_CancelledRead_DoesNotSave()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        _repository.Setup(repository => repository.GetAsync(_appId, "+8613800138000", cancellation.Token))
            .Returns(Task.FromCanceled<OtpEntity?>(cancellation.Token));

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _service.InvalidateAsync(_appId, "13800138000", cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        _unitOfWork.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Invalidate_CancelBeforeSave_DoesNotConsumePersistedOtp()
    {
        using var cancellation = new CancellationTokenSource();
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var databaseOptions = new DbContextOptionsBuilder<IdentityDbContext>().UseSqlite(connection).Options;
        await using var context = new IdentityDbContext(databaseOptions);
        await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = _appId, AppId = "otp-cancellation-app", AppName = "OTP cancellation app",
            AppSecretHash = "unused-test-hash", IsActive = true
        });
        context.Otps.Add(new OtpEntity
        {
            Id = Guid.NewGuid(), AppRegistrationId = _appId, Phone = "+8613800138000",
            Status = OtpStatus.Sent, Attempts = 2, Version = 3
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        _unitOfWork.Setup(unit => unit.SaveChangesAsync(It.IsAny<CancellationToken>()))
            .Returns((CancellationToken ct) =>
            {
                Assert.Equal(cancellation.Token, ct);
                cancellation.Cancel();
                return context.SaveChangesAsync(ct);
            });
        var options = new SmsOptions { OtpHmacKey = Convert.ToBase64String(new byte[32]) };
        var service = new DbOtpService(options, NullLogger<DbOtpService>.Instance, new OtpRepository(context),
            _unitOfWork.Object, new SmsSenderResolver([], options));

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            service.InvalidateAsync(_appId, "13800138000", cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        await using var verify = new IdentityDbContext(databaseOptions);
        var persisted = await verify.Otps.SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(OtpStatus.Sent, persisted.Status);
        Assert.Equal(2, persisted.Attempts);
        Assert.Equal(3, persisted.Version);
        _unitOfWork.Verify(unit => unit.SaveChangesAsync(cancellation.Token), Times.Once);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Generate_EnforcesPersistentHourAndDayLimits(bool hourlyLimit)
    {
        var now = DateTimeOffset.UtcNow;
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000", TestContext.Current.CancellationToken))
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

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Generate_ForwardsCancellationThroughNewAndExistingChallenges(bool hasExisting)
    {
        using var cancellation = new CancellationTokenSource();
        var existing = hasExisting ? new OtpEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = _appId,
            Phone = "+8613800138000",
            CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-10)
        } : null;
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000", cancellation.Token))
            .ReturnsAsync(existing);
        _repository.Setup(value => value.AddAsync(It.IsAny<OtpEntity>(), cancellation.Token))
            .Returns(Task.CompletedTask);

        await _service.GenerateAndSendAsync(_appId, "13800138000", "test", cancellation.Token);

        _repository.Verify(value => value.GetAsync(_appId, "+8613800138000", cancellation.Token), Times.Once);
        _repository.Verify(value => value.AddAsync(It.IsAny<OtpEntity>(), cancellation.Token),
            hasExisting ? Times.Never() : Times.Once());
        _repository.VerifyNoOtherCalls();
        _unitOfWork.Verify(value => value.SaveChangesAsync(cancellation.Token), Times.Once);
        _unitOfWork.VerifyNoOtherCalls();
        _sender.Verify(value => value.SendAsync(
            It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), cancellation.Token), Times.Once);
    }

    [Theory]
    [InlineData("read")]
    [InlineData("add")]
    [InlineData("save")]
    public async Task Generate_WhenDatabaseObservesCancellation_DoesNotSend(string boundary)
    {
        using var cancellation = new CancellationTokenSource();
        _repository.Setup(value => value.GetAsync(_appId, "+8613800138000", cancellation.Token))
            .Returns(() => boundary == "read" ? CancelAsync<OtpEntity?>() : Task.FromResult<OtpEntity?>(null));
        _repository.Setup(value => value.AddAsync(It.IsAny<OtpEntity>(), cancellation.Token))
            .Returns(() => boundary == "add" ? CancelAsync<int>() : Task.CompletedTask);
        _unitOfWork.Setup(value => value.SaveChangesAsync(cancellation.Token))
            .Returns(() => CancelAsync<int>());

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _service.GenerateAndSendAsync(_appId, "13800138000", "test", cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        _repository.Verify(value => value.GetAsync(_appId, "+8613800138000", cancellation.Token), Times.Once);
        _repository.Verify(value => value.AddAsync(It.IsAny<OtpEntity>(), cancellation.Token),
            boundary == "read" ? Times.Never() : Times.Once());
        _repository.VerifyNoOtherCalls();
        _unitOfWork.Verify(value => value.SaveChangesAsync(cancellation.Token),
            boundary == "save" ? Times.Once() : Times.Never());
        _unitOfWork.VerifyNoOtherCalls();
        _sender.Verify(value => value.SendAsync(
            It.IsAny<SmsProviderProfile>(), It.IsAny<SmsVerificationMessage>(), It.IsAny<CancellationToken>()), Times.Never);

        Task<T> CancelAsync<T>()
        {
            cancellation.Cancel();
            return Task.FromCanceled<T>(cancellation.Token);
        }
    }
}
