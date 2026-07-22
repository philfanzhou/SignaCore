using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain.Services.Sms;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain.Services;

public class DbOtpServiceTests
{
    private readonly Mock<IOtpRepository> _otpRepoMock;
    private readonly Mock<IUnitOfWork> _unitOfWorkMock;
    private readonly Mock<ISmsSender> _smsSenderMock;
    private readonly SmsOptions _options;
    private readonly DbOtpService _service;

    public DbOtpServiceTests()
    {
        _otpRepoMock = new Mock<IOtpRepository>();
        _unitOfWorkMock = new Mock<IUnitOfWork>();
        _unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);
        _smsSenderMock = new Mock<ISmsSender>();
        _options = new SmsOptions { OtpTtlSeconds = 300, MaxAttempts = 3, LockoutSeconds = 600 };
        _service = new DbOtpService(_options, NullLogger<DbOtpService>.Instance, _otpRepoMock.Object, _unitOfWorkMock.Object);
    }

    private static OtpEntity CreateEntry(string phone, int attempts = 0, DateTimeOffset? expiresAt = null, DateTimeOffset? lockoutUntil = null) => new()
    {
        Id = Guid.NewGuid(),
        Phone = phone,
        Code = "123456",
        Attempts = attempts,
        ExpiresAt = expiresAt ?? DateTimeOffset.UtcNow.AddMinutes(5),
        LockoutUntil = lockoutUntil ?? DateTimeOffset.MinValue,
        CreatedAt = DateTimeOffset.UtcNow
    };

    [Fact]
    public async Task GenerateAndSendAsync_NoExisting_CreatesAndSendsCode()
    {
        _otpRepoMock.Setup(r => r.GetByPhoneAsync("13800138000")).ReturnsAsync((OtpEntity?)null);

        var code = await _service.GenerateAndSendAsync("13800138000", _smsSenderMock.Object);

        Assert.Equal(6, code.Length);
        _otpRepoMock.Verify(r => r.AddAsync(It.Is<OtpEntity>(o =>
            o.Phone == "13800138000" && o.Code == code && o.Attempts == 0)), Times.Once);
        _smsSenderMock.Verify(s => s.SendAsync("13800138000", code), Times.Once);
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task GenerateAndSendAsync_ExistingBelowMaxAttempts_ReplacesOldEntry()
    {
        var existing = CreateEntry("13800138000", attempts: 1);
        _otpRepoMock.Setup(r => r.GetByPhoneAsync("13800138000")).ReturnsAsync(existing);

        var code = await _service.GenerateAndSendAsync("13800138000", _smsSenderMock.Object);

        _otpRepoMock.Verify(r => r.RemoveAsync(existing), Times.Once);
        _otpRepoMock.Verify(r => r.AddAsync(It.Is<OtpEntity>(o => o.Code == code)), Times.Once);
    }

    [Fact]
    public async Task GenerateAndSendAsync_LockedOut_ThrowsInvalidOperation()
    {
        var existing = CreateEntry("13800138000",
            attempts: 3,
            lockoutUntil: DateTimeOffset.UtcNow.AddMinutes(5));
        _otpRepoMock.Setup(r => r.GetByPhoneAsync("13800138000")).ReturnsAsync(existing);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _service.GenerateAndSendAsync("13800138000", _smsSenderMock.Object));

        _otpRepoMock.Verify(r => r.AddAsync(It.IsAny<OtpEntity>()), Times.Never);
        _smsSenderMock.Verify(s => s.SendAsync(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task GenerateAndSendAsync_LockoutExpired_RemovesOldAndRegenerates()
    {
        var existing = CreateEntry("13800138000",
            attempts: 3,
            lockoutUntil: DateTimeOffset.UtcNow.AddMinutes(-1));
        _otpRepoMock.Setup(r => r.GetByPhoneAsync("13800138000")).ReturnsAsync(existing);

        var code = await _service.GenerateAndSendAsync("13800138000", _smsSenderMock.Object);

        Assert.Equal(6, code.Length);
        _otpRepoMock.Verify(r => r.RemoveAsync(existing), Times.Once);
        _otpRepoMock.Verify(r => r.AddAsync(It.Is<OtpEntity>(o => o.Code == code)), Times.Once);
    }

    [Fact]
    public async Task VerifyAsync_NoEntry_ReturnsFalse()
    {
        _otpRepoMock.Setup(r => r.GetByPhoneAsync(It.IsAny<string>())).ReturnsAsync((OtpEntity?)null);

        var result = await _service.VerifyAsync("13800138000", "123456");

        Assert.False(result);
    }

    [Fact]
    public async Task VerifyAsync_Expired_RemovesEntryAndReturnsFalse()
    {
        var entry = CreateEntry("13800138000", expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1));
        _otpRepoMock.Setup(r => r.GetByPhoneAsync("13800138000")).ReturnsAsync(entry);

        var result = await _service.VerifyAsync("13800138000", "123456");

        Assert.False(result);
        _otpRepoMock.Verify(r => r.RemoveAsync(entry), Times.Once);
    }

    [Fact]
    public async Task VerifyAsync_WrongCode_IncrementsAttemptsAndReturnsFalse()
    {
        var entry = CreateEntry("13800138000", attempts: 0);
        _otpRepoMock.Setup(r => r.GetByPhoneAsync("13800138000")).ReturnsAsync(entry);

        var result = await _service.VerifyAsync("13800138000", "000000");

        Assert.False(result);
        Assert.Equal(1, entry.Attempts);
        _otpRepoMock.Verify(r => r.RemoveAsync(It.IsAny<OtpEntity>()), Times.Never);
    }

    [Fact]
    public async Task VerifyAsync_ReachingMaxAttempts_LocksAndReturnsFalse()
    {
        var entry = CreateEntry("13800138000", attempts: 2);
        _otpRepoMock.Setup(r => r.GetByPhoneAsync("13800138000")).ReturnsAsync(entry);

        var result = await _service.VerifyAsync("13800138000", "000000");

        Assert.False(result);
        Assert.Equal(3, entry.Attempts);
        Assert.True(entry.LockoutUntil > DateTimeOffset.UtcNow.AddMinutes(9));
    }

    [Fact]
    public async Task VerifyAsync_CorrectCode_RemovesEntryAndReturnsTrue()
    {
        var entry = CreateEntry("13800138000", attempts: 1);
        _otpRepoMock.Setup(r => r.GetByPhoneAsync("13800138000")).ReturnsAsync(entry);

        var result = await _service.VerifyAsync("13800138000", "123456");

        Assert.True(result);
        _otpRepoMock.Verify(r => r.RemoveAsync(entry), Times.Once);
    }

    [Fact]
    public async Task InvalidateAsync_ExistingEntry_RemovesIt()
    {
        var entry = CreateEntry("13800138000");
        _otpRepoMock.Setup(r => r.GetByPhoneAsync("13800138000")).ReturnsAsync(entry);

        await _service.InvalidateAsync("13800138000");

        _otpRepoMock.Verify(r => r.RemoveAsync(entry), Times.Once);
        _unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task InvalidateAsync_NoEntry_DoesNothing()
    {
        _otpRepoMock.Setup(r => r.GetByPhoneAsync(It.IsAny<string>())).ReturnsAsync((OtpEntity?)null);

        await _service.InvalidateAsync("13800138000");

        _otpRepoMock.Verify(r => r.RemoveAsync(It.IsAny<OtpEntity>()), Times.Never);
    }
}
