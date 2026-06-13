using QuantumZhou.Identity.Domain.Services;
using QuantumZhou.Identity.Domain.Services.Sms;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain.Services;

public class InMemoryOtpServiceTests
{
    private static SmsOptions CreateSmsOptions() => new() { OtpTtlSeconds = 300, MaxAttempts = 3, LockoutSeconds = 600 };
    private static ISmsSender CreateSmsSender() => new LoggingSmsSender(Microsoft.Extensions.Logging.Abstractions.NullLogger<LoggingSmsSender>.Instance);

    [Fact]
    public async Task GenerateAndSendAsync_ReturnsCode()
    {
        var service = new InMemoryOtpService(CreateSmsOptions(), Microsoft.Extensions.Logging.Abstractions.NullLogger<InMemoryOtpService>.Instance);

        var code = await service.GenerateAndSendAsync("13800138000", CreateSmsSender());

        Assert.NotNull(code);
        Assert.Equal(6, code.Length);
    }

    [Fact]
    public async Task VerifyAsync_WithCorrectCode_ReturnsTrue()
    {
        var service = new InMemoryOtpService(CreateSmsOptions(), Microsoft.Extensions.Logging.Abstractions.NullLogger<InMemoryOtpService>.Instance);
        var code = await service.GenerateAndSendAsync("13800138000", CreateSmsSender());

        var result = await service.VerifyAsync("13800138000", code);

        Assert.True(result);
    }

    [Fact]
    public async Task VerifyAsync_WithWrongCode_ReturnsFalse()
    {
        var service = new InMemoryOtpService(CreateSmsOptions(), Microsoft.Extensions.Logging.Abstractions.NullLogger<InMemoryOtpService>.Instance);
        await service.GenerateAndSendAsync("13800138000", CreateSmsSender());

        var result = await service.VerifyAsync("13800138000", "000000");

        Assert.False(result);
    }

    [Fact]
    public async Task VerifyAsync_WithNonExistentPhone_ReturnsFalse()
    {
        var service = new InMemoryOtpService(CreateSmsOptions(), Microsoft.Extensions.Logging.Abstractions.NullLogger<InMemoryOtpService>.Instance);

        var result = await service.VerifyAsync("99999999999", "123456");

        Assert.False(result);
    }

    [Fact]
    public async Task VerifyAsync_AfterMaxAttempts_LockoutPreventsNewOtp()
    {
        var options = CreateSmsOptions();
        var service = new InMemoryOtpService(options, Microsoft.Extensions.Logging.Abstractions.NullLogger<InMemoryOtpService>.Instance);
        await service.GenerateAndSendAsync("13800138000", CreateSmsSender());

        for (int i = 0; i < options.MaxAttempts; i++)
        {
            await service.VerifyAsync("13800138000", "000000");
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.GenerateAndSendAsync("13800138000", CreateSmsSender()));
    }

    [Fact]
    public async Task InvalidateAsync_RemovesOtp()
    {
        var service = new InMemoryOtpService(CreateSmsOptions(), Microsoft.Extensions.Logging.Abstractions.NullLogger<InMemoryOtpService>.Instance);
        var code = await service.GenerateAndSendAsync("13800138000", CreateSmsSender());

        await service.InvalidateAsync("13800138000");

        var result = await service.VerifyAsync("13800138000", code);
        Assert.False(result);
    }

    [Fact]
    public async Task VerifyAsync_CannotReuseCode_AfterSuccessfulVerification()
    {
        var service = new InMemoryOtpService(CreateSmsOptions(), Microsoft.Extensions.Logging.Abstractions.NullLogger<InMemoryOtpService>.Instance);
        var code = await service.GenerateAndSendAsync("13800138000", CreateSmsSender());

        var firstVerify = await service.VerifyAsync("13800138000", code);
        var secondVerify = await service.VerifyAsync("13800138000", code);

        Assert.True(firstVerify);
        Assert.False(secondVerify);
    }
}
