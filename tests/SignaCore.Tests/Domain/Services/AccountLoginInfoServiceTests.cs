using Moq;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

public class AccountLoginInfoServiceTests
{
    [Fact]
    public async Task UpdateLoginInfoAsync_UpdatesFieldsAndPersistsOnce()
    {
        var accountRepoMock = new Mock<IAccountRepository>();
        var unitOfWorkMock = new Mock<IUnitOfWork>();
        unitOfWorkMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);
        var service = new AccountLoginInfoService(accountRepoMock.Object, unitOfWorkMock.Object);
        var account = new AccountEntity
        {
            Id = Guid.NewGuid(),
            TotalLoginCount = 4,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };

        await service.UpdateLoginInfoAsync(account, "10.0.0.1", "Password");

        Assert.Equal("10.0.0.1", account.LastLoginIp);
        Assert.Equal("Password", account.LastLoginMethod);
        Assert.Equal(5, account.TotalLoginCount);
        Assert.NotNull(account.LastLoginAt);
        Assert.True(account.LastLoginAt > DateTimeOffset.UtcNow.AddSeconds(-5));
        accountRepoMock.Verify(r => r.UpdateAsync(account), Times.Once);
        unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }
}
