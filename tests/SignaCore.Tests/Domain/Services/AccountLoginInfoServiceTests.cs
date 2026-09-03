using Moq;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

public class AccountLoginInfoServiceTests
{
    [Fact]
    public async Task UpdateLoginInfoAsync_UpdatesFieldsAndStagesAccount()
    {
        var accountRepoMock = new Mock<IAccountRepository>();
        var service = new AccountLoginInfoService(accountRepoMock.Object);
        var account = new AccountEntity
        {
            Id = Guid.NewGuid(),
            TotalLoginCount = 4,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };

        await service.UpdateLoginInfoAsync(account, "10.0.0.1", "Password", TestContext.Current.CancellationToken);

        Assert.Equal("10.0.0.1", account.LastLoginIp);
        Assert.Equal("Password", account.LastLoginMethod);
        Assert.Equal(5, account.TotalLoginCount);
        Assert.NotNull(account.LastLoginAt);
        Assert.True(account.LastLoginAt > DateTimeOffset.UtcNow.AddSeconds(-5));
        accountRepoMock.Verify(r => r.UpdateAsync(account, TestContext.Current.CancellationToken), Times.Once);
    }
    [Fact]
    public async Task UpdateLoginInfoAsync_WhenRepositoryObservesCancellation_PropagatesCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        var repository = new Mock<IAccountRepository>(MockBehavior.Strict);
        var account = new AccountEntity { Id = Guid.NewGuid() };
        repository.Setup(value => value.UpdateAsync(account, cancellation.Token))
            .Callback(() => cancellation.Cancel())
            .Throws(() => new OperationCanceledException(cancellation.Token));

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new AccountLoginInfoService(repository.Object).UpdateLoginInfoAsync(
                account, "192.0.2.1", "password", cancellation.Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        repository.Verify(value => value.UpdateAsync(account, cancellation.Token), Times.Once);
        repository.VerifyNoOtherCalls();
    }
}
