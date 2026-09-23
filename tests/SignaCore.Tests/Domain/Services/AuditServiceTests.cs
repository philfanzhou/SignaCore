using Moq;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

public class AuditServiceTests
{
    private static Mock<ILoginHistoryRepository> CreateLoginHistoryRepoMock()
    {
        var mock = new Mock<ILoginHistoryRepository>();
        mock.Setup(r => r.AddAsync(It.IsAny<LoginHistoryEntity>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        return mock;
    }

    [Fact]
    public async Task RecordLoginAsync_StagesLoginHistoryWithAllFields()
    {
        var loginHistoryRepoMock = CreateLoginHistoryRepoMock();
        var service = new AuditService(loginHistoryRepoMock.Object);
        var accountId = Guid.NewGuid();

        await service.RecordLoginAsync(
            accountId, "testuser", "Password", "login_success", "127.0.0.1", "TestAgent",
            appId: "app-1", correlationId: "correlation-1",
            cancellationToken: TestContext.Current.CancellationToken);

        loginHistoryRepoMock.Verify(r => r.AddAsync(It.Is<LoginHistoryEntity>(e =>
            e.AccountId == accountId &&
            e.Username == "testuser" &&
            e.AuthMethod == "Password" &&
            e.EventType == "login_success" &&
            e.ClientIp == "127.0.0.1" &&
            e.UserAgent == "TestAgent" &&
            e.FailureReason == null &&
            e.AppId == "app-1" &&
            e.CorrelationId == "correlation-1"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RecordLoginAsync_WithFailureReason_SavesCorrectly()
    {
        var loginHistoryRepoMock = CreateLoginHistoryRepoMock();
        var service = new AuditService(loginHistoryRepoMock.Object);

        await service.RecordLoginAsync(
            null, "unknown", "Password", "login_failure", "127.0.0.1", "TestAgent", "wrong_password",
            cancellationToken: TestContext.Current.CancellationToken);

        loginHistoryRepoMock.Verify(r => r.AddAsync(It.Is<LoginHistoryEntity>(e =>
            e.EventType == "login_failure" &&
            e.FailureReason == "wrong_password" &&
            e.AccountId == null), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RecordLoginAsync_WhenRepositoryThrows_PropagatesException()
    {
        var loginHistoryRepoMock = CreateLoginHistoryRepoMock();
        loginHistoryRepoMock
            .Setup(r => r.AddAsync(It.IsAny<LoginHistoryEntity>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("DB error"));
        var service = new AuditService(loginHistoryRepoMock.Object);

        var exception = await Assert.ThrowsAsync<Exception>(() =>
            service.RecordLoginAsync(
                Guid.NewGuid(), "testuser", "Password", "login_success", "127.0.0.1", "TestAgent",
                cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal("DB error", exception.Message);
    }

    [Fact]
    public async Task RecordLoginAsync_WithPreCanceledToken_PropagatesWithoutStagingEntry()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var stagedEntries = new List<LoginHistoryEntity>();
        var loginHistoryRepoMock = new Mock<ILoginHistoryRepository>();
        loginHistoryRepoMock
            .Setup(r => r.AddAsync(It.IsAny<LoginHistoryEntity>(), cancellation.Token))
            .Returns((LoginHistoryEntity entry, CancellationToken token) =>
            {
                token.ThrowIfCancellationRequested();
                stagedEntries.Add(entry);
                return Task.CompletedTask;
            });
        var service = new AuditService(loginHistoryRepoMock.Object);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.RecordLoginAsync(
            Guid.NewGuid(), "testuser", "Password", "login_success", "127.0.0.1", "TestAgent",
            cancellationToken: cancellation.Token));

        Assert.Empty(stagedEntries);
        loginHistoryRepoMock.Verify(
            r => r.AddAsync(It.IsAny<LoginHistoryEntity>(), cancellation.Token),
            Times.Once);
    }

}
