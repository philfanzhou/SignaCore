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
        mock.Setup(r => r.AddAsync(It.IsAny<LoginHistoryEntity>())).Returns(Task.CompletedTask);
        return mock;
    }

    private static Mock<IAuditLogRepository> CreateAuditLogRepoMock()
    {
        var mock = new Mock<IAuditLogRepository>();
        mock.Setup(r => r.AddAsync(It.IsAny<AuditLogEntity>())).Returns(Task.CompletedTask);
        return mock;
    }

    [Fact]
    public async Task RecordLoginAsync_StagesLoginHistoryWithAllFields()
    {
        var loginHistoryRepoMock = CreateLoginHistoryRepoMock();
        var auditLogRepoMock = CreateAuditLogRepoMock();
        var service = new AuditService(loginHistoryRepoMock.Object, auditLogRepoMock.Object);
        var accountId = Guid.NewGuid();

        await service.RecordLoginAsync(
            accountId, "testuser", "Password", "login_success", "127.0.0.1", "TestAgent",
            appId: "app-1", correlationId: "correlation-1");

        loginHistoryRepoMock.Verify(r => r.AddAsync(It.Is<LoginHistoryEntity>(e =>
            e.AccountId == accountId &&
            e.Username == "testuser" &&
            e.AuthMethod == "Password" &&
            e.EventType == "login_success" &&
            e.ClientIp == "127.0.0.1" &&
            e.UserAgent == "TestAgent" &&
            e.FailureReason == null &&
            e.AppId == "app-1" &&
            e.CorrelationId == "correlation-1")), Times.Once);
    }

    [Fact]
    public async Task RecordLoginAsync_WithFailureReason_SavesCorrectly()
    {
        var loginHistoryRepoMock = CreateLoginHistoryRepoMock();
        var auditLogRepoMock = CreateAuditLogRepoMock();
        var service = new AuditService(loginHistoryRepoMock.Object, auditLogRepoMock.Object);

        await service.RecordLoginAsync(null, "unknown", "Password", "login_failure", "127.0.0.1", "TestAgent", "wrong_password");

        loginHistoryRepoMock.Verify(r => r.AddAsync(It.Is<LoginHistoryEntity>(e =>
            e.EventType == "login_failure" &&
            e.FailureReason == "wrong_password" &&
            e.AccountId == null)), Times.Once);
    }

    [Fact]
    public async Task RecordLoginAsync_WhenRepositoryThrows_PropagatesException()
    {
        var loginHistoryRepoMock = CreateLoginHistoryRepoMock();
        loginHistoryRepoMock.Setup(r => r.AddAsync(It.IsAny<LoginHistoryEntity>())).ThrowsAsync(new Exception("DB error"));
        var auditLogRepoMock = CreateAuditLogRepoMock();
        var service = new AuditService(loginHistoryRepoMock.Object, auditLogRepoMock.Object);

        var exception = await Assert.ThrowsAsync<Exception>(() =>
            service.RecordLoginAsync(Guid.NewGuid(), "testuser", "Password", "login_success", "127.0.0.1", "TestAgent"));

        Assert.Equal("DB error", exception.Message);
    }

    [Fact]
    public async Task RecordActionAsync_StagesAuditLogWithAllFields()
    {
        var loginHistoryRepoMock = CreateLoginHistoryRepoMock();
        var auditLogRepoMock = CreateAuditLogRepoMock();
        var service = new AuditService(loginHistoryRepoMock.Object, auditLogRepoMock.Object);
        var actorId = Guid.NewGuid();

        await service.RecordActionAsync(
            "account_created", "Account", "123", actorId, "admin", "Created account",
            "127.0.0.1", "correlation-1");

        auditLogRepoMock.Verify(r => r.AddAsync(It.Is<AuditLogEntity>(e =>
            e.Action == "account_created" &&
            e.TargetType == "Account" &&
            e.TargetId == "123" &&
            e.ActorId == actorId &&
            e.ActorName == "admin" &&
            e.Description == "Created account" &&
            e.ClientIp == "127.0.0.1" &&
            e.CorrelationId == "correlation-1")), Times.Once);
    }

    [Fact]
    public async Task RecordActionAsync_WithBeforeAndAfter_SerializesSnapshots()
    {
        var loginHistoryRepoMock = CreateLoginHistoryRepoMock();
        var auditLogRepoMock = CreateAuditLogRepoMock();
        var service = new AuditService(loginHistoryRepoMock.Object, auditLogRepoMock.Object);

        var before = new { IsActive = true };
        var after = new { IsActive = false };

        await service.RecordActionAsync("status_changed", "Account", "123", Guid.NewGuid(), "admin", "Changed status", "127.0.0.1", before: before, after: after);

        auditLogRepoMock.Verify(r => r.AddAsync(It.Is<AuditLogEntity>(e =>
            e.BeforeSnapshot == "{\"isActive\":true}" &&
            e.AfterSnapshot == "{\"isActive\":false}")), Times.Once);
    }

    [Fact]
    public async Task RecordActionAsync_WhenRepositoryThrows_PropagatesException()
    {
        var loginHistoryRepoMock = CreateLoginHistoryRepoMock();
        var auditLogRepoMock = CreateAuditLogRepoMock();
        auditLogRepoMock.Setup(r => r.AddAsync(It.IsAny<AuditLogEntity>())).ThrowsAsync(new Exception("DB error"));
        var service = new AuditService(loginHistoryRepoMock.Object, auditLogRepoMock.Object);

        var exception = await Assert.ThrowsAsync<Exception>(() =>
            service.RecordActionAsync("test", "Account", "123", null, null, null));

        Assert.Equal("DB error", exception.Message);
    }
}
