using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using QuantumZhou.Identity.Database.Entity;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain.Services;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain.Services;

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

    private static Mock<IUnitOfWork> CreateUnitOfWorkMock()
    {
        var mock = new Mock<IUnitOfWork>();
        mock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);
        return mock;
    }

    [Fact]
    public async Task RecordLoginAsync_SavesLoginHistory()
    {
        var loginHistoryRepoMock = CreateLoginHistoryRepoMock();
        var auditLogRepoMock = CreateAuditLogRepoMock();
        var unitOfWorkMock = CreateUnitOfWorkMock();
        var service = new AuditService(loginHistoryRepoMock.Object, auditLogRepoMock.Object, unitOfWorkMock.Object, NullLogger<AuditService>.Instance);

        await service.RecordLoginAsync(Guid.NewGuid(), "testuser", "Password", "login_success", "127.0.0.1", "TestAgent");

        loginHistoryRepoMock.Verify(r => r.AddAsync(It.Is<LoginHistoryEntity>(e =>
            e.Username == "testuser" &&
            e.AuthMethod == "Password" &&
            e.EventType == "login_success")), Times.Once);
        unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RecordLoginAsync_WithFailureReason_SavesCorrectly()
    {
        var loginHistoryRepoMock = CreateLoginHistoryRepoMock();
        var auditLogRepoMock = CreateAuditLogRepoMock();
        var unitOfWorkMock = CreateUnitOfWorkMock();
        var service = new AuditService(loginHistoryRepoMock.Object, auditLogRepoMock.Object, unitOfWorkMock.Object, NullLogger<AuditService>.Instance);

        await service.RecordLoginAsync(null, "unknown", "Password", "login_failure", "127.0.0.1", "TestAgent", "wrong_password");

        loginHistoryRepoMock.Verify(r => r.AddAsync(It.Is<LoginHistoryEntity>(e =>
            e.EventType == "login_failure" &&
            e.FailureReason == "wrong_password" &&
            e.AccountId == null)), Times.Once);
    }

    [Fact]
    public async Task RecordLoginAsync_WhenRepositoryThrows_DoesNotPropagateException()
    {
        var loginHistoryRepoMock = CreateLoginHistoryRepoMock();
        loginHistoryRepoMock.Setup(r => r.AddAsync(It.IsAny<LoginHistoryEntity>())).ThrowsAsync(new Exception("DB error"));
        var auditLogRepoMock = CreateAuditLogRepoMock();
        var unitOfWorkMock = CreateUnitOfWorkMock();
        var service = new AuditService(loginHistoryRepoMock.Object, auditLogRepoMock.Object, unitOfWorkMock.Object, NullLogger<AuditService>.Instance);

        var exception = await Record.ExceptionAsync(() =>
            service.RecordLoginAsync(Guid.NewGuid(), "testuser", "Password", "login_success", "127.0.0.1", "TestAgent"));

        Assert.Null(exception);
    }

    [Fact]
    public async Task RecordActionAsync_SavesAuditLog()
    {
        var loginHistoryRepoMock = CreateLoginHistoryRepoMock();
        var auditLogRepoMock = CreateAuditLogRepoMock();
        var unitOfWorkMock = CreateUnitOfWorkMock();
        var service = new AuditService(loginHistoryRepoMock.Object, auditLogRepoMock.Object, unitOfWorkMock.Object, NullLogger<AuditService>.Instance);

        await service.RecordActionAsync("account_created", "Account", "123", Guid.NewGuid(), "admin", "Created account", "127.0.0.1");

        auditLogRepoMock.Verify(r => r.AddAsync(It.Is<AuditLogEntity>(e =>
            e.Action == "account_created" &&
            e.TargetType == "Account" &&
            e.TargetId == "123" &&
            e.Description == "Created account")), Times.Once);
        unitOfWorkMock.Verify(u => u.SaveChangesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RecordActionAsync_WithBeforeAndAfter_SerializesSnapshots()
    {
        var loginHistoryRepoMock = CreateLoginHistoryRepoMock();
        var auditLogRepoMock = CreateAuditLogRepoMock();
        var unitOfWorkMock = CreateUnitOfWorkMock();
        var service = new AuditService(loginHistoryRepoMock.Object, auditLogRepoMock.Object, unitOfWorkMock.Object, NullLogger<AuditService>.Instance);

        var before = new { IsActive = true };
        var after = new { IsActive = false };

        await service.RecordActionAsync("status_changed", "Account", "123", Guid.NewGuid(), "admin", "Changed status", "127.0.0.1", before: before, after: after);

        auditLogRepoMock.Verify(r => r.AddAsync(It.Is<AuditLogEntity>(e =>
            e.BeforeSnapshot != null &&
            e.AfterSnapshot != null)), Times.Once);
    }

    [Fact]
    public async Task RecordActionAsync_WhenRepositoryThrows_DoesNotPropagateException()
    {
        var loginHistoryRepoMock = CreateLoginHistoryRepoMock();
        var auditLogRepoMock = CreateAuditLogRepoMock();
        auditLogRepoMock.Setup(r => r.AddAsync(It.IsAny<AuditLogEntity>())).ThrowsAsync(new Exception("DB error"));
        var unitOfWorkMock = CreateUnitOfWorkMock();
        var service = new AuditService(loginHistoryRepoMock.Object, auditLogRepoMock.Object, unitOfWorkMock.Object, NullLogger<AuditService>.Instance);

        var exception = await Record.ExceptionAsync(() =>
            service.RecordActionAsync("test", "Account", "123", null, null, null));

        Assert.Null(exception);
    }
}
