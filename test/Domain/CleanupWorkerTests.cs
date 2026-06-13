using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using QuantumZhou.Identity.Database;
using QuantumZhou.Identity.Database.Repositories;
using QuantumZhou.Identity.Domain;
using Xunit;

namespace QuantumZhou.Identity.Tests.Domain;

public class CleanupWorkerTests
{
    private static Mock<IServiceProvider> CreateMockServiceProvider(
        Mock<IRefreshTokenRepository>? refreshTokenRepoMock = null,
        Mock<IAppRegistrationRepository>? appRegRepoMock = null,
        Mock<ISecurityKeyRepository>? securityKeyRepoMock = null,
        Mock<ILoginAttemptRepository>? loginAttemptRepoMock = null,
        Mock<ILoginHistoryRepository>? loginHistoryRepoMock = null,
        Mock<IAuditLogRepository>? auditLogRepoMock = null)
    {
        var serviceProviderMock = new Mock<IServiceProvider>();

        serviceProviderMock
            .Setup(sp => sp.GetService(typeof(IRefreshTokenRepository)))
            .Returns((refreshTokenRepoMock ?? new Mock<IRefreshTokenRepository>()).Object);
        serviceProviderMock
            .Setup(sp => sp.GetService(typeof(IAppRegistrationRepository)))
            .Returns((appRegRepoMock ?? new Mock<IAppRegistrationRepository>()).Object);
        serviceProviderMock
            .Setup(sp => sp.GetService(typeof(ISecurityKeyRepository)))
            .Returns((securityKeyRepoMock ?? new Mock<ISecurityKeyRepository>()).Object);
        serviceProviderMock
            .Setup(sp => sp.GetService(typeof(ILoginAttemptRepository)))
            .Returns((loginAttemptRepoMock ?? new Mock<ILoginAttemptRepository>()).Object);
        serviceProviderMock
            .Setup(sp => sp.GetService(typeof(ILoginHistoryRepository)))
            .Returns((loginHistoryRepoMock ?? new Mock<ILoginHistoryRepository>()).Object);
        serviceProviderMock
            .Setup(sp => sp.GetService(typeof(IAuditLogRepository)))
            .Returns((auditLogRepoMock ?? new Mock<IAuditLogRepository>()).Object);

        return serviceProviderMock;
    }

    private static Mock<IServiceScopeFactory> CreateMockScopeFactory(Mock<IServiceProvider> serviceProviderMock)
    {
        var scopeFactoryMock = new Mock<IServiceScopeFactory>();
        var scopeMock = new Mock<IServiceScope>();

        scopeMock.Setup(s => s.ServiceProvider).Returns(serviceProviderMock.Object);
        scopeFactoryMock.Setup(f => f.CreateScope()).Returns(scopeMock.Object);

        serviceProviderMock
            .Setup(sp => sp.GetService(typeof(IServiceScopeFactory)))
            .Returns(scopeFactoryMock.Object);

        return scopeFactoryMock;
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_RemovesExpiredAndRevokedTokens()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.RemoveExpiredAndRevokedAsync()).ReturnsAsync(5);

        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.DeactivateExpiredCallbacksAsync(It.IsAny<DateTimeOffset>())).ReturnsAsync(0);

        var securityKeyRepoMock = new Mock<ISecurityKeyRepository>();
        securityKeyRepoMock.Setup(r => r.RemoveExpiredInactiveAsync()).Returns(Task.CompletedTask);

        var loginAttemptRepoMock = new Mock<ILoginAttemptRepository>();
        loginAttemptRepoMock.Setup(r => r.RemoveExpiredAsync(It.IsAny<DateTimeOffset>())).Returns(Task.CompletedTask);

        var serviceProviderMock = CreateMockServiceProvider(refreshTokenRepoMock, appRegRepoMock, securityKeyRepoMock, loginAttemptRepoMock);
        var scopeFactoryMock = CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync()).ReturnsAsync(false);

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));

        await worker.StartAsync(cts.Token);
        await Task.Delay(200);
        await worker.StopAsync(CancellationToken.None);

        refreshTokenRepoMock.Verify(r => r.RemoveExpiredAndRevokedAsync(), Times.AtLeastOnce);
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_DeactivatesExpiredAppRegistrations()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.RemoveExpiredAndRevokedAsync()).ReturnsAsync(0);

        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.DeactivateExpiredCallbacksAsync(It.IsAny<DateTimeOffset>())).ReturnsAsync(3);

        var securityKeyRepoMock = new Mock<ISecurityKeyRepository>();
        securityKeyRepoMock.Setup(r => r.RemoveExpiredInactiveAsync()).Returns(Task.CompletedTask);

        var loginAttemptRepoMock = new Mock<ILoginAttemptRepository>();
        loginAttemptRepoMock.Setup(r => r.RemoveExpiredAsync(It.IsAny<DateTimeOffset>())).Returns(Task.CompletedTask);

        var serviceProviderMock = CreateMockServiceProvider(refreshTokenRepoMock, appRegRepoMock, securityKeyRepoMock, loginAttemptRepoMock);
        var scopeFactoryMock = CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync()).ReturnsAsync(false);

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));

        await worker.StartAsync(cts.Token);
        await Task.Delay(200);
        await worker.StopAsync(CancellationToken.None);

        appRegRepoMock.Verify(r => r.DeactivateExpiredCallbacksAsync(It.IsAny<DateTimeOffset>()), Times.AtLeastOnce);
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_RemovesExpiredInactiveKeys()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.RemoveExpiredAndRevokedAsync()).ReturnsAsync(0);

        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.DeactivateExpiredCallbacksAsync(It.IsAny<DateTimeOffset>())).ReturnsAsync(0);

        var securityKeyRepoMock = new Mock<ISecurityKeyRepository>();
        securityKeyRepoMock.Setup(r => r.RemoveExpiredInactiveAsync()).Returns(Task.CompletedTask);

        var loginAttemptRepoMock = new Mock<ILoginAttemptRepository>();
        loginAttemptRepoMock.Setup(r => r.RemoveExpiredAsync(It.IsAny<DateTimeOffset>())).Returns(Task.CompletedTask);

        var serviceProviderMock = CreateMockServiceProvider(refreshTokenRepoMock, appRegRepoMock, securityKeyRepoMock, loginAttemptRepoMock);
        var scopeFactoryMock = CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync()).ReturnsAsync(false);

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));

        await worker.StartAsync(cts.Token);
        await Task.Delay(200);
        await worker.StopAsync(CancellationToken.None);

        securityKeyRepoMock.Verify(r => r.RemoveExpiredInactiveAsync(), Times.AtLeastOnce);
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_CleansUpExpiredLoginAttempts()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.RemoveExpiredAndRevokedAsync()).ReturnsAsync(0);

        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.DeactivateExpiredCallbacksAsync(It.IsAny<DateTimeOffset>())).ReturnsAsync(0);

        var securityKeyRepoMock = new Mock<ISecurityKeyRepository>();
        securityKeyRepoMock.Setup(r => r.RemoveExpiredInactiveAsync()).Returns(Task.CompletedTask);

        var loginAttemptRepoMock = new Mock<ILoginAttemptRepository>();
        loginAttemptRepoMock.Setup(r => r.RemoveExpiredAsync(It.IsAny<DateTimeOffset>())).Returns(Task.CompletedTask);

        var serviceProviderMock = CreateMockServiceProvider(refreshTokenRepoMock, appRegRepoMock, securityKeyRepoMock, loginAttemptRepoMock);
        var scopeFactoryMock = CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync()).ReturnsAsync(false);

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));

        await worker.StartAsync(cts.Token);
        await Task.Delay(200);
        await worker.StopAsync(CancellationToken.None);

        loginAttemptRepoMock.Verify(r => r.RemoveExpiredAsync(It.IsAny<DateTimeOffset>()), Times.AtLeastOnce);
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_WhenKeyNeedsRotation_RotatesKey()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.RemoveExpiredAndRevokedAsync()).ReturnsAsync(0);

        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.DeactivateExpiredCallbacksAsync(It.IsAny<DateTimeOffset>())).ReturnsAsync(0);

        var securityKeyRepoMock = new Mock<ISecurityKeyRepository>();
        securityKeyRepoMock.Setup(r => r.RemoveExpiredInactiveAsync()).Returns(Task.CompletedTask);

        var loginAttemptRepoMock = new Mock<ILoginAttemptRepository>();
        loginAttemptRepoMock.Setup(r => r.RemoveExpiredAsync(It.IsAny<DateTimeOffset>())).Returns(Task.CompletedTask);

        var serviceProviderMock = CreateMockServiceProvider(refreshTokenRepoMock, appRegRepoMock, securityKeyRepoMock, loginAttemptRepoMock);
        var scopeFactoryMock = CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync()).ReturnsAsync(true);
        keyManagerMock.Setup(k => k.RotateKeyAsync()).Returns(Task.CompletedTask);

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));

        await worker.StartAsync(cts.Token);
        await Task.Delay(200);
        await worker.StopAsync(CancellationToken.None);

        keyManagerMock.Verify(k => k.NeedsKeyRotationAsync(), Times.AtLeastOnce);
        keyManagerMock.Verify(k => k.RotateKeyAsync(), Times.AtLeastOnce);
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_WhenKeyDoesNotNeedRotation_DoesNotRotateKey()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.RemoveExpiredAndRevokedAsync()).ReturnsAsync(0);

        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.DeactivateExpiredCallbacksAsync(It.IsAny<DateTimeOffset>())).ReturnsAsync(0);

        var securityKeyRepoMock = new Mock<ISecurityKeyRepository>();
        securityKeyRepoMock.Setup(r => r.RemoveExpiredInactiveAsync()).Returns(Task.CompletedTask);

        var loginAttemptRepoMock = new Mock<ILoginAttemptRepository>();
        loginAttemptRepoMock.Setup(r => r.RemoveExpiredAsync(It.IsAny<DateTimeOffset>())).Returns(Task.CompletedTask);

        var serviceProviderMock = CreateMockServiceProvider(refreshTokenRepoMock, appRegRepoMock, securityKeyRepoMock, loginAttemptRepoMock);
        var scopeFactoryMock = CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync()).ReturnsAsync(false);

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));

        await worker.StartAsync(cts.Token);
        await Task.Delay(200);
        await worker.StopAsync(CancellationToken.None);

        keyManagerMock.Verify(k => k.NeedsKeyRotationAsync(), Times.AtLeastOnce);
        keyManagerMock.Verify(k => k.RotateKeyAsync(), Times.Never);
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_WhenExceptionOccurs_ContinuesRunning()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.RemoveExpiredAndRevokedAsync()).ThrowsAsync(new Exception("Test exception"));

        var serviceProviderMock = CreateMockServiceProvider(refreshTokenRepoMock);
        var scopeFactoryMock = CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));

        var exception = await Record.ExceptionAsync(async () =>
        {
            await worker.StartAsync(cts.Token);
            await Task.Delay(200);
            await worker.StopAsync(CancellationToken.None);
        });

        Assert.Null(exception);
    }
}
