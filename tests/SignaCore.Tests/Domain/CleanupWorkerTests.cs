using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using Xunit;

namespace SignaCore.Tests.Domain;

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

    private sealed class TestableCleanupWorker : CleanupWorker
    {
        public TestableCleanupWorker(
            IServiceProvider serviceProvider,
            IKeyManager keyManager,
            ILogger<CleanupWorker> logger)
            : base(serviceProvider, keyManager, logger)
        {
        }

        public Task RunAsync(CancellationToken cancellationToken) => ExecuteAsync(cancellationToken);
    }

    private static async Task RunWorkerUntilAsync(
        CleanupWorker worker,
        Func<bool> completed)
    {
        await worker.StartAsync(CancellationToken.None);

        try
        {
            var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
            while (!completed() && DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(10);
            }

            Assert.True(completed(), "The cleanup worker did not complete the expected operation within 5 seconds.");
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_RemovesExpiredAndRevokedTokens()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.RemoveExpiredAndRevokedAsync(It.IsAny<CancellationToken>())).ReturnsAsync(5);

        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.DeactivateExpiredCallbacksAsync(
            It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(0);

        var securityKeyRepoMock = new Mock<ISecurityKeyRepository>();
        securityKeyRepoMock.Setup(r => r.RemoveExpiredInactiveAsync(It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var loginAttemptRepoMock = new Mock<ILoginAttemptRepository>();
        loginAttemptRepoMock.Setup(r => r.RemoveExpiredAsync(
            It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

        var serviceProviderMock = CreateMockServiceProvider(refreshTokenRepoMock, appRegRepoMock, securityKeyRepoMock, loginAttemptRepoMock);
        var scopeFactoryMock = CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        await RunWorkerUntilAsync(
            worker,
            () => refreshTokenRepoMock.Invocations.Count > 0);

        refreshTokenRepoMock.Verify(
            r => r.RemoveExpiredAndRevokedAsync(It.IsAny<CancellationToken>()),
            Times.AtLeastOnce);
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_DeactivatesExpiredAppRegistrations()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.RemoveExpiredAndRevokedAsync(It.IsAny<CancellationToken>())).ReturnsAsync(0);

        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.DeactivateExpiredCallbacksAsync(
            It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(3);

        var securityKeyRepoMock = new Mock<ISecurityKeyRepository>();
        securityKeyRepoMock.Setup(r => r.RemoveExpiredInactiveAsync(It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var loginAttemptRepoMock = new Mock<ILoginAttemptRepository>();
        loginAttemptRepoMock.Setup(r => r.RemoveExpiredAsync(
            It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

        var serviceProviderMock = CreateMockServiceProvider(refreshTokenRepoMock, appRegRepoMock, securityKeyRepoMock, loginAttemptRepoMock);
        var scopeFactoryMock = CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        await RunWorkerUntilAsync(
            worker,
            () => appRegRepoMock.Invocations.Count > 0);

        appRegRepoMock.Verify(r => r.DeactivateExpiredCallbacksAsync(
            It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.AtLeastOnce);
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_RemovesExpiredInactiveKeys()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.RemoveExpiredAndRevokedAsync(It.IsAny<CancellationToken>())).ReturnsAsync(0);

        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.DeactivateExpiredCallbacksAsync(
            It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(0);

        var securityKeyRepoMock = new Mock<ISecurityKeyRepository>();
        securityKeyRepoMock.Setup(r => r.RemoveExpiredInactiveAsync(It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var loginAttemptRepoMock = new Mock<ILoginAttemptRepository>();
        loginAttemptRepoMock.Setup(r => r.RemoveExpiredAsync(
            It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

        var serviceProviderMock = CreateMockServiceProvider(refreshTokenRepoMock, appRegRepoMock, securityKeyRepoMock, loginAttemptRepoMock);
        var scopeFactoryMock = CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        await RunWorkerUntilAsync(
            worker,
            () => securityKeyRepoMock.Invocations.Count > 0);

        securityKeyRepoMock.Verify(
            r => r.RemoveExpiredInactiveAsync(It.IsAny<CancellationToken>()),
            Times.AtLeastOnce);
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_CleansUpExpiredLoginAttempts()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.RemoveExpiredAndRevokedAsync(It.IsAny<CancellationToken>())).ReturnsAsync(0);

        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.DeactivateExpiredCallbacksAsync(
            It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(0);

        var securityKeyRepoMock = new Mock<ISecurityKeyRepository>();
        securityKeyRepoMock.Setup(r => r.RemoveExpiredInactiveAsync(It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var loginAttemptRepoMock = new Mock<ILoginAttemptRepository>();
        loginAttemptRepoMock.Setup(r => r.RemoveExpiredAsync(
            It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

        var serviceProviderMock = CreateMockServiceProvider(refreshTokenRepoMock, appRegRepoMock, securityKeyRepoMock, loginAttemptRepoMock);
        var scopeFactoryMock = CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        await RunWorkerUntilAsync(
            worker,
            () => loginAttemptRepoMock.Invocations.Count > 0);

        loginAttemptRepoMock.Verify(r => r.RemoveExpiredAsync(
            It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.AtLeastOnce);
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_WhenKeyNeedsRotation_RotatesKey()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.RemoveExpiredAndRevokedAsync(It.IsAny<CancellationToken>())).ReturnsAsync(0);

        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.DeactivateExpiredCallbacksAsync(
            It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(0);

        var securityKeyRepoMock = new Mock<ISecurityKeyRepository>();
        securityKeyRepoMock.Setup(r => r.RemoveExpiredInactiveAsync(It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var loginAttemptRepoMock = new Mock<ILoginAttemptRepository>();
        loginAttemptRepoMock.Setup(r => r.RemoveExpiredAsync(
            It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

        var serviceProviderMock = CreateMockServiceProvider(refreshTokenRepoMock, appRegRepoMock, securityKeyRepoMock, loginAttemptRepoMock);
        var scopeFactoryMock = CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync(It.IsAny<CancellationToken>())).ReturnsAsync(true);
        keyManagerMock.Setup(k => k.RotateKeyAsync(It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        await RunWorkerUntilAsync(
            worker,
            () => keyManagerMock.Invocations.Any(
                invocation => invocation.Method.Name == nameof(IKeyManager.RotateKeyAsync)));

        keyManagerMock.Verify(
            k => k.NeedsKeyRotationAsync(It.IsAny<CancellationToken>()),
            Times.AtLeastOnce);
        keyManagerMock.Verify(k => k.RotateKeyAsync(It.IsAny<CancellationToken>()), Times.AtLeastOnce);
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_WhenKeyDoesNotNeedRotation_DoesNotRotateKey()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.RemoveExpiredAndRevokedAsync(It.IsAny<CancellationToken>())).ReturnsAsync(0);

        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.DeactivateExpiredCallbacksAsync(
            It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(0);

        var securityKeyRepoMock = new Mock<ISecurityKeyRepository>();
        securityKeyRepoMock.Setup(r => r.RemoveExpiredInactiveAsync(It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var loginAttemptRepoMock = new Mock<ILoginAttemptRepository>();
        loginAttemptRepoMock.Setup(r => r.RemoveExpiredAsync(
            It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);

        var serviceProviderMock = CreateMockServiceProvider(refreshTokenRepoMock, appRegRepoMock, securityKeyRepoMock, loginAttemptRepoMock);
        var scopeFactoryMock = CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        await RunWorkerUntilAsync(
            worker,
            () => keyManagerMock.Invocations.Any(
                invocation => invocation.Method.Name == nameof(IKeyManager.NeedsKeyRotationAsync)));

        keyManagerMock.Verify(
            k => k.NeedsKeyRotationAsync(It.IsAny<CancellationToken>()),
            Times.AtLeastOnce);
        keyManagerMock.Verify(k => k.RotateKeyAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ExecuteAsync_WhenRepositoryObservesStoppingCancellation_ExitsWithoutStartingLaterWork()
    {
        using var stoppingSource = new CancellationTokenSource();
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock
            .Setup(r => r.RemoveExpiredAndRevokedAsync(stoppingSource.Token))
            .Returns<CancellationToken>(token =>
            {
                stoppingSource.Cancel();
                return Task.FromCanceled<int>(token);
            });
        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        var serviceProviderMock = CreateMockServiceProvider(
            refreshTokenRepoMock,
            appRegRepoMock);
        CreateMockScopeFactory(serviceProviderMock);
        var worker = new TestableCleanupWorker(
            serviceProviderMock.Object,
            Mock.Of<IKeyManager>(),
            NullLogger<CleanupWorker>.Instance);

        await worker.RunAsync(stoppingSource.Token);

        refreshTokenRepoMock.Verify(
            r => r.RemoveExpiredAndRevokedAsync(stoppingSource.Token),
            Times.Once);
        appRegRepoMock.Verify(
            r => r.DeactivateExpiredCallbacksAsync(
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task ExecuteAsync_WhenCancellationFollowsCommittedBatch_KeepsBatchAndStopsLaterWork()
    {
        using var stoppingSource = new CancellationTokenSource();
        var committedBatchCount = 0;
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock
            .Setup(r => r.RemoveExpiredAndRevokedAsync(stoppingSource.Token))
            .Returns<CancellationToken>(_ =>
            {
                committedBatchCount++;
                stoppingSource.Cancel();
                return Task.FromResult(1);
            });
        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        var serviceProviderMock = CreateMockServiceProvider(
            refreshTokenRepoMock,
            appRegRepoMock);
        CreateMockScopeFactory(serviceProviderMock);
        var worker = new TestableCleanupWorker(
            serviceProviderMock.Object,
            Mock.Of<IKeyManager>(),
            NullLogger<CleanupWorker>.Instance);

        await worker.RunAsync(stoppingSource.Token);

        Assert.Equal(1, committedBatchCount);
        appRegRepoMock.Verify(
            r => r.DeactivateExpiredCallbacksAsync(
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_WhenExceptionOccurs_ContinuesRunning()
    {
        var refreshTokenRepoMock = new Mock<IRefreshTokenRepository>();
        refreshTokenRepoMock.Setup(r => r.RemoveExpiredAndRevokedAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Test exception"));

        var serviceProviderMock = CreateMockServiceProvider(refreshTokenRepoMock);
        var scopeFactoryMock = CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        var exception = await Record.ExceptionAsync(async () =>
        {
            await RunWorkerUntilAsync(
                worker,
                () => refreshTokenRepoMock.Invocations.Count > 0);
        });

        Assert.Null(exception);
    }
}
