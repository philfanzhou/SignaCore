using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SignaCore.Database;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
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
        Mock<IAuditLogRepository>? auditLogRepoMock = null,
        Mock<IAuthorizationRequestStore>? authorizationRequestStoreMock = null,
        Mock<IIdentitySessionStore>? identitySessionStoreMock = null,
        Mock<IAuthorizationCodeStore>? authorizationCodeStoreMock = null,
        Mock<IRefreshTokenFamilyStore>? refreshTokenFamilyStoreMock = null,
        Mock<ILogoutRequestStore>? logoutRequestStoreMock = null)
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
        serviceProviderMock
            .Setup(sp => sp.GetService(typeof(IAuthorizationRequestStore)))
            .Returns((authorizationRequestStoreMock ?? new Mock<IAuthorizationRequestStore>()).Object);
        serviceProviderMock
            .Setup(sp => sp.GetService(typeof(IIdentitySessionStore)))
            .Returns((identitySessionStoreMock ?? new Mock<IIdentitySessionStore>()).Object);
        serviceProviderMock
            .Setup(sp => sp.GetService(typeof(IAuthorizationCodeStore)))
            .Returns((authorizationCodeStoreMock ?? new Mock<IAuthorizationCodeStore>()).Object);
        serviceProviderMock
            .Setup(sp => sp.GetService(typeof(IRefreshTokenFamilyStore)))
            .Returns((refreshTokenFamilyStoreMock ?? new Mock<IRefreshTokenFamilyStore>()).Object);
        serviceProviderMock
            .Setup(sp => sp.GetService(typeof(ILogoutRequestStore)))
            .Returns((logoutRequestStoreMock ?? new Mock<ILogoutRequestStore>()).Object);

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
    public async Task CleanupExpiredDataAsync_RemovesExpiredAuthorizationRequests()
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

        var authorizationRequestStoreMock = new Mock<IAuthorizationRequestStore>();
        authorizationRequestStoreMock
            .Setup(s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(4);

        var serviceProviderMock = CreateMockServiceProvider(
            refreshTokenRepoMock,
            appRegRepoMock,
            securityKeyRepoMock,
            loginAttemptRepoMock,
            authorizationRequestStoreMock: authorizationRequestStoreMock);
        var scopeFactoryMock = CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        await RunWorkerUntilAsync(
            worker,
            () => authorizationRequestStoreMock.Invocations.Count > 0);

        authorizationRequestStoreMock.Verify(
            s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.AtLeastOnce);
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_RemovesExpiredInteractiveFamilyMembers()
    {
        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        appRegRepoMock.Setup(r => r.DeactivateExpiredCallbacksAsync(
            It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>())).ReturnsAsync(0);

        // One shared sequence log proves the child-first family segment runs after the
        // authorization-code segment and before the identity-session segment of the same round:
        // a family dies only once no retained code links its root, and only before the session
        // delete its members still reference.
        var sequence = new List<string>();
        var codeStoreMock = new Mock<IAuthorizationCodeStore>();
        codeStoreMock
            .Setup(s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback(() => sequence.Add("codes"))
            .ReturnsAsync(0);
        var familyStoreMock = new Mock<IRefreshTokenFamilyStore>();
        familyStoreMock
            .Setup(s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback(() => sequence.Add("families"))
            .ReturnsAsync(3);
        var sessionStoreMock = new Mock<IIdentitySessionStore>();
        sessionStoreMock
            .Setup(s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback(() => sequence.Add("sessions"))
            .ReturnsAsync(0);

        var serviceProviderMock = CreateMockServiceProvider(
            appRegRepoMock: appRegRepoMock,
            authorizationCodeStoreMock: codeStoreMock,
            refreshTokenFamilyStoreMock: familyStoreMock,
            identitySessionStoreMock: sessionStoreMock);
        CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var worker = new CleanupWorker(serviceProviderMock.Object, keyManagerMock.Object, NullLogger<CleanupWorker>.Instance);

        await RunWorkerUntilAsync(
            worker,
            () => sequence.Contains("sessions"));

        familyStoreMock.Verify(
            s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.AtLeastOnce);
        Assert.Equal(
            new[] { "codes", "families", "sessions" },
            sequence.Where(step => step is "codes" or "families" or "sessions").Take(3));
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

    [Fact]
    public async Task CleanupExpiredDataAsync_RemovesExpiredIdentitySessions()
    {
        var identitySessionStoreMock = new Mock<IIdentitySessionStore>();
        identitySessionStoreMock
            .Setup(s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(7);

        var serviceProviderMock = CreateMockServiceProvider(
            identitySessionStoreMock: identitySessionStoreMock);
        CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var worker = new CleanupWorker(
            serviceProviderMock.Object,
            keyManagerMock.Object,
            NullLogger<CleanupWorker>.Instance);

        await RunWorkerUntilAsync(
            worker,
            () => identitySessionStoreMock.Invocations.Count > 0);

        identitySessionStoreMock.Verify(
            s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.AtLeastOnce);
    }

    [Fact]
    public async Task ExecuteAsync_WhenIdentitySessionCleanupObservesStoppingCancellation_ExitsWithoutStartingLaterWork()
    {
        using var stoppingSource = new CancellationTokenSource();
        var identitySessionStoreMock = new Mock<IIdentitySessionStore>();
        identitySessionStoreMock
            .Setup(s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), stoppingSource.Token))
            .Returns<DateTimeOffset, CancellationToken>((_, token) =>
            {
                stoppingSource.Cancel();
                return Task.FromCanceled<int>(token);
            });
        var appRegRepoMock = new Mock<IAppRegistrationRepository>();
        var serviceProviderMock = CreateMockServiceProvider(
            appRegRepoMock: appRegRepoMock,
            identitySessionStoreMock: identitySessionStoreMock);
        CreateMockScopeFactory(serviceProviderMock);
        var worker = new TestableCleanupWorker(
            serviceProviderMock.Object,
            Mock.Of<IKeyManager>(),
            NullLogger<CleanupWorker>.Instance);

        await worker.RunAsync(stoppingSource.Token);

        identitySessionStoreMock.Verify(
            s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), stoppingSource.Token),
            Times.Once);
        appRegRepoMock.Verify(
            r => r.DeactivateExpiredCallbacksAsync(
                It.IsAny<DateTimeOffset>(),
                It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task IdentitySessionCleanup_LogsOnlyTheDeletedCount()
    {
        var logMessages = new List<string>();
        var identitySessionStoreMock = new Mock<IIdentitySessionStore>();
        identitySessionStoreMock
            .Setup(s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(7);

        var serviceProviderMock = CreateMockServiceProvider(
            identitySessionStoreMock: identitySessionStoreMock);
        CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var worker = new CleanupWorker(
            serviceProviderMock.Object,
            keyManagerMock.Object,
            new ListLogger<CleanupWorker>(logMessages));

        await RunWorkerUntilAsync(
            worker,
            () =>
            {
                lock (logMessages)
                {
                    return logMessages.Exists(message =>
                        message.Contains("expired identity sessions", StringComparison.Ordinal));
                }
            });

        // DF-06: the cleanup log names the count and nothing else — no session id and no other
        // row value.
        string message;
        lock (logMessages)
        {
            message = Assert.Single(
                logMessages,
                candidate => candidate.Contains("expired identity sessions", StringComparison.Ordinal));
        }

        Assert.Equal("Deleted 7 expired identity sessions", message);
    }

    [Fact]
    public async Task CleanupExpiredDataAsync_RemovesExpiredAuthorizationCodes()
    {
        var authorizationCodeStoreMock = new Mock<IAuthorizationCodeStore>();
        authorizationCodeStoreMock
            .Setup(s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(3);

        var serviceProviderMock = CreateMockServiceProvider(
            authorizationCodeStoreMock: authorizationCodeStoreMock);
        CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var worker = new CleanupWorker(
            serviceProviderMock.Object,
            keyManagerMock.Object,
            NullLogger<CleanupWorker>.Instance);

        await RunWorkerUntilAsync(
            worker,
            () => authorizationCodeStoreMock.Invocations.Count > 0);

        authorizationCodeStoreMock.Verify(
            s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.AtLeastOnce);
    }

    [Fact]
    public async Task AuthorizationCodeCleanup_RunsBeforeTheIdentitySessionSegment()
    {
        // PS-23: within one round the authorization-code segment must complete before the session
        // segment, so a code past its retention is deleted before the session cleanup re-checks
        // its reference predicate.
        var segmentOrder = new List<string>();
        var authorizationCodeStoreMock = new Mock<IAuthorizationCodeStore>();
        authorizationCodeStoreMock
            .Setup(s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(1)
            .Callback(() => segmentOrder.Add("authorization-codes"));
        var identitySessionStoreMock = new Mock<IIdentitySessionStore>();
        identitySessionStoreMock
            .Setup(s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(1)
            .Callback(() => segmentOrder.Add("identity-sessions"));

        var serviceProviderMock = CreateMockServiceProvider(
            identitySessionStoreMock: identitySessionStoreMock,
            authorizationCodeStoreMock: authorizationCodeStoreMock);
        CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var worker = new CleanupWorker(
            serviceProviderMock.Object,
            keyManagerMock.Object,
            NullLogger<CleanupWorker>.Instance);

        await RunWorkerUntilAsync(
            worker,
            () => segmentOrder.Contains("identity-sessions"));

        Assert.Equal(
            new[] { "authorization-codes", "identity-sessions" },
            segmentOrder.Where(segment => segment is "authorization-codes" or "identity-sessions").ToArray());
    }

    [Fact]
    public async Task ExecuteAsync_WhenAuthorizationCodeCleanupObservesStoppingCancellation_ExitsWithoutStartingLaterWork()
    {
        using var stoppingSource = new CancellationTokenSource();
        var authorizationCodeStoreMock = new Mock<IAuthorizationCodeStore>();
        authorizationCodeStoreMock
            .Setup(s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), stoppingSource.Token))
            .Returns<DateTimeOffset, CancellationToken>((_, token) =>
            {
                stoppingSource.Cancel();
                return Task.FromCanceled<int>(token);
            });
        var identitySessionStoreMock = new Mock<IIdentitySessionStore>();
        var serviceProviderMock = CreateMockServiceProvider(
            identitySessionStoreMock: identitySessionStoreMock,
            authorizationCodeStoreMock: authorizationCodeStoreMock);
        CreateMockScopeFactory(serviceProviderMock);
        var worker = new TestableCleanupWorker(
            serviceProviderMock.Object,
            Mock.Of<IKeyManager>(),
            NullLogger<CleanupWorker>.Instance);

        await worker.RunAsync(stoppingSource.Token);

        authorizationCodeStoreMock.Verify(
            s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), stoppingSource.Token),
            Times.Once);
        identitySessionStoreMock.Verify(
            s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task AuthorizationCodeCleanup_LogsOnlyTheDeletedCount()
    {
        var logMessages = new List<string>();
        var authorizationCodeStoreMock = new Mock<IAuthorizationCodeStore>();
        authorizationCodeStoreMock
            .Setup(s => s.CleanupExpiredAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(5);

        var serviceProviderMock = CreateMockServiceProvider(
            authorizationCodeStoreMock: authorizationCodeStoreMock);
        CreateMockScopeFactory(serviceProviderMock);
        var keyManagerMock = new Mock<IKeyManager>();
        keyManagerMock.Setup(k => k.NeedsKeyRotationAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var worker = new CleanupWorker(
            serviceProviderMock.Object,
            keyManagerMock.Object,
            new ListLogger<CleanupWorker>(logMessages));

        await RunWorkerUntilAsync(
            worker,
            () =>
            {
                lock (logMessages)
                {
                    return logMessages.Exists(message =>
                        message.Contains("expired authorization codes", StringComparison.Ordinal));
                }
            });

        // DF-03: the cleanup log names the count and nothing else — no code, no digest, and no
        // other row value.
        string message;
        lock (logMessages)
        {
            message = Assert.Single(
                logMessages,
                candidate => candidate.Contains("expired authorization codes", StringComparison.Ordinal));
        }

        Assert.Equal("Deleted 5 expired authorization codes", message);
    }

    private sealed class ListLogger<T>(List<string> messages) : ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (messages)
            {
                messages.Add(formatter(state, exception));
            }
        }
    }
}
