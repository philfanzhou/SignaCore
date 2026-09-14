using Microsoft.Extensions.DependencyInjection;
using ServiceMantle.AspNetCore.Health;
using ServiceMantle.Health;
using ServiceMantle.Installation;
using SignaCore.Domain.Keys;
using SignaCore.Host.HealthChecks;
using Xunit;
using Moq;

namespace SignaCore.Tests.Host.HealthChecks;

/// <summary>
/// Drives the shared decision source the readiness endpoints resolve, with the signing-key gate and
/// a test-owned snapshot source registered. It proves the gate is wired into the one decision every
/// ServiceMantle surface reads, and that a missing base snapshot stays closed without running it.
/// </summary>
public sealed class SigningKeyReadinessDecisionTests
{
    private const string Secret = "Password=decision-secret;-----BEGIN PRIVATE KEY-----";

    private static readonly ServiceHealthSnapshot ReadySnapshot = new(
        ServiceStartupPhase.Completed,
        ServiceMigrationReadinessState.Succeeded,
        ServiceDatabaseReadinessState.Reachable);

    private static readonly ServiceHealthSnapshot PendingSetupSnapshot = new(
        ServiceStartupPhase.PendingSetup,
        ServiceMigrationReadinessState.NotStarted,
        ServiceDatabaseReadinessState.Reachable);

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task GetDecisionAsync_WhenSnapshotAndSigningKeysAreReady_ReturnsReadyWithTheSameSnapshot()
    {
        var keyManager = ReadyKeyManager();
        await using var provider = Build(ReadySnapshot, keyManager);
        using var scope = provider.CreateScope();

        var decision = await scope.ServiceProvider
            .GetRequiredService<IServiceReadinessDecisionSource>()
            .GetDecisionAsync(Token);

        Assert.True(decision.IsReady);
        Assert.Null(decision.ErrorCode);
        Assert.Same(ReadySnapshot, decision.Snapshot);
        keyManager.VerifyGet(manager => manager.InitializationCompleted, Times.Once);
    }

    [Fact]
    public async Task GetDecisionAsync_WhenSigningKeysAreUnavailable_ReturnsNotReadyWithTheProductCodeOnly()
    {
        var keyManager = FaultedKeyManager();
        await using var provider = Build(ReadySnapshot, keyManager);
        using var scope = provider.CreateScope();

        var decision = await scope.ServiceProvider
            .GetRequiredService<IServiceReadinessDecisionSource>()
            .GetDecisionAsync(Token);

        Assert.False(decision.IsReady);
        Assert.Equal(SigningKeyReadinessContributor.SigningKeysUnavailableErrorCode, decision.ErrorCode);
        Assert.Same(ReadySnapshot, decision.Snapshot);
        Assert.DoesNotContain(Secret, decision.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("decision-secret", decision.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(nameof(InvalidOperationException), decision.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetDecisionAsync_WithoutASnapshotSource_FailsClosedAndNeverRunsTheContributor()
    {
        var keyManager = ReadyKeyManager();
        await using var provider = Build(snapshot: null, keyManager);
        using var scope = provider.CreateScope();

        var decision = await scope.ServiceProvider
            .GetRequiredService<IServiceReadinessDecisionSource>()
            .GetDecisionAsync(Token);

        Assert.False(decision.IsReady);
        Assert.Equal(WellKnownServiceReadinessDecisionErrorCodes.ProbeFailed, decision.ErrorCode);
        Assert.Null(decision.Snapshot);
        keyManager.VerifyGet(manager => manager.InitializationCompleted, Times.Never);
    }

    [Fact]
    public async Task GetDecisionAsync_WhenTheBaseSnapshotIsNotReady_ReturnsNotReadyAndNeverRunsTheContributor()
    {
        var keyManager = ReadyKeyManager();
        await using var provider = Build(PendingSetupSnapshot, keyManager);
        using var scope = provider.CreateScope();

        var decision = await scope.ServiceProvider
            .GetRequiredService<IServiceReadinessDecisionSource>()
            .GetDecisionAsync(Token);

        Assert.False(decision.IsReady);
        Assert.Same(PendingSetupSnapshot, decision.Snapshot);
        keyManager.VerifyGet(manager => manager.InitializationCompleted, Times.Never);
    }

    private static ServiceProvider Build(ServiceHealthSnapshot? snapshot, Mock<IKeyManager> keyManager) =>
        ReadinessComposition.Build((services, _) =>
        {
            services.AddSingleton(keyManager.Object);
            if (snapshot is not null)
            {
                services.AddSingleton<IServiceHealthSnapshotSource>(new StubSnapshotSource(snapshot));
            }
        });

    private static Mock<IKeyManager> ReadyKeyManager()
    {
        var mock = new Mock<IKeyManager>();
        mock.SetupGet(manager => manager.InitializationCompleted).Returns(Task.CompletedTask);
        return mock;
    }

    private static Mock<IKeyManager> FaultedKeyManager()
    {
        var mock = new Mock<IKeyManager>();
        mock.SetupGet(manager => manager.InitializationCompleted)
            .Returns(Task.FromException(new InvalidOperationException(Secret)));
        return mock;
    }
}
