using Moq;
using ServiceMantle.Health;
using ServiceMantle.Installation;
using SignaCore.Domain.Keys;
using SignaCore.Host.HealthChecks;
using Xunit;

namespace SignaCore.Tests.Host.HealthChecks;

/// <summary>
/// Pins how the signing-key gate behaves inside the shared ordered evaluation: its own code survives
/// a rejection, a failing neighbour is mapped to the shared failure code without short-circuiting it,
/// the shared budget stays a timeout, and a caller cancellation stays the caller's cancellation.
/// </summary>
public sealed class SigningKeyReadinessCombinerTests
{
    private const string Secret = "Password=combiner-secret;-----BEGIN PRIVATE KEY-----";

    private static readonly ServiceHealthSnapshot ReadySnapshot = new(
        ServiceStartupPhase.Completed,
        ServiceMigrationReadinessState.Succeeded,
        ServiceDatabaseReadinessState.Reachable);

    private static readonly TimeSpan Budget = TimeSpan.FromMilliseconds(250);

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task EvaluateAsync_WhenSigningKeysAreUnavailable_ReportsTheProductCodeAndStillRunsTheNextContributor()
    {
        var keyManager = FaultedKeyManager();
        var later = new ScriptedReadinessContributor(
            SigningKeyReadinessContributor.SigningKeyOrder + 100,
            (_, _) => ValueTask.FromResult(ServiceReadinessContributorResult.Ready()));
        var combiner = new ServiceReadinessContributorCombiner(
            [new SigningKeyReadinessContributor(keyManager.Object), later]);

        var result = await combiner.EvaluateAsync(ReadySnapshot, Budget, Token);

        Assert.False(result.IsReady);
        Assert.Equal(SigningKeyReadinessContributor.SigningKeysUnavailableErrorCode, result.ErrorCode);
        Assert.Equal(1, later.Calls);
        Assert.DoesNotContain(Secret, result.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task EvaluateAsync_WhenAnEarlierContributorThrows_ReportsContributorFailedAndStillConsultsTheSigningKeys()
    {
        var keyManager = ReadyKeyManager();
        var throwing = new ScriptedReadinessContributor(
            SigningKeyReadinessContributor.SigningKeyOrder - 50,
            (_, _) => throw new InvalidOperationException(Secret));
        var combiner = new ServiceReadinessContributorCombiner(
            [throwing, new SigningKeyReadinessContributor(keyManager.Object)]);

        var result = await combiner.EvaluateAsync(ReadySnapshot, Budget, Token);

        Assert.False(result.IsReady);
        Assert.Equal(WellKnownServiceReadinessContributorErrorCodes.ContributorFailed, result.ErrorCode);
        keyManager.VerifyGet(manager => manager.InitializationCompleted, Times.Once);
        Assert.DoesNotContain(Secret, result.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("combiner-secret", result.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task EvaluateAsync_WhenAnEarlierContributorReturnsNull_ReportsContributorFailed()
    {
        var nullResult = new ScriptedReadinessContributor(
            SigningKeyReadinessContributor.SigningKeyOrder - 50,
            (_, _) => ValueTask.FromResult<ServiceReadinessContributorResult>(null!));
        var combiner = new ServiceReadinessContributorCombiner(
            [nullResult, new SigningKeyReadinessContributor(ReadyKeyManager().Object)]);

        var result = await combiner.EvaluateAsync(ReadySnapshot, Budget, Token);

        Assert.False(result.IsReady);
        Assert.Equal(WellKnownServiceReadinessContributorErrorCodes.ContributorFailed, result.ErrorCode);
        Assert.Equal(1, nullResult.Calls);
    }

    [Fact]
    public async Task EvaluateAsync_WhenTheSharedBudgetExpires_ReportsContributorTimeoutAndNeverReachesTheSigningKeys()
    {
        var time = new ManualTimeProvider();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var keyManager = ReadyKeyManager();
        var blocking = new ScriptedReadinessContributor(
            SigningKeyReadinessContributor.SigningKeyOrder - 50,
            async (_, cancellationToken) =>
            {
                entered.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return ServiceReadinessContributorResult.Ready();
            });
        var combiner = new ServiceReadinessContributorCombiner(
            [blocking, new SigningKeyReadinessContributor(keyManager.Object)], time);

        var evaluation = combiner.EvaluateAsync(ReadySnapshot, Budget, Token).AsTask();
        await entered.Task.WaitAsync(Token);
        time.Advance(Budget);

        // Virtual time drives the outcome; the real bound only turns a regression into a failure.
        var result = await evaluation.WaitAsync(TimeSpan.FromSeconds(30), Token);

        Assert.False(result.IsReady);
        Assert.Equal(WellKnownServiceReadinessContributorErrorCodes.ContributorTimeout, result.ErrorCode);
        keyManager.VerifyGet(manager => manager.InitializationCompleted, Times.Never);
    }

    [Fact]
    public async Task EvaluateAsync_WhenTheCallerCancels_ThrowsWithTheCallerTokenInsteadOfATimeout()
    {
        var time = new ManualTimeProvider();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var blocking = new ScriptedReadinessContributor(1, async (_, cancellationToken) =>
        {
            entered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return ServiceReadinessContributorResult.Ready();
        });
        var combiner = new ServiceReadinessContributorCombiner([blocking], time);
        using var cancellation = new CancellationTokenSource();

        var evaluation = combiner.EvaluateAsync(ReadySnapshot, Budget, cancellation.Token).AsTask();
        await entered.Task.WaitAsync(Token);

        // The budget stays deliberately unspent, so only the caller can end the evaluation.
        time.Advance(TimeSpan.FromMilliseconds(100));
        await cancellation.CancelAsync();
        var exception = await Assert.ThrowsAsync<OperationCanceledException>(
            () => evaluation.WaitAsync(TimeSpan.FromSeconds(30), Token));

        Assert.Equal(cancellation.Token, exception.CancellationToken);
    }

    [Fact]
    public void Constructor_RejectsASecondContributorOnTheSigningKeyOrder()
    {
        var duplicate = new ScriptedReadinessContributor(
            SigningKeyReadinessContributor.SigningKeyOrder,
            (_, _) => ValueTask.FromResult(ServiceReadinessContributorResult.Ready()));

        var exception = Assert.Throws<InvalidOperationException>(() => new ServiceReadinessContributorCombiner(
            [new SigningKeyReadinessContributor(ReadyKeyManager().Object), duplicate]));

        Assert.Equal("Service readiness contributor registration is invalid.", exception.Message);
        Assert.Null(exception.InnerException);
    }

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
