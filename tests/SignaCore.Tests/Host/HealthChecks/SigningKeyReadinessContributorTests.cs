using Microsoft.Extensions.Diagnostics.HealthChecks;
using Moq;
using ServiceMantle.Health;
using ServiceMantle.Installation;
using SignaCore.Domain.Keys;
using SignaCore.Host.HealthChecks;
using Xunit;

namespace SignaCore.Tests.Host.HealthChecks;

/// <summary>
/// Pins the signing-key readiness gate: it decides exactly what <see cref="SigningKeysHealthCheck"/>
/// decides, and the only thing that may leave it is a stable safe code.
/// </summary>
public sealed class SigningKeyReadinessContributorTests
{
    private const string Secret =
        "Server=db.internal;Password=master-key-secret;-----BEGIN PRIVATE KEY-----";

    private static readonly ServiceHealthSnapshot ReadySnapshot = new(
        ServiceStartupPhase.Completed,
        ServiceMigrationReadinessState.Succeeded,
        ServiceDatabaseReadinessState.Reachable);

    private static CancellationToken Token => TestContext.Current.CancellationToken;

    [Fact]
    public async Task EvaluateAsync_WhenInitializationCompleted_ReturnsReady()
    {
        var contributor = new SigningKeyReadinessContributor(KeyManager(Task.CompletedTask).Object);

        var result = await contributor.EvaluateAsync(ReadySnapshot, Token);

        Assert.True(result.IsReady);
        Assert.Null(result.ErrorCode);
    }

    [Fact]
    public async Task EvaluateAsync_WhenInitializationFaulted_ReturnsNotReadyWithTheSafeCodeOnly()
    {
        var contributor = new SigningKeyReadinessContributor(
            KeyManager(Task.FromException(new InvalidOperationException(Secret))).Object);

        var result = await contributor.EvaluateAsync(ReadySnapshot, Token);

        Assert.False(result.IsReady);
        Assert.Equal(SigningKeyReadinessContributor.SigningKeysUnavailableErrorCode, result.ErrorCode);
        Assert.Equal("signacore.signing_keys_unavailable", result.ErrorCode);
        Assert.DoesNotContain(Secret, result.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("master-key-secret", result.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(nameof(InvalidOperationException), result.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task EvaluateAsync_WhenInitializationHasNotCompleted_ReturnsNotReadyWithTheSafeCode()
    {
        var pending = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var contributor = new SigningKeyReadinessContributor(KeyManager(pending.Task).Object);

        var result = await contributor.EvaluateAsync(ReadySnapshot, Token);

        Assert.False(result.IsReady);
        Assert.Equal(SigningKeyReadinessContributor.SigningKeysUnavailableErrorCode, result.ErrorCode);
        pending.SetResult(true);
    }

    /// <summary>
    /// The contributor replaces nothing today: it has to reach the same verdict the mapped
    /// <c>/health/ready</c> check reaches, state by state.
    /// </summary>
    [Theory]
    [InlineData("completed")]
    [InlineData("faulted")]
    [InlineData("pending")]
    public async Task EvaluateAsync_AgreesWithSigningKeysHealthCheck_OnEveryInitializationState(string state)
    {
        var pending = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var initialization = state switch
        {
            "completed" => Task.CompletedTask,
            "faulted" => Task.FromException(new InvalidOperationException(Secret)),
            _ => pending.Task,
        };
        var keyManager = KeyManager(initialization);
        var contributor = new SigningKeyReadinessContributor(keyManager.Object);
        var healthCheck = new SigningKeysHealthCheck(keyManager.Object);

        var result = await contributor.EvaluateAsync(ReadySnapshot, Token);
        var check = await healthCheck.CheckHealthAsync(new HealthCheckContext(), Token);
        pending.TrySetResult(true);

        Assert.Equal(check.Status == HealthStatus.Healthy, result.IsReady);
        if (check.Status == HealthStatus.Healthy)
        {
            Assert.Null(result.ErrorCode);
            return;
        }

        Assert.Equal(SigningKeyReadinessContributor.SigningKeysUnavailableErrorCode, result.ErrorCode);
        // The existing check hands the faulting exception to the health report; the shared result
        // type structurally cannot, which is the whole point of the safe-code contract.
        Assert.Equal(state == "faulted", check.Exception is not null);
        Assert.DoesNotContain(Secret, result.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("initialization", result.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task EvaluateAsync_WhenTheCallerCancelled_ThrowsBeforeReadingTheKeyManager()
    {
        var keyManager = KeyManager(Task.CompletedTask);
        var contributor = new SigningKeyReadinessContributor(keyManager.Object);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => contributor.EvaluateAsync(ReadySnapshot, cancellation.Token).AsTask());

        Assert.Equal(cancellation.Token, exception.CancellationToken);
        keyManager.VerifyGet(manager => manager.InitializationCompleted, Times.Never);
    }

    [Fact]
    public async Task EvaluateAsync_WithoutASnapshot_Throws()
    {
        var contributor = new SigningKeyReadinessContributor(KeyManager(Task.CompletedTask).Object);

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => contributor.EvaluateAsync(null!, Token).AsTask());
    }

    [Fact]
    public void Order_IsTheFixedStableValue()
    {
        Assert.Equal(100, SigningKeyReadinessContributor.SigningKeyOrder);
        Assert.Equal(
            SigningKeyReadinessContributor.SigningKeyOrder,
            new SigningKeyReadinessContributor(KeyManager(Task.CompletedTask).Object).Order);
    }

    private static Mock<IKeyManager> KeyManager(Task initialization)
    {
        var mock = new Mock<IKeyManager>();
        mock.SetupGet(manager => manager.InitializationCompleted).Returns(initialization);
        return mock;
    }
}
