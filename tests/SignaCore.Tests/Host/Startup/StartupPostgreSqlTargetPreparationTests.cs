using Npgsql;
using ServiceMantle.Bootstrap;
using SignaCore.Database;
using SignaCore.Host.Startup;
using Xunit;

namespace SignaCore.Tests.Host.Startup;

/// <summary>
/// Startup PostgreSQL target preparation through the shared provider: an existing connectable
/// target is never re-created or probed through the maintenance database, a proven-missing target
/// is created exactly once with the maintenance convention and a mandatory confirming observation,
/// every closed failure classification fails startup without leaking connection secrets, and
/// caller cancellation propagates as the original cancellation instead of a result.
/// </summary>
public sealed class StartupPostgreSqlTargetPreparationTests
{
    private const string PasswordSentinel = "correct-horse-battery-staple-SENTINEL";

    private static DatabaseOptions Options(string? connectionString = null) => new()
    {
        Provider = "PostgreSQL",
        ServerVersion = "15",
        ConnectionString = connectionString ?? $"""
            Host=127.0.0.1;Port=5432;Database=signacore_tests;Username=signacore;Password={PasswordSentinel}
            """
    };

    // ----- Existing connectable target -----

    [Fact]
    public async Task ExistingConnectableTarget_ReturnsWithoutPreparationOrMaintenanceAccess()
    {
        var provider = new ScriptedPreparationProvider(
            [DatabaseTargetObservation.TargetConnectable()]);

        await StartupDatabase.EnsurePostgreSqlDatabaseExistsAsync(
            Options(), provider, TestContext.Current.CancellationToken);

        Assert.Equal(1, provider.ObserveCount);
        Assert.Empty(provider.PrepareRequests);
    }

    // ----- Missing target creation -----

    [Fact]
    public async Task MissingTarget_PrepareUsesMaintenanceConventionThenConfirmsConnectable()
    {
        var provider = new ScriptedPreparationProvider(
            [
                DatabaseTargetObservation.TargetMissing(),
                DatabaseTargetObservation.TargetConnectable()
            ],
            [DatabaseTargetPreparationResult.Success(DatabaseTargetPreparationOutcome.Created)]);

        await StartupDatabase.EnsurePostgreSqlDatabaseExistsAsync(
            Options(), provider, TestContext.Current.CancellationToken);

        var request = Assert.Single(provider.PrepareRequests);
        var administrative = new NpgsqlConnectionStringBuilder(request.AdministrativeConnectionString);
        var target = new NpgsqlConnectionStringBuilder(request.Target.ConnectionString);
        Assert.Equal("postgres", administrative.Database);
        Assert.False(administrative.Pooling);
        Assert.Equal(target.Host, administrative.Host);
        Assert.Equal(target.Port, administrative.Port);
        Assert.Equal(target.Username, administrative.Username);
        Assert.Equal(target.Password, administrative.Password);
        Assert.Equal("signacore_tests", target.Database);
        Assert.Equal(TimeSpan.FromSeconds(30), Assert.Single(provider.PrepareTimeouts));
        Assert.Equal(2, provider.ObserveCount);
    }

    [Fact]
    public async Task MissingTarget_ConcurrentWinnerAlreadyExists_IsConfirmedLikeACreation()
    {
        var provider = new ScriptedPreparationProvider(
            [
                DatabaseTargetObservation.TargetMissing(),
                DatabaseTargetObservation.TargetConnectable()
            ],
            [DatabaseTargetPreparationResult.Success(DatabaseTargetPreparationOutcome.AlreadyExists)]);

        // Another instance created the target after the missing observation: the shared provider
        // resolves the race and this instance still converges on the confirming observation.
        await StartupDatabase.EnsurePostgreSqlDatabaseExistsAsync(
            Options(), provider, TestContext.Current.CancellationToken);

        Assert.Equal(2, provider.ObserveCount);
    }

    // ----- Fail-closed observation classifications -----

    [Theory]
    [InlineData(WellKnownDatabaseTargetPreparationErrorCodes.AuthenticationFailed)]
    [InlineData(WellKnownDatabaseTargetPreparationErrorCodes.PermissionDenied)]
    [InlineData(WellKnownDatabaseTargetPreparationErrorCodes.ConnectionFailed)]
    [InlineData(WellKnownDatabaseTargetPreparationErrorCodes.InvalidTarget)]
    public async Task NonMissingObservation_FailsClosedWithoutPreparation(string errorCode)
    {
        var provider = new ScriptedPreparationProvider(
            [DatabaseTargetObservation.TargetUnreachable(errorCode, targetExists: null)]);

        var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
            StartupDatabase.EnsurePostgreSqlDatabaseExistsAsync(
                Options(), provider, TestContext.Current.CancellationToken));

        Assert.Equal(errorCode, exception.ErrorCode);
        Assert.DoesNotContain(PasswordSentinel, exception.Message, StringComparison.Ordinal);
        Assert.Null(exception.InnerException);
        Assert.Empty(provider.PrepareRequests);
    }

    [Fact]
    public async Task ServerUnreachableObservation_FailsClosedWithItsClassification()
    {
        var provider = new ScriptedPreparationProvider(
            [DatabaseTargetObservation.ServerUnreachable(
                WellKnownDatabaseTargetPreparationErrorCodes.ConnectionFailed)]);

        var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
            StartupDatabase.EnsurePostgreSqlDatabaseExistsAsync(
                Options(), provider, TestContext.Current.CancellationToken));

        Assert.Equal(
            WellKnownDatabaseTargetPreparationErrorCodes.ConnectionFailed,
            exception.ErrorCode);
        Assert.Empty(provider.PrepareRequests);
    }

    // ----- Preparation failures and the mandatory confirmation -----

    [Fact]
    public async Task PreparationFailure_FailsClosedWithoutConfirmationObservation()
    {
        var provider = new ScriptedPreparationProvider(
            [DatabaseTargetObservation.TargetMissing()],
            [DatabaseTargetPreparationResult.Failure(
                WellKnownDatabaseTargetPreparationErrorCodes.PermissionDenied)]);

        var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
            StartupDatabase.EnsurePostgreSqlDatabaseExistsAsync(
                Options(), provider, TestContext.Current.CancellationToken));

        Assert.Equal(
            WellKnownDatabaseTargetPreparationErrorCodes.PermissionDenied,
            exception.ErrorCode);
        Assert.DoesNotContain(PasswordSentinel, exception.Message, StringComparison.Ordinal);
        Assert.Equal(1, provider.ObserveCount);
    }

    [Fact]
    public async Task PreparationSucceededButConfirmationNotConnectable_FailsClosedBeforeMigration()
    {
        var provider = new ScriptedPreparationProvider(
            [
                DatabaseTargetObservation.TargetMissing(),
                DatabaseTargetObservation.TargetUnreachable(
                    WellKnownDatabaseTargetPreparationErrorCodes.ConnectionFailed,
                    targetExists: null)
            ],
            [DatabaseTargetPreparationResult.Success(DatabaseTargetPreparationOutcome.Created)]);

        var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
            StartupDatabase.EnsurePostgreSqlDatabaseExistsAsync(
                Options(), provider, TestContext.Current.CancellationToken));

        Assert.Equal(
            WellKnownDatabaseTargetPreparationErrorCodes.ConnectionFailed,
            exception.ErrorCode);
        Assert.Equal(2, provider.ObserveCount);
        Assert.DoesNotContain(PasswordSentinel, exception.Message, StringComparison.Ordinal);
        Assert.Null(exception.InnerException);
    }

    [Theory]
    [InlineData(WellKnownDatabaseTargetPreparationErrorCodes.PreparationFailed)]
    [InlineData(WellKnownDatabaseTargetPreparationErrorCodes.ProviderMismatch)]
    [InlineData(WellKnownDatabaseTargetPreparationErrorCodes.CapabilityNotSupported)]
    public async Task UnclassifiedObservationCode_FailsClosedWithTheGenericMessage(string errorCode)
    {
        // Codes without a dedicated operator message still fail closed through the fixed generic
        // message; the shared factories validate the closed code set, so no other code can reach
        // this arm in a real run.
        var provider = new ScriptedPreparationProvider(
            [DatabaseTargetObservation.TargetUnreachable(errorCode, targetExists: null)]);

        var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
            StartupDatabase.EnsurePostgreSqlDatabaseExistsAsync(
                Options(), provider, TestContext.Current.CancellationToken));

        Assert.Equal(errorCode, exception.ErrorCode);
        Assert.Contains("could not be prepared", exception.Message, StringComparison.Ordinal);
    }

    // ----- Cancellation -----

    [Fact]
    public async Task CancellationDuringObservation_PropagatesAsCallerCancellation()
    {
        var provider = new ScriptedPreparationProvider(
            [],
            [],
            observeError: new OperationCanceledException("cancelled by the test"));

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            StartupDatabase.EnsurePostgreSqlDatabaseExistsAsync(
                Options(), provider, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CancellationDuringPreparation_PropagatesAsCallerCancellation()
    {
        var provider = new ScriptedPreparationProvider(
            [DatabaseTargetObservation.TargetMissing()],
            [],
            prepareError: new OperationCanceledException("cancelled by the test"));

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            StartupDatabase.EnsurePostgreSqlDatabaseExistsAsync(
                Options(), provider, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task PreCancelledToken_FailsBeforeAnyObservation()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        var provider = new ScriptedPreparationProvider(
            [DatabaseTargetObservation.TargetMissing()]);

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            StartupDatabase.EnsurePostgreSqlDatabaseExistsAsync(
                Options(), provider, cancellation.Token));
        Assert.Equal(0, provider.ObserveCount);
    }

    // ----- Real provider input classifications (no server needed) -----

    [Fact]
    public async Task MalformedConnectionString_FailsClosedAsInvalidTarget()
    {
        var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
            StartupDatabase.EnsurePostgreSqlDatabaseExistsAsync(
                Options("not a connection string at all"),
                targetPreparationProvider: null,
                TestContext.Current.CancellationToken));

        Assert.Equal(
            WellKnownDatabaseTargetPreparationErrorCodes.InvalidTarget,
            exception.ErrorCode);
    }

    [Fact]
    public async Task UnreachableServer_FailsClosedAsConnectionFailedWithoutSecrets()
    {
        // Port 1 on the loopback interface is closed everywhere these tests run, so the real
        // provider observes a refused connection immediately and classifies it.
        var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
            StartupDatabase.EnsurePostgreSqlDatabaseExistsAsync(
                Options($"Host=127.0.0.1;Port=1;Database=signacore_tests;Username=signacore;Password={PasswordSentinel};Timeout=3"),
                targetPreparationProvider: null,
                TestContext.Current.CancellationToken));

        Assert.Equal(
            WellKnownDatabaseTargetPreparationErrorCodes.ConnectionFailed,
            exception.ErrorCode);
        Assert.DoesNotContain(PasswordSentinel, exception.Message, StringComparison.Ordinal);
        Assert.Null(exception.InnerException);
    }

    /// <summary>
    /// A preparation provider whose observation and preparation results are supplied by the test,
    /// so the startup classification steps run deterministically without a reachable server.
    /// </summary>
    private sealed class ScriptedPreparationProvider : IDatabaseTargetPreparationProvider
    {
        private readonly Queue<DatabaseTargetObservation> observations;
        private readonly Queue<DatabaseTargetPreparationResult> preparations;
        private readonly Exception? observeError;
        private readonly Exception? prepareError;

        public ScriptedPreparationProvider(
            IReadOnlyList<DatabaseTargetObservation> observations,
            IReadOnlyList<DatabaseTargetPreparationResult>? preparations = null,
            Exception? observeError = null,
            Exception? prepareError = null)
        {
            this.observations = new Queue<DatabaseTargetObservation>(observations);
            this.preparations = new Queue<DatabaseTargetPreparationResult>(preparations ?? []);
            this.observeError = observeError;
            this.prepareError = prepareError;
        }

        public string ProviderId => "PostgreSQL";

        public BootstrapDatabaseTargetKind TargetKind => BootstrapDatabaseTargetKind.ServerDatabase;

        public int ObserveCount { get; private set; }

        public List<DatabaseTargetPreparationRequest> PrepareRequests { get; } = [];

        public List<TimeSpan> PrepareTimeouts { get; } = [];

        public ValueTask<DatabaseTargetObservation> ObserveAsync(
            BootstrapDatabaseConfiguration target,
            CancellationToken cancellationToken)
        {
            if (observeError is not null)
            {
                throw observeError;
            }

            ObserveCount++;
            return ValueTask.FromResult(
                observations.Count > 0
                    ? observations.Dequeue()
                    : DatabaseTargetObservation.ServerUnreachable(
                        WellKnownDatabaseTargetPreparationErrorCodes.PreparationFailed));
        }

        public ValueTask<DatabaseTargetPreparationResult> PrepareAsync(
            DatabaseTargetPreparationRequest request,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            if (prepareError is not null)
            {
                throw prepareError;
            }

            PrepareRequests.Add(request);
            PrepareTimeouts.Add(timeout);
            return ValueTask.FromResult(
                preparations.Count > 0
                    ? preparations.Dequeue()
                    : DatabaseTargetPreparationResult.Failure(
                        WellKnownDatabaseTargetPreparationErrorCodes.PreparationFailed));
        }
    }
}
