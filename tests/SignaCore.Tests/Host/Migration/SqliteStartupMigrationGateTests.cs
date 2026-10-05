using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using ServiceMantle;
using ServiceMantle.Bootstrap;
using ServiceMantle.Installation;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host.Bootstrap;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;
using SignaCore.Host.Migration;
using SignaCore.Host.Startup;
using ServiceMantle.Migration;
using Xunit;
using static SignaCore.Tests.Host.Migration.SqliteMigrationGateTestSupport;

namespace SignaCore.Tests.Host.Migration;

/// <summary>
/// Startup-gate and bootstrap-phase behavior on SQLite: the shared orchestration serializes on the
/// process-local target, failures never reach installation resolution or setup-code output, the
/// fixed error projection carries no secrets or original exceptions, caller cancellation takes
/// precedence at every reachable checkpoint, and the fresh/upgrade install flows keep their
/// original behavior.
/// </summary>
public sealed class SqliteStartupMigrationGateTests
{
    private const string PreServiceInstallations = "20260831103622_PersistInteractiveOidcClientConfiguration";
    private const string SetupCodeSentinel = "SETUP-CODE-987654-SENTINEL";

    [Fact]
    public async Task Gate_EachRunUsesFreshReceiptAndLeavesBorrowedContextAndExecutorAlive()
    {
        var path = NewDatabasePath();
        try
        {
            var options = TestDatabaseOptions(path);
            var contextOptions = new DbContextOptionsBuilder<IdentityDbContext>();
            contextOptions.UseIdentityDatabase(options);
            await using var db = new IdentityDbContext(contextOptions.Options);
            using var executor = new DisposableExecutor(new SignaCoreMigrationExecutor(db, options));

            await StartupMigrationGate.RunAsync(db, options, NullLogger.Instance, executor,
                TestContext.Current.CancellationToken);
            Assert.False(executor.Disposed);
            Assert.Equal(1, executor.ExecuteCount);
            var history = (await db.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken)).ToArray();
            Assert.NotEmpty(history);

            // A second direct call must receive a fresh receipt, observe current, and skip migration.
            await StartupMigrationGate.RunAsync(db, options, NullLogger.Instance, executor,
                TestContext.Current.CancellationToken);
            Assert.False(executor.Disposed);
            Assert.Equal(1, executor.ExecuteCount);
            Assert.Equal(history, await db.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken));
            await db.Database.ExecuteSqlRawAsync("SELECT 1;", TestContext.Current.CancellationToken);
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public async Task CoreComposition_PrepareAndRepeatedRunShareGateWithoutHostedServicesOrExecutorOwnership()
    {
        var path = NewDatabasePath();
        try
        {
            var options = TestDatabaseOptions(path);
            var contextOptions = new DbContextOptionsBuilder<IdentityDbContext>();
            contextOptions.UseIdentityDatabase(options);
            await using var db = new IdentityDbContext(contextOptions.Options);
            using var executor = new DisposableExecutor(new SignaCoreMigrationExecutor(db, options));
            await using (var composition = StartupDatabaseComposition.Create(options, executor))
            {
                Assert.Empty(composition.Services.GetServices<IHostedService>());
                Assert.Same(executor, composition.Services.GetRequiredService<IDatabaseMigrationExecutor>());
                var gate = composition.Services.GetRequiredService<StartupDatabaseGate>();
                await composition.PrepareAsync(TestContext.Current.CancellationToken);
                Assert.Equal(0, executor.ExecuteCount);
                Assert.True(File.Exists(path));
                Assert.Empty(await db.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken));
                await composition.RunMigrationAsync(NullLogger.Instance, TestContext.Current.CancellationToken);
                await composition.RunMigrationAsync(NullLogger.Instance, TestContext.Current.CancellationToken);
                Assert.Same(gate, composition.Services.GetRequiredService<StartupDatabaseGate>());
                Assert.Equal(1, executor.ExecuteCount);
                Assert.False(executor.Disposed);
            }
            Assert.False(executor.Disposed);
            await db.Database.ExecuteSqlRawAsync("SELECT 1;", TestContext.Current.CancellationToken);
        }
        finally
        {
            Cleanup(path);
        }
    }

    private sealed class DisposableExecutor(IDatabaseMigrationExecutor inner) : IDatabaseMigrationExecutor, IDisposable
    {
        public bool Disposed { get; private set; }
        public int ExecuteCount { get; private set; }
        public ValueTask<MigrationObservationState> InspectAsync(CancellationToken cancellationToken = default)
            => inner.InspectAsync(cancellationToken);
        public ValueTask ExecuteAsync(CancellationToken cancellationToken = default)
        {
            ExecuteCount++;
            return inner.ExecuteAsync(cancellationToken);
        }
        public void Dispose() => Disposed = true;
    }

    // ----- Shared single-instance serialization -----

    [Fact]
    public async Task Gate_TwoInstancesSameTarget_SecondWaitsThenReinspectsAndSkipsExecute()
    {
        var databasePath = NewDatabasePath();
        try
        {
            var order = new List<string>();
            var sync = new object();

            void Record(string @event)
            {
                lock (sync)
                {
                    order.Add(@event);
                }
            }

            var executeStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var allowExecuteCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var executed = false;

            var first = new DelegateMigrationExecutor
            {
                InspectImpl = _ => ValueTask.FromResult(
                    executed ? MigrationObservationState.CurrentVersionCompatible : MigrationObservationState.Empty),
                ExecuteImpl = async _ =>
                {
                    Record("first-execute");
                    executed = true;
                    executeStarted.TrySetResult();
                    await allowExecuteCompletion.Task;
                }
            };

            var secondInspected = false;
            var second = new DelegateMigrationExecutor
            {
                InspectImpl = _ =>
                {
                    Record("second-inspect");
                    secondInspected = true;
                    return ValueTask.FromResult(
                        executed
                            ? MigrationObservationState.CurrentVersionCompatible
                            : MigrationObservationState.Empty);
                },
                ExecuteImpl = _ =>
                {
                    Record("second-execute");
                    return ValueTask.CompletedTask;
                }
            };

            var firstGate = RunGate(databasePath, first);
            await executeStarted.Task.WaitAsync(TimeSpan.FromSeconds(30));

            var secondGate = RunGate(databasePath, second);
            await Assert.ThrowsAsync<TimeoutException>(() =>
                secondGate.WaitAsync(TimeSpan.FromMilliseconds(300)));

            allowExecuteCompletion.TrySetResult();
            await firstGate;
            await secondGate;

            Assert.Equal(1, first.ExecuteCount);
            Assert.Equal(0, second.ExecuteCount);
            Assert.Equal(1, second.InspectCount);
            Assert.True(secondInspected);

            // The second instance only observed the target after the first instance's execution,
            // proving the shared turn was actually held and re-inspected under it.
            var executeIndex = order.IndexOf("first-execute");
            var inspectIndex = order.IndexOf("second-inspect");
            Assert.True(executeIndex >= 0 && inspectIndex > executeIndex);
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Gate_WaitingForLocalTurn_CancelledByCaller_ThrowsOriginalTokenWithoutExecuting()
    {
        var databasePath = NewDatabasePath();
        try
        {
            var executeStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var allowExecuteCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var holderExecuted = false;
            var holder = new DelegateMigrationExecutor
            {
                InspectImpl = _ => ValueTask.FromResult(holderExecuted
                    ? MigrationObservationState.CurrentVersionCompatible
                    : MigrationObservationState.Empty),
                ExecuteImpl = async _ =>
                {
                    holderExecuted = true;
                    executeStarted.TrySetResult();
                    await allowExecuteCompletion.Task;
                }
            };

            var holderGate = RunGate(databasePath, holder);
            await executeStarted.Task.WaitAsync(TimeSpan.FromSeconds(30));

            using var cts = new CancellationTokenSource();
            var waitingGate = RunGate(databasePath, new DelegateMigrationExecutor(), cts.Token);
            await Task.Delay(200, TestContext.Current.CancellationToken);
            Assert.False(waitingGate.IsCompleted);
            cts.Cancel();

            var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waitingGate);
            Assert.Equal(cts.Token, exception.CancellationToken);

            allowExecuteCompletion.TrySetResult();
            await holderGate;
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    // ----- Fixed failure projection -----

    [Fact]
    public async Task Gate_ExecuteFailure_DeliversFixedCodeAndMessageWithoutSecretsOrOriginalException()
    {
        var databasePath = NewDatabasePath();
        try
        {
            var failing = new DelegateMigrationExecutor
            {
                InspectImpl = _ => ValueTask.FromResult(MigrationObservationState.Empty),
                ExecuteImpl = _ => throw new InvalidOperationException(
                    $"boom with password=super-secret-pw and setup code {SetupCodeSentinel} and inner detail")
            };

            var exception = await Assert.ThrowsAsync<StartupMigrationException>(
                () => RunGate(databasePath, failing));

            Assert.Equal(WellKnownMigrationErrorCodes.ExecutionFailed, exception.ErrorCode);
            Assert.Equal(
                "SignaCore startup database migration failed (migration.execution_failed).",
                exception.Message);
            Assert.DoesNotContain("super-secret-pw", exception.Message);
            Assert.DoesNotContain(SetupCodeSentinel, exception.Message);
            Assert.DoesNotContain("inner detail", exception.Message);
            Assert.Null(exception.InnerException);
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Gate_FinalStateNotCompatible_DeliversFinalStateInvalid()
    {
        var databasePath = NewDatabasePath();
        try
        {
            var executed = false;
            var lying = new DelegateMigrationExecutor
            {
                InspectImpl = _ => ValueTask.FromResult(executed
                    ? MigrationObservationState.PendingMigration
                    : MigrationObservationState.Empty),
                ExecuteImpl = _ =>
                {
                    executed = true;
                    return ValueTask.CompletedTask;
                }
            };

            var exception = await Assert.ThrowsAsync<StartupMigrationException>(
                () => RunGate(databasePath, lying));
            Assert.Equal(WellKnownMigrationErrorCodes.FinalStateInvalid, exception.ErrorCode);
            Assert.Equal(1, lying.ExecuteCount);
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Gate_CorruptFile_DeliversInspectionFailedWithoutOriginalException()
    {
        var databasePath = NewDatabasePath();
        var corruptBytes = Enumerable.Repeat((byte)0x41, 512).ToArray();
        File.WriteAllBytes(databasePath, corruptBytes);
        try
        {
            // A supported ordinary file reaches the real executor, whose catalog inspection fails.
            var options = TestDatabaseOptions(databasePath);
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(options);
            await using var db = new IdentityDbContext(optionsBuilder.Options);

            var exception = await Assert.ThrowsAsync<StartupMigrationException>(() =>
                StartupMigrationGate.RunAsync(
                    db,
                    options,
                    NullLogger.Instance,
                    new SignaCoreMigrationExecutor(db, options),
                    TestContext.Current.CancellationToken));

            Assert.Equal(WellKnownMigrationErrorCodes.InspectionFailed, exception.ErrorCode);
            Assert.DoesNotContain(databasePath, exception.Message);
            Assert.Null(exception.InnerException);
            Assert.Equal(corruptBytes, File.ReadAllBytes(databasePath));
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    [Theory]
    [InlineData("relative")]
    [InlineData("uri")]
    [InlineData("shared-cache")]
    [InlineData("read-only")]
    [InlineData("noncanonical")]
    [InlineData("directory")]
    [InlineData("symlink")]
    public async Task Gate_UnsupportedTarget_FailsLockSafelyWithoutCallingExecutorOrWritingFiles(string kind)
    {
        var directory = Path.Combine(PhysicalTempPath(), $"signacore-gate-invalid-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var databasePath = Path.Combine(directory, "identity.db");
        var target = databasePath;
        string? extra = null;
        switch (kind)
        {
            case "relative":
                target = Path.GetRelativePath(Environment.CurrentDirectory, databasePath);
                break;
            case "uri":
                target = $"file:{databasePath}";
                break;
            case "shared-cache":
                extra = "Cache=Shared";
                break;
            case "read-only":
                extra = "Mode=ReadOnly";
                break;
            case "noncanonical":
                target = Path.Combine(directory, ".", "identity.db");
                break;
            case "directory":
                target = directory;
                break;
            case "symlink":
                File.WriteAllBytes(databasePath, []);
                target = Path.Combine(directory, "link.db");
                File.CreateSymbolicLink(target, databasePath);
                break;
        }

        try
        {
            var entriesBefore = Directory.GetFileSystemEntries(directory).Order().ToArray();
            var executor = new DelegateMigrationExecutor();
            var exception = await Assert.ThrowsAsync<StartupMigrationException>(() =>
                RunGate(target, executor, TestContext.Current.CancellationToken, extra));

            Assert.Equal(WellKnownMigrationErrorCodes.LockFailed, exception.ErrorCode);
            Assert.Equal("SignaCore startup database migration failed (migration.lock_failed).", exception.Message);
            Assert.DoesNotContain(target, exception.Message);
            Assert.DoesNotContain(directory, exception.Message);
            Assert.Null(exception.InnerException);
            Assert.Equal(0, executor.InspectCount);
            Assert.Equal(0, executor.ExecuteCount);
            Assert.Equal(entriesBefore, Directory.GetFileSystemEntries(directory).Order().ToArray());
            if (kind == "symlink")
            {
                Assert.Empty(File.ReadAllBytes(databasePath));
            }
            else
            {
                Assert.False(File.Exists(databasePath));
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    // ----- Caller cancellation checkpoints (single-instance path) -----

    [Fact]
    public async Task Gate_CancelledBeforeCall_ThrowsOriginalToken()
    {
        var databasePath = NewDatabasePath();
        try
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            var executor = new DelegateMigrationExecutor();

            var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => RunGate(databasePath, executor, cts.Token));
            Assert.Equal(cts.Token, exception.CancellationToken);
            Assert.Equal(0, executor.InspectCount);
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Gate_CancelledDuringInspect_ThrowsOriginalToken()
    {
        var databasePath = NewDatabasePath();
        try
        {
            using var cts = new CancellationTokenSource();
            var inspectEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var releaseInspection = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var executor = new DelegateMigrationExecutor
            {
                InspectImpl = async token =>
                {
                    inspectEntered.TrySetResult();
                    await releaseInspection.Task.WaitAsync(token);
                    return MigrationObservationState.Empty;
                }
            };

            var gate = RunGate(databasePath, executor, cts.Token);
            await inspectEntered.Task.WaitAsync(TimeSpan.FromSeconds(30));
            cts.Cancel();
            releaseInspection.TrySetResult();

            var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => gate);
            Assert.Equal(cts.Token, exception.CancellationToken);
            Assert.Equal(0, executor.ExecuteCount);
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Gate_CancelledDuringExecute_ThrowsOriginalToken()
    {
        var databasePath = NewDatabasePath();
        try
        {
            using var cts = new CancellationTokenSource();
            var executeEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var releaseExecute = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var executor = new DelegateMigrationExecutor
            {
                InspectImpl = _ => ValueTask.FromResult(MigrationObservationState.Empty),
                ExecuteImpl = async token =>
                {
                    executeEntered.TrySetResult();
                    await releaseExecute.Task.WaitAsync(token);
                }
            };

            var gate = RunGate(databasePath, executor, cts.Token);
            await executeEntered.Task.WaitAsync(TimeSpan.FromSeconds(30));
            cts.Cancel();
            releaseExecute.TrySetResult();

            var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => gate);
            Assert.Equal(cts.Token, exception.CancellationToken);
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Gate_CancelledDuringFinalReinspection_ThrowsOriginalToken()
    {
        var databasePath = NewDatabasePath();
        try
        {
            using var cts = new CancellationTokenSource();
            var executed = false;
            var finalInspectionEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var releaseFinalInspection = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var executor = new DelegateMigrationExecutor
            {
                InspectImpl = async token =>
                {
                    if (!executed)
                    {
                        return MigrationObservationState.Empty;
                    }

                    finalInspectionEntered.TrySetResult();
                    await releaseFinalInspection.Task.WaitAsync(token);
                    return MigrationObservationState.CurrentVersionCompatible;
                },
                ExecuteImpl = _ =>
                {
                    executed = true;
                    return ValueTask.CompletedTask;
                }
            };

            var gate = RunGate(databasePath, executor, cts.Token);
            await finalInspectionEntered.Task.WaitAsync(TimeSpan.FromSeconds(30));
            cts.Cancel();
            releaseFinalInspection.TrySetResult();

            var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => gate);
            Assert.Equal(cts.Token, exception.CancellationToken);
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Gate_CancelledAfterStagesSettled_ThrowsOriginalTokenInsteadOfSucceeding()
    {
        var databasePath = NewDatabasePath();
        try
        {
            using var cts = new CancellationTokenSource();
            var executed = false;
            var executor = new DelegateMigrationExecutor
            {
                InspectImpl = _ =>
                {
                    if (executed)
                    {
                        // Cancel as the final stage completes, inside the checkpoint window between
                        // stage settlement and result delivery.
                        cts.Cancel();
                        return ValueTask.FromResult(MigrationObservationState.CurrentVersionCompatible);
                    }

                    return ValueTask.FromResult(MigrationObservationState.Empty);
                },
                ExecuteImpl = _ =>
                {
                    executed = true;
                    return ValueTask.CompletedTask;
                }
            };

            var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => RunGate(databasePath, executor, cts.Token));
            Assert.Equal(cts.Token, exception.CancellationToken);
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    // ----- Full bootstrap phase: real executor -----

    [Fact]
    public async Task Bootstrap_FreshDatabase_RunsMigrationThenCreatesPendingSetupWithHash()
    {
        var databasePath = NewDatabasePath();
        try
        {
            var bootstrap = NewBootstrap(TestDatabaseOptions(databasePath));
            var result = await InstallationStartup.RunAsync(
                bootstrap, EmptyConfiguration(), StubEnvironment(), NullLoggerFactory.Instance);

            Assert.Equal(InstallationPhase.PendingSetup, result.Phase);
            Assert.NotNull(result.PlaintextSetupCode);
            Assert.Null(result.SharedSnapshot);
            Assert.Null(result.ConfigurationEntries);

            // The legacy installation_state and system_settings tables are dropped by the forward
            // chain; the pending installation and its hashed setup code live in
            // service_installations.
            Assert.False(TableExists(databasePath, "installation_state"));
            Assert.False(TableExists(databasePath, "system_settings"));
            Assert.True(TableExists(databasePath, "service_installations"));
            Assert.Equal(1, Scalar(databasePath, "SELECT COUNT(*) FROM service_installations"));
            var storedDigest = await StoredSetupCodeDigestAsync(databasePath);
            Assert.NotNull(storedDigest);
            Assert.True(
                ServiceMantle.Installation.SetupCode.TryParse(result.PlaintextSetupCode, out var setupCode) &&
                setupCode is not null &&
                SetupCodeDigest.Compute(setupCode).Value == storedDigest,
                "The stored service_installations digest must be the ServiceMantle digest of the issued plaintext.");
            var storedStatus = Convert.ToInt32(await StoredColumnAsync(databasePath, "service_installations", "status"));
            Assert.Equal((int)ServiceMantle.Installation.InstallationStatus.PendingSetup, storedStatus);
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Bootstrap_CurrentHistoryWithCompletedInstallation_SkipsExecuteAndLoadsSnapshot()
    {
        var databaseDirectory = Path.Combine(PhysicalTempPath(), $"signacore-gate-completed-{Guid.NewGuid():N}");
        Directory.CreateDirectory(databaseDirectory);
        var databasePath = Path.Combine(databaseDirectory, "identity.db");
        try
        {
            var options = TestDatabaseOptions(databasePath);
            var bootstrapFilePath = await InstallationTestSupport.PrepareCompletedInstallationAsync(
                databaseDirectory,
                options,
                rootSecret: "root-secret-for-tests-only",
                adminUsername: "administrator",
                adminPassword: "not-a-real-password-#42!");

            // Running the phase again on the already-current database must skip the executor and
            // still resolve the installation state and load the snapshot.
            var bootstrap = SignaCoreBootstrapStore.Load(
                new ConfigurationBuilder()
                    .AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        [SignaCoreBootstrapStore.FilePathConfigurationKey] = bootstrapFilePath
                    })
                    .Build(),
                StubEnvironment());
            Assert.Equal(options.ConnectionString, bootstrap.Database.ConnectionString);

            var result = await InstallationStartup.RunAsync(
                bootstrap, EmptyConfiguration(), StubEnvironment(), NullLoggerFactory.Instance);

            Assert.Equal(InstallationPhase.Completed, result.Phase);
            Assert.Null(result.PlaintextSetupCode);
            Assert.NotNull(result.SharedSnapshot);
            Assert.Equal(
                "administrator",
                result.SharedSnapshot!.Values["admin.username"].GetString());
            Assert.NotNull(result.ConfigurationEntries);
            Assert.Equal(
                "administrator",
                result.ConfigurationEntries![SystemSettingKeys.AdminUsername]);

            // The test installation wrote the shared aggregate directly through the shared update
            // path (no legacy rows ever existed), and the snapshot was activated from it.
            var verificationBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            verificationBuilder.UseIdentityDatabase(options);
            using (var verification = new IdentityDbContext(verificationBuilder.Options))
            {
                var aggregate = await SharedSettingAggregate.ReadVersionAsync(
                    verification, TestContext.Current.CancellationToken);
                Assert.Equal(1, aggregate);
            }

            // The bootstrap phase activated the snapshot on the process-shared accessor instance.
            Assert.True(result.CurrentSnapshotAccessor.TryGetCurrent(out var activated));
            Assert.Equal(1, activated!.Version);
        }
        finally
        {
            Cleanup(databasePath);
            Directory.Delete(databaseDirectory, recursive: true);
        }
    }

    [Fact]
    public async Task Bootstrap_PrefixHistoryWithBusinessData_RunsLegacyImport()
    {
        var databasePath = NewDatabasePath();
        try
        {
            var options = TestDatabaseOptions(databasePath);
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(options);
            await using (var db = new IdentityDbContext(optionsBuilder.Options))
            {
                var migrator = db.Database.GetService<IMigrator>();
                await migrator.MigrateAsync(PreServiceInstallations, TestContext.Current.CancellationToken);
                db.Accounts.Add(new AccountEntity
                {
                    Id = Guid.NewGuid(),
                    IsActive = true,
                    CreatedAt = DateTimeOffset.UtcNow
                });
                await db.SaveChangesAsync(TestContext.Current.CancellationToken);
            }

            // Missing legacy configuration still fails closed after the migration gate passed.
            await Assert.ThrowsAsync<SettingsSnapshotException>(() => InstallationStartup.RunAsync(
                NewBootstrap(options), EmptyConfiguration(), StubEnvironment(), NullLoggerFactory.Instance));

            var configuration = new ConfigurationBuilder().AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    [SystemSettingKeys.PublicBaseUrl] = "http://localhost",
                    [SystemSettingKeys.JwtIssuer] = "http://localhost",
                    [SystemSettingKeys.AdminUsername] = "administrator"
                }).Build();
            var result = await InstallationStartup.RunAsync(
                NewBootstrap(options), configuration, StubEnvironment(), NullLoggerFactory.Instance);

            Assert.Equal(InstallationPhase.Completed, result.Phase);
            Assert.Null(result.PlaintextSetupCode);
            Assert.NotNull(result.SharedSnapshot);
            Assert.Equal(
                "http://localhost",
                result.SharedSnapshot!.Values["endpoints.public_base_url"].GetString());

            // The business data made the backfill adopt a completed service_installations row; the
            // protected import wrote the deployment configuration into the shared aggregate, which
            // the activated snapshot was loaded from. Both legacy tables — installation_state and
            // the empty system_settings — are gone after the guarded drop.
            var importVerificationBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            importVerificationBuilder.UseIdentityDatabase(options);
            using (var verification = new IdentityDbContext(importVerificationBuilder.Options))
            {
                Assert.Equal(1, await SharedSettingAggregate.ReadVersionAsync(
                    verification, TestContext.Current.CancellationToken));
            }

            Assert.False(TableExists(databasePath, "installation_state"));
            Assert.Equal(
                (int)ServiceMantle.Installation.InstallationStatus.Completed,
                Convert.ToInt32(
                    await StoredColumnAsync(databasePath, "service_installations", "status")));
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Bootstrap_PendingInstallationWithoutIssuedCode_IssuesCodeOnNextBoot()
    {
        var databasePath = NewDatabasePath();
        try
        {
            var options = TestDatabaseOptions(databasePath);

            // First boot creates the pending installation and issues its code.
            var first = await InstallationStartup.RunAsync(
                NewBootstrap(options), EmptyConfiguration(), StubEnvironment(), NullLoggerFactory.Instance);
            Assert.Equal(InstallationPhase.PendingSetup, first.Phase);
            Assert.NotNull(first.PlaintextSetupCode);

            // Simulate the recovery window between creating the pending row and saving its first
            // code: the row survives with no issued material.
            ExecuteSql(
                databasePath,
                "UPDATE service_installations SET setup_code_generation = 0, setup_code_digest = NULL, setup_code_issued_at_utc = NULL, setup_code_expires_at_utc = NULL");

            var second = await InstallationStartup.RunAsync(
                NewBootstrap(options), EmptyConfiguration(), StubEnvironment(), NullLoggerFactory.Instance);
            Assert.Equal(InstallationPhase.PendingSetup, second.Phase);
            Assert.NotNull(second.PlaintextSetupCode);
            Assert.NotEqual(first.PlaintextSetupCode, second.PlaintextSetupCode);

            var storedDigest = await StoredSetupCodeDigestAsync(databasePath);
            Assert.True(
                ServiceMantle.Installation.SetupCode.TryParse(second.PlaintextSetupCode, out var setupCode) &&
                setupCode is not null &&
                SetupCodeDigest.Compute(setupCode).Value == storedDigest);
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    [Fact]
    public async Task Bootstrap_UnknownHistoryVersion_FailsClosedWithoutTouchingInstallState()
    {
        var databaseDirectory = Path.Combine(PhysicalTempPath(), $"signacore-gate-toonew-{Guid.NewGuid():N}");
        Directory.CreateDirectory(databaseDirectory);
        var databasePath = Path.Combine(databaseDirectory, "identity.db");
        try
        {
            var options = TestDatabaseOptions(databasePath);
            await InstallationTestSupport.PrepareCompletedInstallationAsync(
                databaseDirectory,
                options,
                rootSecret: "root-secret-for-tests-only",
                adminUsername: "administrator",
                adminPassword: "not-a-real-password-#42!");

            ExecuteSql(
                databasePath,
                "INSERT INTO __EFMigrationsHistory (MigrationId, ProductVersion) VALUES ('99990101000000_NotInThisBuild', '10.0.12')");

            var storedDigestBeforeFailure = await StoredSetupCodeDigestAsync(databasePath);
            Assert.Null(storedDigestBeforeFailure);

            var exception = await Assert.ThrowsAsync<StartupMigrationException>(() => InstallationStartup.RunAsync(
                NewBootstrap(options), EmptyConfiguration(), StubEnvironment(), NullLoggerFactory.Instance));
            Assert.Equal(WellKnownMigrationErrorCodes.VersionTooNew, exception.ErrorCode);

            // A completed installation is not rolled back and no new setup code is issued.
            Assert.Equal(
                (int)ServiceMantle.Installation.InstallationStatus.Completed,
                Convert.ToInt32(
                    await StoredColumnAsync(databasePath, "service_installations", "status")));
            Assert.Equal(
                storedDigestBeforeFailure,
                await StoredSetupCodeDigestAsync(databasePath));
        }
        finally
        {
            Cleanup(databasePath);
            Directory.Delete(databaseDirectory, recursive: true);
        }
    }

    [Fact]
    public async Task Bootstrap_ExecuteFailure_DoesNotRunResolverOrEmitSetupCode_AndSafeRetryRecovers()
    {
        var databasePath = NewDatabasePath();
        try
        {
            var options = TestDatabaseOptions(databasePath);
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(options);
            await using (var db = new IdentityDbContext(optionsBuilder.Options))
            {
                var migrator = db.Database.GetService<IMigrator>();
                await migrator.MigrateAsync(PreServiceInstallations, TestContext.Current.CancellationToken);
            }

            // Sabotage the next migration: its target table already exists, so execution fails
            // without touching the history or the installation state.
            ExecuteSql(
                databasePath,
                """
                CREATE TABLE service_installations (
                    service_id TEXT PRIMARY KEY,
                    status INTEGER NOT NULL,
                    version INTEGER NOT NULL
                )
                """);

            var exception = await Assert.ThrowsAsync<StartupMigrationException>(() => InstallationStartup.RunAsync(
                NewBootstrap(options), EmptyConfiguration(), StubEnvironment(), NullLoggerFactory.Instance));
            Assert.Equal(WellKnownMigrationErrorCodes.ExecutionFailed, exception.ErrorCode);

            // The failure never reached installation resolution: no service_installations row or
            // setup code was generated anywhere.
            Assert.True(TableExists(databasePath, "service_installations"));
            Assert.Equal(0, Scalar(databasePath, "SELECT COUNT(*) FROM service_installations"));

            // A safe retry after the operator removes the conflicting object resumes the existing
            // migration behavior; no history, installation row, or database deletion is involved.
            ExecuteSql(databasePath, "DROP TABLE service_installations");
            var result = await InstallationStartup.RunAsync(
                NewBootstrap(options), EmptyConfiguration(), StubEnvironment(), NullLoggerFactory.Instance);
            Assert.Equal(InstallationPhase.PendingSetup, result.Phase);
            Assert.NotNull(result.PlaintextSetupCode);
            Assert.Equal(
                1,
                Scalar(databasePath, "SELECT COUNT(*) FROM service_installations"));
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    // ----- Full bootstrap phase: cancellation through the injected gate seam -----

    [Fact]
    public async Task Bootstrap_CancelledDuringMigrationStage_OriginalTokenWinsAndResolverNeverRuns()
    {
        foreach (var stage in new[] { Stage.Inspect, Stage.Execute, Stage.FinalInspection })
        {
            var databasePath = NewDatabasePath();
            try
            {
                using var cts = new CancellationTokenSource();
                var (executor, entered) = CancellingExecutor(stage, cts);
                var gate = InstallationStartup.RunAsync(
                    NewBootstrap(TestDatabaseOptions(databasePath)),
                    EmptyConfiguration(),
                    StubEnvironment(),
                    NullLoggerFactory.Instance,
                    executor,
                    cts.Token);

                await entered.Task.WaitAsync(TimeSpan.FromSeconds(30));
                cts.Cancel();
                var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => gate);
                Assert.Equal(cts.Token, exception.CancellationToken);

                // Installation resolution never started: no state row exists anywhere.
                Assert.False(TableExists(databasePath, "service_installations"));
            }
            finally
            {
                Cleanup(databasePath);
            }
        }
    }

    [Fact]
    public async Task Bootstrap_CancelledAfterMigrationSettled_OriginalTokenWinsAndResolverNeverRuns()
    {
        var databasePath = NewDatabasePath();
        try
        {
            using var cts = new CancellationTokenSource();
            var executed = false;
            var executor = new DelegateMigrationExecutor
            {
                InspectImpl = _ =>
                {
                    if (executed)
                    {
                        cts.Cancel();
                        return ValueTask.FromResult(MigrationObservationState.CurrentVersionCompatible);
                    }

                    return ValueTask.FromResult(MigrationObservationState.Empty);
                },
                ExecuteImpl = _ =>
                {
                    executed = true;
                    return ValueTask.CompletedTask;
                }
            };

            var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                InstallationStartup.RunAsync(
                    NewBootstrap(TestDatabaseOptions(databasePath)),
                    EmptyConfiguration(),
                    StubEnvironment(),
                    NullLoggerFactory.Instance,
                    executor,
                    cts.Token));
            Assert.Equal(cts.Token, exception.CancellationToken);
            Assert.False(TableExists(databasePath, "service_installations"));
        }
        finally
        {
            Cleanup(databasePath);
        }
    }

    // ----- Helpers -----

    private static Task RunGate(
        string databasePath,
        IDatabaseMigrationExecutor executor,
        CancellationToken cancellationToken = default,
        string? extra = null)
    {
        var options = TestDatabaseOptions(databasePath, extra);
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(options);
        var db = new IdentityDbContext(optionsBuilder.Options);
        return StartupMigrationGate.RunAsync(db, options, NullLogger.Instance, executor, cancellationToken);
    }

    private static BootstrapConfiguration NewBootstrap(DatabaseOptions options) => new(
        ServiceId.Parse("signacore"),
        new BootstrapDatabaseConfiguration(options.Provider, options.ServerVersion, options.ConnectionString),
        "root-secret-for-tests-only");

    private static IConfiguration EmptyConfiguration() =>
        new ConfigurationBuilder().AddInMemoryCollection().Build();

    private static IHostEnvironment StubEnvironment() => new TestHostEnvironment();

    private static async Task<object?> StoredColumnAsync(string databasePath, string table, string column)
    {
        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={databasePath}");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {column} FROM {table} LIMIT 1";
        var value = await command.ExecuteScalarAsync(TestContext.Current.CancellationToken);
        return value is DBNull ? null : value;
    }

    private static async Task<string?> StoredSetupCodeDigestAsync(string databasePath) =>
        (string?)await StoredColumnAsync(databasePath, "service_installations", "setup_code_digest");

    private static (DelegateMigrationExecutor Executor, TaskCompletionSource Entered) CancellingExecutor(
        Stage stage,
        CancellationTokenSource cts)
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executed = false;
        return (new DelegateMigrationExecutor
        {
            InspectImpl = async token =>
            {
                if (!executed)
                {
                    if (stage == Stage.Inspect)
                    {
                        entered.TrySetResult();
                        await Task.Delay(Timeout.InfiniteTimeSpan, token);
                    }

                    return MigrationObservationState.Empty;
                }

                if (stage == Stage.FinalInspection)
                {
                    entered.TrySetResult();
                    await Task.Delay(Timeout.InfiniteTimeSpan, token);
                }

                return MigrationObservationState.CurrentVersionCompatible;
            },
            ExecuteImpl = async token =>
            {
                executed = true;
                if (stage == Stage.Execute)
                {
                    entered.TrySetResult();
                    await Task.Delay(Timeout.InfiniteTimeSpan, token);
                }
            }
        }, entered);
    }

    private enum Stage
    {
        Inspect,
        Execute,
        FinalInspection
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "SignaCore.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } =
            new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
}

/// <summary>A recording executor whose stage behavior is supplied by the test.</summary>
internal sealed class DelegateMigrationExecutor : IDatabaseMigrationExecutor
{
    public Func<CancellationToken, ValueTask<MigrationObservationState>>? InspectImpl { get; set; }

    public Func<CancellationToken, ValueTask>? ExecuteImpl { get; set; }

    public int InspectCount { get; private set; }

    public int ExecuteCount { get; private set; }

    public async ValueTask<MigrationObservationState> InspectAsync(CancellationToken cancellationToken = default)
    {
        InspectCount++;
        if (InspectImpl is null)
        {
            return MigrationObservationState.CurrentVersionCompatible;
        }

        return await InspectImpl(cancellationToken);
    }

    public async ValueTask ExecuteAsync(CancellationToken cancellationToken = default)
    {
        ExecuteCount++;
        if (ExecuteImpl is not null)
        {
            await ExecuteImpl(cancellationToken);
        }
    }
}
