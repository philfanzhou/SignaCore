using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using ServiceMantle;
using ServiceMantle.Bootstrap;
using SignaCore.Database;
using SignaCore.Host.Startup;
using Xunit;
using static SignaCore.Tests.Host.Migration.SqliteMigrationGateTestSupport;

namespace SignaCore.Tests.Host.Startup;

/// <summary>
/// Startup SQLite target preparation through the shared provider under the narrowed compatibility
/// contract: the parent-directory pre-step keeps the fresh-directory first-install experience, only
/// a proven-missing target is created (then confirmed connectable), existing dirty targets pass
/// through to EF's native open, non-absolute or aliased paths fail closed with the absolute-path
/// guidance, and every other closed classification fails startup without touching the target.
/// </summary>
public sealed class StartupSqliteTargetPreparationTests
{
    private static string NewTargetPath() =>
        Path.Combine(
            PhysicalTempPath(),
            $"signacore-startup-target-{Guid.NewGuid():N}",
            "data",
            "signacore.db");

    private static DatabaseOptions Options(string connectionString) => new()
    {
        Provider = "SQLite",
        ConnectionString = connectionString
    };

    private static DatabaseOptions FileOptions(string path) => Options($"Data Source={path}");

    private static void Cleanup(string path)
    {
        SqliteConnection.ClearAllPools();
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory) && directory.StartsWith(PhysicalTempPath(), StringComparison.Ordinal))
        {
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (DirectoryNotFoundException)
            {
            }
            catch (IOException)
            {
            }
        }
    }

    private static void CreateValidDatabaseFile(string path)
    {
        using var connection = new SqliteConnection($"Data Source={path}");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA user_version = 0";
        command.ExecuteNonQuery();
    }

    // ----- Fresh install through the pre-step and the shared provider -----

    [Fact]
    public async Task MissingTargetWithMissingParents_PreStepCreatesDirectoryAndProviderCreatesFile()
    {
        var path = NewTargetPath();
        try
        {
            await StartupDatabase.EnsureDatabaseExistsAsync(
                FileOptions(path), TestContext.Current.CancellationToken);

            // The pre-step created the whole missing parent chain, and the shared provider created
            // the database file itself.
            Assert.True(Directory.Exists(Path.GetDirectoryName(path)));
            Assert.True(File.Exists(path));

            // The created target is an ordinary SQLite file a plain open (including an older
            // binary) can read.
            using var connection = new SqliteConnection($"Data Source={path}");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT count(*) FROM sqlite_schema";
            Assert.Equal(0L, Convert.ToInt64(command.ExecuteScalar()));
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public async Task FreshStartupRunOnMissingTarget_ReachesSetupMode()
    {
        var path = NewTargetPath();
        try
        {
            var result = await InstallationStartup.RunAsync(
                NewBootstrap(FileOptions(path)),
                new ConfigurationBuilder().Build(),
                StubEnvironment(),
                NullLoggerFactory.Instance);

            Assert.Equal(SignaCore.Host.Installation.InstallationPhase.PendingSetup, result.Phase);
            Assert.NotNull(result.PlaintextSetupCode);
            Assert.True(File.Exists(path));
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public async Task TwoConcurrentPreparationsOfTheSameMissingTarget_ConvergeOnOneFile()
    {
        var path = NewTargetPath();
        try
        {
            // SQLite stays single-instance: the migration orchestration serializes the startup
            // phases, and preparation itself converges through the shared provider's publish race
            // handling just like the outer lock does for two processes.
            await Task.WhenAll(
                StartupDatabase.EnsureDatabaseExistsAsync(
                    FileOptions(path), TestContext.Current.CancellationToken),
                StartupDatabase.EnsureDatabaseExistsAsync(
                    FileOptions(path), TestContext.Current.CancellationToken));

            Assert.True(File.Exists(path));
            using var connection = new SqliteConnection($"Data Source={path}");
            connection.Open();
        }
        finally
        {
            Cleanup(path);
        }
    }

    // ----- Existing targets -----

    [Fact]
    public async Task ExistingConnectableTarget_ReturnsUnchanged()
    {
        var path = NewTargetPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        CreateValidDatabaseFile(path);
        try
        {
            var before = File.GetLastWriteTimeUtc(path);
            await StartupDatabase.EnsureDatabaseExistsAsync(
                FileOptions(path), TestContext.Current.CancellationToken);
            Assert.Equal(before, File.GetLastWriteTimeUtc(path));
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Theory]
    [InlineData("-wal")]
    [InlineData("-shm")]
    [InlineData("-journal")]
    public async Task ExistingDirtyTargetWithSidecar_PassesThroughToEfNativeOpen(string sidecarSuffix)
    {
        var path = NewTargetPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        CreateValidDatabaseFile(path);
        File.WriteAllText(path + sidecarSuffix, "sidecar content");
        try
        {
            // A dirty target is not a startup precondition failure: EF's native open stays the
            // final judge, exactly as it was before the shared-provider switch.
            await StartupDatabase.EnsureDatabaseExistsAsync(
                FileOptions(path), TestContext.Current.CancellationToken);

            Assert.True(File.Exists(path));
            Assert.True(File.Exists(path + sidecarSuffix));
        }
        finally
        {
            Cleanup(path);
        }
    }

    // ----- Narrowed path contract -----

    public static TheoryData<string> RejectedConnectionStrings => new()
    {
        "Data Source=relative-target.db",
        "Data Source=nested/relative-target.db",
        "Data Source=|DataDirectory|signacore.db",
        "Data Source=file:signacore.db",
        $"Data Source={Path.Combine(PhysicalTempPath(), "signacore-dotdot", "..", "rejected.db")}",
    };

    [Theory]
    [MemberData(nameof(RejectedConnectionStrings))]
    public async Task NonAbsoluteOrAliasedTarget_FailsClosedPointingAtAbsolutePaths(string connectionString)
    {
        var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
            StartupDatabase.EnsureDatabaseExistsAsync(
                Options(connectionString), TestContext.Current.CancellationToken));

        Assert.Equal(
            WellKnownDatabaseTargetPreparationErrorCodes.InvalidTarget,
            exception.ErrorCode);
        Assert.Contains("absolute", exception.Message, StringComparison.Ordinal);
        Assert.Null(exception.InnerException);

        // Nothing was created anywhere near the working directory for a rejected input.
        Assert.False(File.Exists(Path.Combine(Directory.GetCurrentDirectory(), "relative-target.db")));
        Assert.False(File.Exists(Path.Combine(Directory.GetCurrentDirectory(), "nested")));
        Assert.False(Directory.Exists(Path.Combine(PhysicalTempPath(), "signacore-dotdot")));
    }

    [Fact]
    public async Task SymlinkedTarget_FailsClosedAsInvalidTarget()
    {
        var realPath = NewTargetPath();
        var linkPath = Path.Combine(
            Path.GetDirectoryName(realPath)!,
            "linked-" + Path.GetFileName(realPath));
        Directory.CreateDirectory(Path.GetDirectoryName(realPath)!);
        CreateValidDatabaseFile(realPath);
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                File.CreateSymbolicLink(linkPath, realPath);
            }
            else
            {
                // Symlinks need privileges on Windows; the alias family is already covered by the
                // non-absolute theory above there.
                return;
            }

            var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
                StartupDatabase.EnsureDatabaseExistsAsync(
                    FileOptions(linkPath), TestContext.Current.CancellationToken));

            Assert.Equal(
                WellKnownDatabaseTargetPreparationErrorCodes.InvalidTarget,
                exception.ErrorCode);
            Assert.Contains("absolute", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            Cleanup(realPath);
        }
    }

    [Fact]
    public async Task StartupRunWithHandEditedRelativePath_FailsClosedWithoutCreatingAnything()
    {
        // A hand-edited bootstrap file can still carry a relative path past the file-level checks;
        // the narrowed startup contract refuses it with the migration guidance instead of silently
        // resolving it against the working directory.
        var cwdBefore = Directory.GetCurrentDirectory();
        var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
            InstallationStartup.RunAsync(
                NewBootstrap(Options("Data Source=hand-edited-relative.db")),
                new ConfigurationBuilder().Build(),
                StubEnvironment(),
                NullLoggerFactory.Instance));

        Assert.Equal(
            WellKnownDatabaseTargetPreparationErrorCodes.InvalidTarget,
            exception.ErrorCode);
        Assert.Contains("absolute", exception.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(cwdBefore, "hand-edited-relative.db")));
    }

    // ----- Parent-directory pre-step failure -----

    [Fact]
    public async Task ParentDirectoryCreationFailure_FailsClosedBeforeAnyObservation()
    {
        var path = NewTargetPath();
        var provider = new RecordingPreparationProvider();
        try
        {
            var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
                StartupDatabase.EnsureSqliteDatabaseExistsAsync(
                    FileOptions(path),
                    provider,
                    directory => throw new UnauthorizedAccessException("simulated denial"),
                    TestContext.Current.CancellationToken));

            Assert.Equal(
                WellKnownDatabaseTargetPreparationErrorCodes.PermissionDenied,
                exception.ErrorCode);
            Assert.DoesNotContain(Path.GetTempPath(), exception.Message, StringComparison.Ordinal);
            Assert.False(provider.Reached);
            Assert.False(File.Exists(path));
        }
        finally
        {
            Cleanup(path);
        }
    }

    // ----- Path canonicalization pre-step failure -----

    // The simulated BCL failure texts embed the configured data source exactly like the real
    // Windows full-path expansion does; the classification under test must discard them.
    public static TheoryData<Exception> CanonicalizationFailures => new()
    {
        new ArgumentException($"Illegal characters in path. : 'C:\\data:v2\\signacore.db'"),
        new NotSupportedException($"The given path's format is not supported. : 'C:\\data:v2\\signacore.db'"),
        new PathTooLongException(
            "The specified path, file name, or both are too long. : 'C:\\data:v2\\signacore.db'"),
        new IOException(
            "The filename, directory name, or volume label syntax is incorrect. : " +
            "'C:\\data:v2\\signacore.db'."),
    };

    [Theory]
    [MemberData(nameof(CanonicalizationFailures))]
    public async Task CanonicalizationFailure_FailsClosedAsInvalidTargetWithoutLeakingThePath(
        Exception canonicalizationError)
    {
        var path = NewTargetPath();
        var provider = new RecordingPreparationProvider();
        try
        {
            // A data source the OS full-path expansion refuses (proven on Windows for a
            // drive-absolute path with an extra colon) must fail through the same closed
            // classification as every other invalid target, never as the raw BCL exception.
            var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
                StartupDatabase.EnsureSqliteDatabaseExistsAsync(
                    FileOptions(path),
                    provider,
                    null,
                    TestContext.Current.CancellationToken,
                    _ => throw canonicalizationError));

            Assert.Equal(
                WellKnownDatabaseTargetPreparationErrorCodes.InvalidTarget,
                exception.ErrorCode);
            Assert.Contains("absolute", exception.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(path, exception.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(
                FileOptions(path).ConnectionString,
                exception.Message,
                StringComparison.Ordinal);
            Assert.DoesNotContain("C:\\data:v2", exception.Message, StringComparison.Ordinal);

            // Fails closed before any observation, directory materialization, or file creation.
            Assert.False(provider.Reached);
            Assert.False(Directory.Exists(Path.GetDirectoryName(path)));
            Assert.False(File.Exists(path));
        }
        finally
        {
            Cleanup(path);
        }
    }

    // ----- Scripted provider flows -----

    [Fact]
    public async Task MissingTarget_PrepareUsesFileRequestAndConfirmsConnectable()
    {
        var path = NewTargetPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var provider = new ScriptedPreparationProvider(
            [
                DatabaseTargetObservation.TargetMissing(),
                DatabaseTargetObservation.TargetConnectable()
            ],
            [DatabaseTargetPreparationResult.Success(DatabaseTargetPreparationOutcome.Created)]);

        try
        {
            await StartupDatabase.EnsureSqliteDatabaseExistsAsync(
                FileOptions(path), provider, null, TestContext.Current.CancellationToken);

            var request = Assert.Single(provider.PrepareRequests);
            Assert.Null(request.AdministrativeConnectionString);
            Assert.Equal(
                FileOptions(path).ConnectionString,
                request.Target.ConnectionString);
            Assert.Equal(TimeSpan.FromSeconds(30), Assert.Single(provider.PrepareTimeouts));
            Assert.Equal(2, provider.ObserveCount);
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public async Task MissingTarget_ConcurrentWinnerAlreadyExists_IsConfirmedLikeACreation()
    {
        var path = NewTargetPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var provider = new ScriptedPreparationProvider(
            [
                DatabaseTargetObservation.TargetMissing(),
                DatabaseTargetObservation.TargetConnectable()
            ],
            [DatabaseTargetPreparationResult.Success(DatabaseTargetPreparationOutcome.AlreadyExists)]);

        try
        {
            await StartupDatabase.EnsureSqliteDatabaseExistsAsync(
                FileOptions(path), provider, null, TestContext.Current.CancellationToken);
            Assert.Equal(2, provider.ObserveCount);
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public async Task ConflictObservation_PassesThroughWithoutPreparation()
    {
        var path = NewTargetPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var provider = new ScriptedPreparationProvider(
            [DatabaseTargetObservation.TargetUnreachable(
                WellKnownDatabaseTargetPreparationErrorCodes.TargetConflict,
                targetExists: true)]);

        try
        {
            await StartupDatabase.EnsureSqliteDatabaseExistsAsync(
                FileOptions(path), provider, null, TestContext.Current.CancellationToken);
            Assert.Empty(provider.PrepareRequests);
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Theory]
    [InlineData(WellKnownDatabaseTargetPreparationErrorCodes.PermissionDenied)]
    [InlineData(WellKnownDatabaseTargetPreparationErrorCodes.ConnectionFailed)]
    [InlineData(WellKnownDatabaseTargetPreparationErrorCodes.InvalidTarget)]
    public async Task NonConflictUnreachableObservation_FailsClosedWithoutPreparation(string errorCode)
    {
        var path = NewTargetPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var provider = new ScriptedPreparationProvider(
            [DatabaseTargetObservation.TargetUnreachable(errorCode, targetExists: true)]);

        try
        {
            var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
                StartupDatabase.EnsureSqliteDatabaseExistsAsync(
                    FileOptions(path), provider, null, TestContext.Current.CancellationToken));

            Assert.Equal(errorCode, exception.ErrorCode);
            Assert.Null(exception.InnerException);
            Assert.Empty(provider.PrepareRequests);
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public async Task PreparationFailure_FailsClosedWithoutConfirmationObservation()
    {
        var path = NewTargetPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var provider = new ScriptedPreparationProvider(
            [DatabaseTargetObservation.TargetMissing()],
            [DatabaseTargetPreparationResult.Failure(
                WellKnownDatabaseTargetPreparationErrorCodes.PermissionDenied)]);

        try
        {
            var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
                StartupDatabase.EnsureSqliteDatabaseExistsAsync(
                    FileOptions(path), provider, null, TestContext.Current.CancellationToken));

            Assert.Equal(
                WellKnownDatabaseTargetPreparationErrorCodes.PermissionDenied,
                exception.ErrorCode);
            Assert.Equal(1, provider.ObserveCount);
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public async Task PreparationSucceededButConfirmationNotConnectable_FailsClosedBeforeMigration()
    {
        var path = NewTargetPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var provider = new ScriptedPreparationProvider(
            [
                DatabaseTargetObservation.TargetMissing(),
                DatabaseTargetObservation.TargetUnreachable(
                    WellKnownDatabaseTargetPreparationErrorCodes.ConnectionFailed,
                    targetExists: null)
            ],
            [DatabaseTargetPreparationResult.Success(DatabaseTargetPreparationOutcome.Created)]);

        try
        {
            var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
                StartupDatabase.EnsureSqliteDatabaseExistsAsync(
                    FileOptions(path), provider, null, TestContext.Current.CancellationToken));

            Assert.Equal(
                WellKnownDatabaseTargetPreparationErrorCodes.ConnectionFailed,
                exception.ErrorCode);
            Assert.Equal(2, provider.ObserveCount);
            Assert.Null(exception.InnerException);
            // A created file is never deleted to manufacture a clean failure.
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public async Task ConfirmationConflict_DoesNotUseInitialDirtyTargetException()
    {
        var path = NewTargetPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var provider = new ScriptedPreparationProvider(
            [DatabaseTargetObservation.TargetMissing(),
             DatabaseTargetObservation.TargetUnreachable(
                 WellKnownDatabaseTargetPreparationErrorCodes.TargetConflict, targetExists: true)],
            [DatabaseTargetPreparationResult.Success(DatabaseTargetPreparationOutcome.Created)]);
        try
        {
            var exception = await Assert.ThrowsAsync<StartupDatabaseException>(() =>
                StartupDatabase.EnsureSqliteDatabaseExistsAsync(
                    FileOptions(path), provider, null, TestContext.Current.CancellationToken));
            Assert.Equal(WellKnownDatabaseTargetPreparationErrorCodes.TargetConflict, exception.ErrorCode);
            Assert.Equal(2, provider.ObserveCount);
            Assert.Single(provider.PrepareRequests);
            Assert.Null(exception.InnerException);
        }
        finally
        {
            Cleanup(path);
        }
    }

    // ----- Cancellation -----

    [Fact]
    public async Task CancellationDuringObservation_PropagatesAsCallerCancellation()
    {
        var path = NewTargetPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var provider = new ScriptedPreparationProvider(
            [], [], observeError: new OperationCanceledException("cancelled by the test"));

        try
        {
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                StartupDatabase.EnsureSqliteDatabaseExistsAsync(
                    FileOptions(path), provider, null, TestContext.Current.CancellationToken));
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public async Task CancellationDuringPreparation_PropagatesAsCallerCancellation()
    {
        var path = NewTargetPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var provider = new ScriptedPreparationProvider(
            [DatabaseTargetObservation.TargetMissing()],
            [],
            prepareError: new OperationCanceledException("cancelled by the test"));

        try
        {
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                StartupDatabase.EnsureSqliteDatabaseExistsAsync(
                    FileOptions(path), provider, null, TestContext.Current.CancellationToken));
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public async Task PreCancelledToken_FailsBeforeAnyObservation()
    {
        var path = NewTargetPath();
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        var provider = new ScriptedPreparationProvider(
            [DatabaseTargetObservation.TargetMissing()]);

        try
        {
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                StartupDatabase.EnsureSqliteDatabaseExistsAsync(
                    FileOptions(path), provider, null, cancellation.Token));
            Assert.Equal(0, provider.ObserveCount);
            Assert.False(File.Exists(path));
        }
        finally
        {
            Cleanup(path);
        }
    }

    private static BootstrapConfiguration NewBootstrap(DatabaseOptions database) => new(
        ServiceId.Parse("signacore"),
        new BootstrapDatabaseConfiguration(database.Provider, database.ServerVersion, database.ConnectionString),
        "root-secret-for-tests-only");

    private static IHostEnvironment StubEnvironment() => new TestHostEnvironment();

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "SignaCore.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } =
            new Microsoft.Extensions.FileProviders.NullFileProvider();
    }

    /// <summary>
    /// A preparation provider whose observation and preparation results are supplied by the test,
    /// so the startup classification steps run deterministically without a real target.
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

        public string ProviderId => "SQLite";

        public BootstrapDatabaseTargetKind TargetKind => BootstrapDatabaseTargetKind.File;

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

    /// <summary>
    /// A provider that only records that it was reached; used by the pre-step failure test, which
    /// must stop before any observation.
    /// </summary>
    private sealed class RecordingPreparationProvider : IDatabaseTargetPreparationProvider
    {
        public bool Reached { get; private set; }

        public string ProviderId => "SQLite";

        public BootstrapDatabaseTargetKind TargetKind => BootstrapDatabaseTargetKind.File;

        public ValueTask<DatabaseTargetObservation> ObserveAsync(
            BootstrapDatabaseConfiguration target,
            CancellationToken cancellationToken)
        {
            Reached = true;
            return ValueTask.FromResult(DatabaseTargetObservation.TargetConnectable());
        }

        public ValueTask<DatabaseTargetPreparationResult> PrepareAsync(
            DatabaseTargetPreparationRequest request,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            Reached = true;
            return ValueTask.FromResult(
                DatabaseTargetPreparationResult.Success(DatabaseTargetPreparationOutcome.Created));
        }
    }
}
