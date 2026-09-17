using Microsoft.EntityFrameworkCore;
using ServiceMantle.Bootstrap;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host.Bootstrap;
using Xunit;

namespace SignaCore.Tests.Host.Bootstrap;

/// <summary>
/// The fixed step order of the SignaCore candidate validator: the first failed rule decides the
/// error code, a missing target is prepared explicitly once, and only an internal failure reports
/// the shared 503 classification.
/// </summary>
public sealed class SignaCoreBootstrapCandidateValidatorTests : IAsyncLifetime
{
    private string _directory = string.Empty;

    public ValueTask InitializeAsync()
    {
        _directory = Path.Combine(CreateTemporaryRoot(), $"signacore-validator-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_directory);
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// The shared SQLite target rules reject a path whose ancestors are symbolic links, and the
    /// macOS temporary root is one (/var → /private/var), so tests resolve it first.
    /// </summary>
    private static string CreateTemporaryRoot()
    {
        var root = Path.GetTempPath();
        if (OperatingSystem.IsMacOS() && root.StartsWith("/var/", StringComparison.Ordinal))
        {
            root = "/private" + root;
        }

        return root;
    }

    public ValueTask DisposeAsync()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }

        return ValueTask.CompletedTask;
    }

    private static SignaCoreBootstrapCandidateValidator CreateValidator(string? currentMasterKey = null) =>
        new(SignaCoreBootstrapStore.CreateProviderRegistry(), currentMasterKey);

    private static BootstrapConfiguration Candidate(
        string provider = "SQLite",
        string? serverVersion = null,
        string connectionString = "Data Source=valid.db",
        string masterKey = "candidate-key") =>
        new(
            SignaCore.Host.Installation.InstallationStores.ServiceId,
            new BootstrapDatabaseConfiguration(provider, serverVersion, connectionString),
            masterKey);

    [Fact]
    public async Task UnknownProvider_FailsTheSharedChecksFirst()
    {
        var result = await CreateValidator().ValidateAsync(
            Candidate(provider: "MongoDb", connectionString: "Host=x"),
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Equal("database.provider_not_registered", result.ErrorCode);
    }

    [Fact]
    public void LocalShapeThatCannotBeReloaded_ReportsTheLocalCode()
    {
        // The shared rules are a superset for most shapes now, but this process additionally
        // requires what its own reload path requires, so the net stays independent of the shared
        // providers' drift: a PostgreSQL target without a host parses and names a database yet
        // could never be loaded here after the restart.
        var local = SignaCoreBootstrapCandidateValidator.ValidateLocalShape(new DatabaseOptions
        {
            Provider = "PostgreSQL",
            ServerVersion = "15",
            ConnectionString = "Database=x"
        });

        Assert.NotNull(local);
        Assert.False(local!.IsValid);
        Assert.Equal("signacore.bootstrap.database_invalid", local.ErrorCode);

        Assert.Null(SignaCoreBootstrapCandidateValidator.ValidateLocalShape(new DatabaseOptions
        {
            Provider = "PostgreSQL",
            ServerVersion = "15",
            ConnectionString = "Host=db;Database=x"
        }));
    }

    [Fact]
    public async Task MissingParentDirectory_FailsTheSharedTargetRules()
    {
        var result = await CreateValidator().ValidateAsync(
            Candidate(connectionString: $"Data Source={Path.Combine(_directory, "missing-parent", "identity.db")}"),
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Equal("database.connection_string_invalid", result.ErrorCode);
        Assert.False(Directory.Exists(Path.Combine(_directory, "missing-parent")));
    }

    [Fact]
    public async Task MissingFileTarget_IsPreparedExplicitlyAndThenAccepted()
    {
        var databasePath = Path.Combine(_directory, "fresh.db");
        var result = await CreateValidator().ValidateAsync(
            Candidate(connectionString: $"Data Source={databasePath}"),
            TestContext.Current.CancellationToken);

        Assert.True(result.IsValid);
        // The explicit preparation created exactly the empty target the next start will migrate.
        Assert.True(File.Exists(databasePath));
    }

    [Fact]
    public async Task PreparedTargetStillRejectableLocally_FailsWithoutABootstrapFile()
    {
        // A relative in-memory target cannot be prepared and is refused; no bootstrap file exists.
        var result = await CreateValidator().ValidateAsync(
            Candidate(connectionString: "Data Source=:memory:"),
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.False(File.Exists(Path.Combine(_directory, "signacore.bootstrap.json")));
    }

    [Fact]
    public async Task UnreachableTarget_ReportsTheLocalUnreachableCode()
    {
        var inspection = new BootstrapTargetInspection(
            BootstrapTargetKind.Unreachable,
            MasterKeyCompatibility.NoProtectedData,
            InstallationId: null,
            Endpoint: "redacted",
            FailureReason: "probe");
        var validator = new SignaCoreBootstrapCandidateValidator(
            SignaCoreBootstrapStore.CreateProviderRegistry(),
            currentMasterKey: null,
            inspection: (_, _, _) => Task.FromResult(inspection));

        var result = await validator.ValidateAsync(
            Candidate(connectionString: $"Data Source={Path.Combine(_directory, "existing.db")}"),
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Equal("signacore.bootstrap.target_unreachable", result.ErrorCode);
    }

    [Fact]
    public async Task ProtectedTargetWithWrongKey_IsMasterKeyMismatch()
    {
        var protectedPath = await CreateProtectedTargetAsync();
        var result = await CreateValidator().ValidateAsync(
            Candidate(connectionString: $"Data Source={protectedPath}", masterKey: "a-wrong-candidate-key"),
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Equal("signacore.bootstrap.master_key_mismatch", result.ErrorCode);
    }

    [Fact]
    public async Task RunningHostRefusesToSwapItsKeyForOneTheTargetCannotRead()
    {
        // NoProtectedData, but the candidate key differs from the running key and the target
        // cannot prove it readable: the replacement is refused.
        var result = await CreateValidator(currentMasterKey: "the-running-key").ValidateAsync(
            Candidate(
                connectionString: $"Data Source={Path.Combine(_directory, "fresh.db")}",
                masterKey: "a-different-key"),
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Equal("signacore.bootstrap.master_key_replacement_refused", result.ErrorCode);
    }

    [Fact]
    public async Task RunningHostKeepsItsOwnKey()
    {
        var result = await CreateValidator(currentMasterKey: "the-running-key").ValidateAsync(
            Candidate(
                connectionString: $"Data Source={Path.Combine(_directory, "fresh.db")}",
                masterKey: "the-running-key"),
            TestContext.Current.CancellationToken);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task ModeHostHasNoCurrentKey_SoTheReplacementStepIsInert()
    {
        var result = await CreateValidator(currentMasterKey: null).ValidateAsync(
            Candidate(
                connectionString: $"Data Source={Path.Combine(_directory, "fresh.db")}",
                masterKey: "any-key"),
            TestContext.Current.CancellationToken);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task CallerCancellation_Propagates()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await cancelled.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(() => CreateValidator().ValidateAsync(
            Candidate(connectionString: $"Data Source={Path.Combine(_directory, "fresh.db")}",
                masterKey: "candidate-key"),
            cancelled.Token).AsTask());
    }

    [Fact]
    public async Task InternalInspectionFailure_IsTheSharedValidationFailedCode()
    {
        var validator = new SignaCoreBootstrapCandidateValidator(
            SignaCoreBootstrapStore.CreateProviderRegistry(),
            currentMasterKey: null,
            inspection: (_, _, _) => throw new IOException("simulated internal failure"));

        var result = await validator.ValidateAsync(
            Candidate(connectionString: $"Data Source={Path.Combine(_directory, "existing.db")}"),
            TestContext.Current.CancellationToken);

        Assert.False(result.IsValid);
        Assert.Equal("candidate.validation_failed", result.ErrorCode);
    }

    private async Task<string> CreateProtectedTargetAsync()
    {
        var databasePath = Path.Combine(_directory, $"protected-{Guid.NewGuid():N}.db");
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = $"Data Source={databasePath}"
        });
        await using var context = new IdentityDbContext(optionsBuilder.Options);
        await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
        context.SystemSettings.Add(new SystemSettingEntity
        {
            Key = "smtp.password",
            Value = "definitely-not-a-readable-envelope",
            ValueType = "string",
            IsSecret = true,
            Version = 1,
            UpdatedAt = DateTimeOffset.UtcNow,
            UpdatedBy = "seed"
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        await context.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        foreach (var sidecar in new[] { "-journal", "-wal", "-shm" })
        {
            var path = databasePath + sidecar;
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }

        return databasePath;
    }
}
