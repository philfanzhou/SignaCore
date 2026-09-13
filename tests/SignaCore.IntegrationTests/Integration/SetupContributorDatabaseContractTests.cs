using System.Data.Common;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host.Configuration;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Host.Installation;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// Database contract of the contributor-backed first-run setup slice: the shared orchestration
/// stages the initial administrator, the settings snapshot, and the installation audit projection
/// into one transaction whose only save and commit belong to the setup service.
/// <para>
/// The SQLite provider runs everywhere; the PostgreSQL cases join the container matrix gated by
/// <c>RUN_SIGNACORE_DATABASE_CONTRACTS=true</c>, which the CI database-contract job selects through
/// the <c>DatabaseContractTests</c> name filter.
/// </para>
/// </summary>
public sealed class SetupContributorDatabaseContractTests
{
    private const string RootKey = "setup-contract-root-key";
    private const string Username = "setup_admin";
    private const string Password = "SetupAdmin123";
    private const string PublicBaseUrl = "https://identity.example.test";
    private const string ClientIp = "192.0.2.10";
    private const string CancelledMessage =
        "First-run setup was cancelled before the installation could be completed.";

    private static readonly string PostgreSqlImage =
        Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") is { Length: > 0 } image
            ? image
            : "postgres:15-alpine";

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Completion_PersistsOneConsistentFirstRunSlice(string provider)
    {
        await using var database = await SetupDatabase.CreateAsync(provider);
        await using var context = database.CreateContext();
        var service = CreateService(context, database.Options);

        var result = await service.CompleteAsync(
            CreateRequest(database.SetupCode), ClientIp, TestContext.Current.CancellationToken);

        Assert.Equal(SetupOutcome.Completed, result.Outcome);
        await VerifyCommittedSliceAsync(database);
    }

    /// <summary>
    /// The administrator account must come from the orchestrated contributor: its hash is derived
    /// exactly once by the contributor's registration, and the contributor's read-only validation
    /// re-checks the password policy inside the transaction.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Completion_StagesTheAdministratorThroughTheContributor(string provider)
    {
        await using var database = await SetupDatabase.CreateAsync(provider);
        await using var context = database.CreateContext();
        var hasher = new RecordingHasher(CreateFastHasher());
        var policy = new RecordingPolicy(new DefaultPasswordPolicy());
        var service = CreateService(context, database.Options, hasher: hasher, policy: policy);

        var result = await service.CompleteAsync(
            CreateRequest(database.SetupCode), ClientIp, TestContext.Current.CancellationToken);

        Assert.Equal(SetupOutcome.Completed, result.Outcome);
        // One hash from the contributor's single registration; the policy answered the request-level
        // shape check and the contributor's read-only validation.
        Assert.Equal(1, hasher.HashCalls);
        Assert.Equal(2, policy.ValidateCalls);
        await VerifyCommittedSliceAsync(database);
    }

    /// <summary>
    /// If the contributor is taken out of the completion path, this contract fails: the second
    /// policy call below is the contributor's validation, and refusing there must refuse the whole
    /// completion without touching the database.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task ContributorValidation_GatesTheWholeCompletion(string provider)
    {
        await using var database = await SetupDatabase.CreateAsync(provider);
        await using var context = database.CreateContext();
        var policy = new RecordingPolicy(new DefaultPasswordPolicy(), failOnCall: 2);
        var service = CreateService(context, database.Options, policy: policy);

        var result = await service.CompleteAsync(
            CreateRequest(database.SetupCode), ClientIp, TestContext.Current.CancellationToken);

        Assert.Equal(SetupOutcome.InvalidRequest, result.Outcome);
        Assert.Equal(
            "The administrator password does not satisfy the password policy.",
            result.Error);
        Assert.Equal(2, policy.ValidateCalls);
        await VerifyNothingWasWrittenAsync(database);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task DuplicateUsername_IsRefusedAndExistingRowsAreUntouched(string provider)
    {
        await using var database = await SetupDatabase.CreateAsync(provider);
        await SeedExistingAdministratorAsync(database, Username);
        await using var context = database.CreateContext();
        var service = CreateService(context, database.Options);

        var result = await service.CompleteAsync(
            CreateRequest(database.SetupCode), ClientIp, TestContext.Current.CancellationToken);

        Assert.Equal(SetupOutcome.InvalidRequest, result.Outcome);
        Assert.Equal(
            "An account with this administrator username already exists.",
            result.Error);
        await VerifyNothingWasWrittenAsync(database, existingAccounts: 1, existingCredentials: 1);

        await using var verify = database.CreateContext();
        var credential = await verify.PasswordCredentials.SingleAsync(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("existing-test-hash", credential.PasswordHash);
    }

    public static TheoryData<string> ContributorFailureModes()
    {
        var cases = new TheoryData<string> { "hasher-throws", "hasher-cancel-internally" };
        return cases;
    }

    [Theory]
    [MemberData(nameof(ContributorFailureModes))]
    public async Task ContributorFailures_RollBackCleanlyWithASafeException(string failureMode)
    {
        await using var database = await SetupDatabase.CreateAsync("SQLite");
        await using var context = database.CreateContext();
        IPasswordHasher hasher = failureMode switch
        {
            "hasher-throws" => new ThrowingHasher(),
            "hasher-cancel-internally" => new InternallyCancelingHasher(),
            _ => throw new ArgumentOutOfRangeException(nameof(failureMode))
        };
        var service = CreateService(context, database.Options, hasher: hasher);

        var exception = await Assert.ThrowsAsync<SetupStagingException>(
            async () => await service.CompleteAsync(
                CreateRequest(database.SetupCode), ClientIp, TestContext.Current.CancellationToken));

        Assert.Null(exception.InnerException);
        Assert.Equal(SetupStagingException.FixedMessage, exception.Message);
        await VerifyNothingWasWrittenAsync(database);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task SettingsAndAuditFailures_RollBackCleanly(string provider)
    {
        await using var protectorFailure = await SetupDatabase.CreateAsync(provider);
        await using (var context = protectorFailure.CreateContext())
        {
            var service = CreateService(
                context, protectorFailure.Options, protector: new ThrowingProtector());

            var exception = await Assert.ThrowsAsync<SetupStagingException>(
                async () => await service.CompleteAsync(
                    CreateRequest(protectorFailure.SetupCode),
                    ClientIp,
                    TestContext.Current.CancellationToken));

            Assert.Null(exception.InnerException);
        }

        await VerifyNothingWasWrittenAsync(protectorFailure);

        // The shared audit model refuses a client IP that is not an address, which fails the audit
        // staging after the settings were staged: everything must still roll back.
        await using var auditFailure = await SetupDatabase.CreateAsync(provider);
        await using (var context = auditFailure.CreateContext())
        {
            var service = CreateService(context, auditFailure.Options);

            var exception = await Assert.ThrowsAsync<SetupStagingException>(
                async () => await service.CompleteAsync(
                    CreateRequest(auditFailure.SetupCode),
                    "not-an-ip",
                    TestContext.Current.CancellationToken));

            Assert.Null(exception.InnerException);
        }

        await VerifyNothingWasWrittenAsync(auditFailure);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task SaveFailure_RollsBackCleanly(string provider)
    {
        await using var database = await SetupDatabase.CreateAsync(provider);
        await using var context = database.CreateServicedContext(new FailingSaveInterceptor());
        var service = CreateService(context, database.Options);

        var exception = await Assert.ThrowsAsync<SetupStagingException>(
            async () => await service.CompleteAsync(
                CreateRequest(database.SetupCode), ClientIp, TestContext.Current.CancellationToken));

        Assert.Null(exception.InnerException);
        await VerifyNothingWasWrittenAsync(database);
    }

    /// <summary>
    /// The final consumption re-check refuses an installation whose version cannot be incremented
    /// (seeded to the boundary) even though the read-only validation passed: every artifact staged
    /// before the re-check is discarded and nothing is committed.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task FinalConsumeRecheckFailure_DiscardsAllStagedWork(string provider)
    {
        await using var database = await SetupDatabase.CreateAsync(
            provider, seedVersion: int.MaxValue - 1);
        await using var context = database.CreateContext();
        var service = CreateService(context, database.Options);

        var result = await service.CompleteAsync(
            CreateRequest(database.SetupCode), ClientIp, TestContext.Current.CancellationToken);

        Assert.Equal(SetupOutcome.InvalidSetupCode, result.Outcome);
        await VerifyNothingWasWrittenAsync(database, expectedVersion: int.MaxValue);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task RetryAfterAFailedAttempt_CompletesWithFreshAttemptState(string provider)
    {
        await using var database = await SetupDatabase.CreateAsync(provider);
        await SeedExistingAdministratorAsync(database, Username);
        await using var context = database.CreateContext();
        var service = CreateService(context, database.Options);

        var rejected = await service.CompleteAsync(
            CreateRequest(database.SetupCode, username: Username),
            ClientIp,
            TestContext.Current.CancellationToken);
        var completed = await service.CompleteAsync(
            CreateRequest(database.SetupCode, username: "second_admin"),
            ClientIp,
            TestContext.Current.CancellationToken);

        Assert.Equal(SetupOutcome.InvalidRequest, rejected.Outcome);
        Assert.Equal(SetupOutcome.Completed, completed.Outcome);
        await VerifyCommittedSliceAsync(database, username: "second_admin", expectedAccounts: 2);
    }

    public static TheoryData<string> CancellationCheckpoints()
    {
        return
        [
            "entry",
            "during-validate",
            "during-register",
            "before-commit",
            "rejection-with-cancellation",
            "after-commit"
        ];
    }

    /// <summary>
    /// Every caller-cancellation checkpoint delivers the same safe result: an
    /// <see cref="OperationCanceledException"/> carrying the original token, the fixed message, and
    /// no inner exception — once the transaction and its cleanup have settled. Cancellation
    /// observed after the commit keeps the committed facts; cancellation observed during the
    /// cleanup of an otherwise refused attempt wins over that refusal.
    /// </summary>
    [Theory]
    [MemberData(nameof(CancellationCheckpoints))]
    public async Task CallerCancellation_IsObservedOnceTheWorkHasSettled(string checkpoint)
    {
        using var cancellation = new CancellationTokenSource();
        DbTransactionInterceptor? interceptor = checkpoint switch
        {
            "before-commit" => new CancelOnCommittingInterceptor(cancellation),
            "after-commit" => new CancelAfterCommitInterceptor(cancellation),
            _ => null
        };
        await using var database = await SetupDatabase.CreateAsync("SQLite", interceptor: interceptor);

        RecordingHasher hasher;
        if (checkpoint is "during-validate" or "rejection-with-cancellation")
        {
            hasher = new RecordingHasher(CreateFastHasher());
            // The contributor's validation is the second policy call: cancel together with a
            // rejection there, so the pending refusal and the caller's cancellation coincide —
            // the cancellation observed once the failure cleanup settles must win.
            var policy = new RecordingPolicy(
                new DefaultPasswordPolicy(),
                cancellation,
                cancelOnCall: 2,
                failOnCall: checkpoint == "rejection-with-cancellation" ? 2 : null);
            await RunCanceledCompletionAsync(database, cancellation, policy: policy);
            return;
        }

        hasher = checkpoint == "during-register"
            ? new RecordingHasher(CreateFastHasher(), cancellation, cancelOnHash: true)
            : new RecordingHasher(CreateFastHasher());

        if (checkpoint == "entry")
        {
            await cancellation.CancelAsync();
        }

        await RunCanceledCompletionAsync(
            database, cancellation, interceptor: interceptor, hasher: hasher);

        if (checkpoint == "entry")
        {
            Assert.Equal(0, hasher.HashCalls);
        }

        if (checkpoint == "after-commit")
        {
            await VerifyCommittedSliceAsync(database);
        }
        else
        {
            await VerifyNothingWasWrittenAsync(database);
        }
    }

    /// <summary>
    /// Two independent scopes on a real PostgreSQL server overlap on the singleton installation
    /// row: the contender provably waits on a server-observed row lock, the winner completes, and
    /// the contender reports <see cref="SetupOutcome.AlreadyCompleted"/> — with exactly one
    /// committed first-run slice between them.
    /// </summary>
    [Fact]
    public async Task OverlappingScopes_OnPostgreSql_SerializeOnTheInstallationRow()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL setup concurrency matrix.");

        await using var container = CreatePostgreSqlContainer();
        await container.StartAsync(TestContext.Current.CancellationToken);
        await using var database = await SetupDatabase.CreateAsync(container);

        var locked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var winnerContext = database.CreateServicedContext(
            new HoldLockAfterRowLockInterceptor(locked, release));
        await using var contenderContext = database.CreateContext();
        var winnerService = CreateService(winnerContext, database.Options);
        var contenderService = CreateService(contenderContext, database.Options);

        var winner = Task.Run(() => winnerService.CompleteAsync(
            CreateRequest(database.SetupCode), ClientIp, TestContext.Current.CancellationToken));
        await locked.Task.WaitAsync(TimeSpan.FromSeconds(30));

        var contender = Task.Run(() => contenderService.CompleteAsync(
            CreateRequest(database.SetupCode), ClientIp, TestContext.Current.CancellationToken));

        // The contender must actually be waiting on the server's row lock — not merely queued in
        // the test process — before the winner releases anything.
        await using var observer = new NpgsqlConnection(container.GetConnectionString());
        await observer.OpenAsync(TestContext.Current.CancellationToken);
        var observed = false;
        for (var attempt = 0; attempt < 500 && !observed; attempt++)
        {
            await using var command = observer.CreateCommand();
            command.CommandText =
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() " +
                "AND wait_event_type = 'Lock' AND query LIKE '%service_installations%'";
            if (Convert.ToInt64(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken)) > 0)
            {
                observed = true;
                break;
            }

            await Task.Delay(20, TestContext.Current.CancellationToken);
        }

        Assert.True(observed, "The contender never waited on the installation row lock.");
        Assert.False(contender.IsCompleted);

        release.TrySetResult();
        var results = await Task.WhenAll(winner, contender);

        Assert.Equal(SetupOutcome.Completed, results[0].Outcome);
        Assert.Equal(SetupOutcome.AlreadyCompleted, results[1].Outcome);
        await VerifyCommittedSliceAsync(database);
    }

    /// <summary>
    /// A serialization-class transient failure inside the setup transaction is retried by the
    /// existing execution strategy; the retried attempt re-reads the installation and reports the
    /// completion instead of staging a second slice.
    /// </summary>
    [Fact]
    public async Task TransientFailure_IsRetriedAndReobservesCompletion()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL setup retry matrix.");

        await using var container = CreatePostgreSqlContainer();
        await container.StartAsync(TestContext.Current.CancellationToken);
        await using var database = await SetupDatabase.CreateAsync(container);

        await using (var firstContext = database.CreateContext())
        {
            var first = CreateService(firstContext, database.Options);
            Assert.Equal(
                SetupOutcome.Completed,
                (await first.CompleteAsync(
                    CreateRequest(database.SetupCode),
                    ClientIp,
                    TestContext.Current.CancellationToken)).Outcome);
        }

        var transient = new TransientSerializationFailureInterceptor();
        await using var secondContext = database.CreateServicedContext(transient);
        transient.Armed = true;
        var second = CreateService(secondContext, database.Options);

        var result = await second.CompleteAsync(
            CreateRequest(database.SetupCode), ClientIp, TestContext.Current.CancellationToken);

        Assert.True(transient.ThrewOnce);
        Assert.Equal(SetupOutcome.AlreadyCompleted, result.Outcome);
        await VerifyCommittedSliceAsync(database);
    }

    private static async Task RunCanceledCompletionAsync(
        SetupDatabase database,
        CancellationTokenSource cancellation,
        IInterceptor? interceptor = null,
        IPasswordHasher? hasher = null,
        IPasswordPolicy? policy = null)
    {
        await using var context = database.CreateServicedContext(interceptor);
        var service = CreateService(context, database.Options, hasher: hasher, policy: policy);

        OperationCanceledException? exception = null;
        try
        {
            var result = await service.CompleteAsync(
                CreateRequest(database.SetupCode), ClientIp, cancellation.Token);
            Assert.Fail($"Expected cancellation at the checkpoint, got {result.Outcome}.");
        }
        catch (OperationCanceledException caught)
        {
            exception = caught;
        }

        Assert.NotNull(exception);
        Assert.Equal(cancellation.Token, exception.CancellationToken);
        Assert.Null(exception.InnerException);
        Assert.Equal(CancelledMessage, exception.Message);
    }

    private static SetupRequest CreateRequest(
        string setupCode,
        string username = Username,
        string password = Password) =>
        new(PublicBaseUrl, false, "SignaCore.Services", username, password, setupCode);

    private static InstallationSetupService CreateService(
        IdentityDbContext context,
        DatabaseOptions options,
        IPasswordHasher? hasher = null,
        IPasswordPolicy? policy = null,
        IConfigurationProtector? protector = null)
    {
        hasher ??= CreateFastHasher();
        policy ??= new DefaultPasswordPolicy();
        return new InstallationSetupService(
            context,
            options,
            new SystemSettingsStore(
                protector ?? new AesGcmConfigurationProtector(new BootstrapMasterKeyProvider(RootKey))),
            policy,
            new InitialAdministratorSetupContributorFactory(context, hasher, policy),
            NullLogger<InstallationSetupService>.Instance);
    }

    private static IPasswordHasher CreateFastHasher() =>
        new BCryptPasswordHasher(new PasswordHasherOptions { WorkFactor = 4 });

    private static PostgreSqlContainer CreatePostgreSqlContainer() =>
        new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

    private static async Task SeedExistingAdministratorAsync(SetupDatabase database, string username)
    {
        await using var context = database.CreateContext();
        var accountId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = username,
            UsernameNormalized = IdentityValueNormalizer.Normalize(username),
            PasswordHash = "existing-test-hash",
            CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// The committed slice: one administrator with a verifiable hash, one consistent configuration
    /// version, encrypted secret defaults, exactly one legacy audit row linked to the created
    /// account, and a consumed setup code.
    /// </summary>
    private static async Task VerifyCommittedSliceAsync(
        SetupDatabase database,
        string username = Username,
        int expectedAccounts = 1)
    {
        await using var context = database.CreateContext();
        var installation = await context.ServiceInstallations.SingleAsync(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(InstallationStatus.Completed, installation.Status);
        Assert.NotNull(installation.CompletedAtUtc);
        Assert.Null(installation.SetupCodeDigest);
        Assert.Null(installation.SetupCodeExpiresAtUtc);

        var credentials = context.PasswordCredentials.AsNoTracking();
        var credential = expectedAccounts == 1
            ? await credentials.SingleAsync(cancellationToken: TestContext.Current.CancellationToken)
            : await credentials.SingleAsync(
                candidate => candidate.Username == username,
                cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(username, credential.Username);
        Assert.Equal(IdentityValueNormalizer.Normalize(username), credential.UsernameNormalized);
        Assert.True(CreateFastHasher().VerifyPassword(Password, credential.PasswordHash));
        Assert.DoesNotContain(Password, credential.PasswordHash, StringComparison.Ordinal);
        Assert.Equal(expectedAccounts, await context.Accounts.CountAsync(
            cancellationToken: TestContext.Current.CancellationToken));

        var settings = await context.SystemSettings
            .AsNoTracking()
            .ToDictionaryAsync(setting => setting.Key, cancellationToken: TestContext.Current.CancellationToken);
        var expectedKeys = SystemSettingsCatalog.BuildDefaults().Keys
            .Append(SystemSettingKeys.PublicBaseUrl)
            .Append(SystemSettingKeys.JwtIssuer)
            .Append(SystemSettingKeys.JwtAudience)
            .ToHashSet();
        Assert.Equal(expectedKeys, settings.Keys.ToHashSet());
        Assert.All(settings.Values, setting => Assert.Equal(1, setting.Version));
        Assert.Equal(PublicBaseUrl, settings[SystemSettingKeys.PublicBaseUrl].Value);
        Assert.Equal(username, settings[SystemSettingKeys.AdminUsername].Value);

        var protector = new AesGcmConfigurationProtector(new BootstrapMasterKeyProvider(RootKey));
        var secrets = settings.Values.Where(setting => setting.IsSecret).ToList();
        Assert.NotEmpty(secrets);
        foreach (var secret in secrets)
        {
            Assert.NotEqual(secret.Value, protector.Unprotect(secret.Key, secret.Value));
        }

        var repository = new AuditLogRepository(context);
        var auditRows = await repository.QueryAsync(
            "installation.setup.completed",
            "Installation",
            "signacore",
            credential.AccountId,
            pageSize: 10,
            skip: 0,
            cancellationToken: TestContext.Current.CancellationToken);
        var audit = Assert.Single(auditRows);
        Assert.Equal(credential.AccountId, audit.ActorId);
        Assert.Equal(username, audit.ActorName);
        Assert.Contains("ConfigurationVersion=1", audit.Description, StringComparison.Ordinal);
        Assert.DoesNotContain(PublicBaseUrl, audit.Description, StringComparison.Ordinal);
        Assert.Equal(ClientIp, audit.ClientIp);
        Assert.Null(audit.BeforeSnapshot);
        Assert.Null(audit.AfterSnapshot);
        // The synthetic password never reached the audit projection.
        Assert.DoesNotContain(Password, audit.Description ?? string.Empty, StringComparison.Ordinal);
        Assert.Equal(1, await context.AuditLogs.CountAsync(
            cancellationToken: TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// Nothing from a refused, failed, or canceled attempt reached the database: no accounts,
    /// credentials, settings, or audit rows were created, and the installation is still pending
    /// with its setup code intact.
    /// </summary>
    private static async Task VerifyNothingWasWrittenAsync(
        SetupDatabase database,
        int existingAccounts = 0,
        int existingCredentials = 0,
        int expectedVersion = 2)
    {
        await using var context = database.CreateContext();
        var installation = await context.ServiceInstallations.SingleAsync(
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(InstallationStatus.PendingSetup, installation.Status);
        Assert.Null(installation.CompletedAtUtc);
        Assert.NotNull(installation.SetupCodeDigest);
        Assert.NotNull(installation.SetupCodeExpiresAtUtc);
        Assert.Equal(expectedVersion, installation.Version);

        Assert.Equal(existingAccounts, await context.Accounts.CountAsync(
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(existingCredentials, await context.PasswordCredentials.CountAsync(
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.False(await context.SystemSettings.AnyAsync(
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.False(await context.AuditLogs.AnyAsync(
            cancellationToken: TestContext.Current.CancellationToken));
    }

    private static bool ShouldRunContainerMatrix() =>
        string.Equals(
            Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS"),
            "true",
            StringComparison.OrdinalIgnoreCase);

    private sealed class RecordingHasher(
        IPasswordHasher inner,
        CancellationTokenSource? cancellation = null,
        bool cancelOnHash = false) : IPasswordHasher
    {
        public int HashCalls { get; private set; }

        public string HashPassword(string password)
        {
            HashCalls++;
            if (cancelOnHash)
            {
                cancellation!.Cancel();
            }

            return inner.HashPassword(password);
        }

        public bool VerifyPassword(string password, string hash) =>
            inner.VerifyPassword(password, hash);
    }

    private sealed class RecordingPolicy(
        IPasswordPolicy inner,
        CancellationTokenSource? cancellation = null,
        int? cancelOnCall = null,
        int? failOnCall = null) : IPasswordPolicy
    {
        public int ValidateCalls { get; private set; }

        public bool Validate(string password, out string errorMessage)
        {
            ValidateCalls++;
            if (cancelOnCall == ValidateCalls)
            {
                cancellation!.Cancel();
            }

            if (failOnCall == ValidateCalls)
            {
                errorMessage = "Password does not satisfy the password policy";
                return false;
            }

            return inner.Validate(password, out errorMessage);
        }
    }

    private sealed class ThrowingHasher : IPasswordHasher
    {
        public string HashPassword(string password) =>
            throw new InvalidOperationException("synthetic hasher failure");

        public bool VerifyPassword(string password, string hash) => false;
    }

    private sealed class InternallyCancelingHasher : IPasswordHasher
    {
        public string HashPassword(string password) =>
            // An internal cancellation whose token nobody canceled: an ordinary failure, not a
            // caller cancellation.
            throw new OperationCanceledException();

        public bool VerifyPassword(string password, string hash) => false;
    }

    private sealed class ThrowingProtector : IConfigurationProtector
    {
        public string Protect(string settingKey, string plaintext) =>
            throw new CryptographicException("synthetic protection failure");

        public string Unprotect(string settingKey, string protectedValue) => protectedValue;
    }

    /// <summary>
    /// Fails the single setup SaveChanges so the staged slice meets a deterministic save failure.
    /// </summary>
    private sealed class FailingSaveInterceptor : SaveChangesInterceptor
    {
        public override InterceptionResult<int> SavingChanges(
            DbContextEventData eventData,
            InterceptionResult<int> result) =>
            throw new InvalidOperationException("synthetic save failure");

        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("synthetic save failure");
    }

    /// <summary>
    /// Cancels and throws while the setup transaction is committing: the flush already happened,
    /// so the transaction rolls back and nothing is committed.
    /// </summary>
    private sealed class CancelOnCommittingInterceptor(CancellationTokenSource cancellation)
        : DbTransactionInterceptor
    {
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(
            DbTransaction transaction,
            TransactionEventData eventData,
            InterceptionResult result,
            CancellationToken cancellationToken = default)
        {
            cancellation.Cancel();
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(result);
        }
    }

    /// <summary>
    /// Cancels after the commit finished without throwing from the interceptor: only the service's
    /// final cancellation check can still observe this cancellation, which is exactly what the
    /// test asserts against.
    /// </summary>
    private sealed class CancelAfterCommitInterceptor(CancellationTokenSource cancellation)
        : DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(
            DbTransaction transaction,
            TransactionEndEventData eventData,
            CancellationToken cancellationToken = default)
        {
            cancellation.Cancel();
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Holds the installation row lock taken by the setup's <c>SELECT ... FOR UPDATE</c> until the
    /// test releases it, so a second scope can be observed waiting on the server.
    /// </summary>
    private sealed class HoldLockAfterRowLockInterceptor(
        TaskCompletionSource locked,
        TaskCompletionSource release) : DbCommandInterceptor
    {
        public override async ValueTask<DbDataReader> ReaderExecutedAsync(
            DbCommand command,
            CommandExecutedEventData eventData,
            DbDataReader result,
            CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("FOR UPDATE", StringComparison.OrdinalIgnoreCase))
            {
                locked.TrySetResult();
                await release.Task.WaitAsync(TimeSpan.FromSeconds(60), cancellationToken);
            }

            return result;
        }
    }

    /// <summary>
    /// Throws one PostgreSQL serialization-failure error inside the transaction so the existing
    /// retrying execution strategy replays the whole setup attempt.
    /// </summary>
    private sealed class TransientSerializationFailureInterceptor : DbCommandInterceptor
    {
        private bool _thrown;

        public bool Armed { get; set; }

        public bool ThrewOnce => _thrown;

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            if (Armed && !_thrown)
            {
                _thrown = true;
                throw new PostgresException(
                    "synthetic serialization failure",
                    "ERROR",
                    "ERROR",
                    "40001");
            }

            return ValueTask.FromResult(result);
        }
    }

    /// <summary>
    /// A migrated, pending SignaCore installation with one revealed setup code. SQLite contexts
    /// share one open connection; PostgreSQL contexts connect through the provider's pool.
    /// </summary>
    private sealed class SetupDatabase : IAsyncDisposable
    {
        private SetupDatabase(
            IAsyncDisposable owner,
            Func<DbContextOptionsBuilder<IdentityDbContext>> optionsBuilderFactory,
            DatabaseOptions options,
            string setupCode)
        {
            Owner = owner;
            OptionsBuilderFactory = optionsBuilderFactory;
            Options = options;
            SetupCode = setupCode;
        }

        private IAsyncDisposable Owner { get; }

        private Func<DbContextOptionsBuilder<IdentityDbContext>> OptionsBuilderFactory { get; }

        public DatabaseOptions Options { get; }

        public string SetupCode { get; }

        public static async Task<SetupDatabase> CreateAsync(
            string provider,
            int? seedVersion = null,
            IInterceptor? interceptor = null)
        {
            if (provider == "SQLite")
            {
                var connection = new SqliteConnection("Data Source=:memory:");
                await connection.OpenAsync(TestContext.Current.CancellationToken);
                var connectionOwner = new ConnectionOwner(connection);
                try
                {
                    return await CreateCoreAsync(
                        connectionOwner,
                        () => new DbContextOptionsBuilder<IdentityDbContext>()
                            .UseSqlite(
                                connection,
                                providerOptions => providerOptions.MigrationsAssembly(
                                    "SignaCore.Database.Migrations.Sqlite")),
                        new DatabaseOptions { Provider = "SQLite", ConnectionString = "Data Source=:memory:" },
                        seedVersion,
                        interceptor);
                }
                catch
                {
                    await connectionOwner.DisposeAsync();
                    throw;
                }
            }

            if (!ShouldRunContainerMatrix())
            {
                Assert.Skip(
                    "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL setup contract matrix.");
            }

            var container = CreatePostgreSqlContainer();
            await container.StartAsync(TestContext.Current.CancellationToken);
            try
            {
                var options = new DatabaseOptions
                {
                    Provider = "PostgreSQL",
                    ServerVersion = "15",
                    ConnectionString = container.GetConnectionString()
                };
                return await CreateCoreAsync(
                    container,
                    () =>
                {
                    var builder = new DbContextOptionsBuilder<IdentityDbContext>();
                    builder.UseIdentityDatabase(options);
                    return builder;
                },
                    options,
                    seedVersion,
                    interceptor);
            }
            catch
            {
                await container.DisposeAsync();
                throw;
            }
        }

        public static async Task<SetupDatabase> CreateAsync(PostgreSqlContainer container)
        {
            var options = new DatabaseOptions
            {
                Provider = "PostgreSQL",
                ServerVersion = "15",
                ConnectionString = container.GetConnectionString()
            };
            return await CreateCoreAsync(
                new NoopOwner(),
                () =>
                {
                    var builder = new DbContextOptionsBuilder<IdentityDbContext>();
                    builder.UseIdentityDatabase(options);
                    return builder;
                },
                options,
                seedVersion: null,
                interceptor: null);
        }

        private static async Task<SetupDatabase> CreateCoreAsync(
            IAsyncDisposable owner,
            Func<DbContextOptionsBuilder<IdentityDbContext>> optionsBuilderFactory,
            DatabaseOptions options,
            int? seedVersion,
            IInterceptor? interceptor)
        {
            await WaitUntilConnectableAsync(optionsBuilderFactory().Options);

            await using (var migration = new IdentityDbContext(optionsBuilderFactory().Options))
            {
                await migration.Database.MigrateAsync(TestContext.Current.CancellationToken);
            }

            await using (var seeding = new IdentityDbContext(optionsBuilderFactory().Options))
            {
                seeding.ServiceInstallations.Add(new ServiceInstallationEntity
                {
                    ServiceId = InstallationStores.ServiceIdValue,
                    Status = InstallationStatus.PendingSetup,
                    CreatedAtUtc = DateTime.UtcNow.AddMinutes(-1),
                    Version = seedVersion ?? 1
                });
                await seeding.SaveChangesAsync(TestContext.Current.CancellationToken);
                seeding.ChangeTracker.Clear();

                var issued = await InstallationStores.CreateSetupCodeStore(seeding)
                    .CreateAsync(InstallationStores.ServiceId, TestContext.Current.CancellationToken);
                Assert.True(issued.IsIssued, $"Setup code creation failed: {issued.ErrorCode}");
                return new SetupDatabase(
                    owner, optionsBuilderFactory, options, issued.SetupCode!.Reveal());
            }
        }

        /// <summary>
        /// Rapid container churn on a shared Docker daemon can briefly refuse the mapped port even
        /// after the container reports started; connect attempts are retried until the database
        /// actually answers.
        /// </summary>
        private static async Task WaitUntilConnectableAsync(DbContextOptions<IdentityDbContext> options)
        {
            var deadline = DateTimeOffset.UtcNow.AddSeconds(60);
            while (DateTimeOffset.UtcNow < deadline)
            {
                try
                {
                    await using var probe = new IdentityDbContext(options);
                    if (await probe.Database.CanConnectAsync(TestContext.Current.CancellationToken))
                    {
                        return;
                    }
                }
                catch (Exception)
                {
                    // Retry until the deadline: the container may still be forwarding ports.
                }

                await Task.Delay(200, TestContext.Current.CancellationToken);
            }

            throw new InvalidOperationException(
                "The setup contract database did not become connectable within 60s.");
        }

        public IdentityDbContext CreateContext() =>
            new(OptionsBuilderFactory().Options);

        public IdentityDbContext CreateServicedContext(IInterceptor? interceptor) =>
            interceptor is null
                ? CreateContext()
                : new(OptionsBuilderFactory().AddInterceptors(interceptor).Options);

        public async ValueTask DisposeAsync() => await Owner.DisposeAsync();

        private sealed class ConnectionOwner(DbConnection connection) : IAsyncDisposable
        {
            public async ValueTask DisposeAsync() => await connection.DisposeAsync();
        }

        private sealed class NoopOwner : IAsyncDisposable
        {
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }
}
