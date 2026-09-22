using System.Data.Common;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Keys;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host.Configuration;
using ServiceMantle.Audit;
using ServiceMantle.Configuration;
using ServiceMantle.Installation;
using ServiceMantle.AspNetCore.ManagementApi.Setup;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Host.Installation;
using SignaCore.Tests.Integration;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// Database contract of the executor-backed first-run setup slice: the shared setup entry hands the
/// completion to <see cref="SetupCompletionExecutor"/>, which stages the initial administrator,
/// the settings snapshot, and the installation audit projection into one transaction whose only
/// save and commit belong to the executor.
/// <para>
/// The SQLite provider runs everywhere; the PostgreSQL cases join the container matrix gated by
/// <c>RUN_SIGNACORE_DATABASE_CONTRACTS=true</c>, which the CI database-contract job selects through
/// the <c>DatabaseContractTests</c> name filter. Every context is built with the retrying
/// execution strategy disabled, exactly the way the PendingSetup host registers its contexts.
/// </para>
/// </summary>
public sealed class SetupContributorDatabaseContractTests
{
    private const string RootKey = "setup-contract-root-key";
    private const string Username = "setup_admin";
    private const string Password = "SetupAdmin123";
    private const string PublicBaseUrl = "https://identity.example.test";
    private const string ClientIp = "192.0.2.10";

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

        var result = await CompleteAsync(
            context, database.Options, database.SetupCode,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(SetupCompletionStatus.Committed, result.Status);
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

        var result = await CompleteAsync(
            context, database.Options, database.SetupCode, hasher: hasher, policy: policy,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(SetupCompletionStatus.Committed, result.Status);
        // One hash from the contributor's single registration; the policy answered the executor's
        // request-level shape check and the contributor's read-only validation.
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

        var result = await CompleteAsync(
            context, database.Options, database.SetupCode, policy: policy,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(SetupCompletionStatus.ValidationFailed, result.Status);
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

        var result = await CompleteAsync(
            context, database.Options, database.SetupCode,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(SetupCompletionStatus.ValidationFailed, result.Status);
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

    /// <summary>
    /// A contributor failure is the one safe-unavailable outcome — never a validation verdict, and
    /// never a detail-carrying exception across the executor boundary.
    /// </summary>
    [Theory]
    [MemberData(nameof(ContributorFailureModes))]
    public async Task ContributorFailures_LeaveNothingWrittenAndAnswerUnavailable(string failureMode)
    {
        await using var database = await SetupDatabase.CreateAsync("SQLite");
        await using var context = database.CreateContext();
        IPasswordHasher hasher = failureMode switch
        {
            "hasher-throws" => new ThrowingHasher(),
            "hasher-cancel-internally" => new InternallyCancelingHasher(),
            _ => throw new ArgumentOutOfRangeException(nameof(failureMode))
        };

        var result = await CompleteAsync(
            context, database.Options, database.SetupCode, hasher: hasher,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(SetupCompletionStatus.Unavailable, result.Status);
        await VerifyNothingWasWrittenAsync(database);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task SettingsAndAuditFailures_LeaveNothingWrittenAndAnswerUnavailable(string provider)
    {
        await using var rootKeyFailure = await SetupDatabase.CreateAsync(provider);
        await using (var context = rootKeyFailure.CreateContext())
        {
            var result = await CompleteAsync(
                context, rootKeyFailure.Options, rootKeyFailure.SetupCode,
                rootKeySource: new ThrowingRootKeySource(),
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.Equal(SetupCompletionStatus.Unavailable, result.Status);
        }

        await VerifyNothingWasWrittenAsync(rootKeyFailure);

        // The shared audit model refuses a client IP that is not an address, which fails the audit
        // staging after the aggregate was staged: everything must still roll back.
        await using var auditFailure = await SetupDatabase.CreateAsync(provider);
        await using (var context = auditFailure.CreateContext())
        {
            var result = await CompleteAsync(
                context, auditFailure.Options, auditFailure.SetupCode, clientIp: "not-an-ip",
                cancellationToken: TestContext.Current.CancellationToken);

            Assert.Equal(SetupCompletionStatus.Unavailable, result.Status);
        }

        await VerifyNothingWasWrittenAsync(auditFailure);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task SaveFailure_LeavesNothingWrittenAndAnswersUnavailable(string provider)
    {
        await using var database = await SetupDatabase.CreateAsync(provider);
        await using var context = database.CreateServicedContext(new FailingSaveInterceptor());

        var result = await CompleteAsync(
            context, database.Options, database.SetupCode,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(SetupCompletionStatus.Unavailable, result.Status);
        await VerifyNothingWasWrittenAsync(database);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task CommitFailure_LeavesNothingWrittenAndAnswersUnavailable(string provider)
    {
        await using var database = await SetupDatabase.CreateAsync(provider);
        await using var context = database.CreateServicedContext(new FailingCommitInterceptor());

        var result = await CompleteAsync(
            context, database.Options, database.SetupCode,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(SetupCompletionStatus.Unavailable, result.Status);
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

        var result = await CompleteAsync(
            context, database.Options, database.SetupCode,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(SetupCompletionStatus.CredentialInvalid, result.Status);
        await VerifyNothingWasWrittenAsync(database, expectedVersion: int.MaxValue);
    }

    /// <summary>
    /// A refusal does not poison the transaction owner: the same code completes cleanly on the
    /// next submission, through a fresh scope with fresh attempt state.
    /// </summary>
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task RetryAfterAFailedAttempt_CompletesWithFreshAttemptState(string provider)
    {
        await using var database = await SetupDatabase.CreateAsync(provider);
        await SeedExistingAdministratorAsync(database, Username);
        await using (var context = database.CreateContext())
        {
            var rejected = await CompleteAsync(
                context, database.Options, database.SetupCode, username: Username,
                cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal(SetupCompletionStatus.ValidationFailed, rejected.Status);
        }

        await using (var context = database.CreateContext())
        {
            var completed = await CompleteAsync(
                context, database.Options, database.SetupCode, username: "second_admin",
                cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal(SetupCompletionStatus.Committed, completed.Status);
        }

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
    /// Every caller-cancellation checkpoint delivers the caller's own cancellation — an
    /// <see cref="OperationCanceledException"/> carrying the original token — once the transaction
    /// and its cleanup have settled. Cancellation observed after the commit keeps the committed
    /// facts; cancellation observed during the cleanup of an otherwise refused attempt wins over
    /// that refusal.
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
    /// exactly one first-run slice is committed between them.
    /// <para>
    /// The contender's answer depends on where the race caught it. A submission that arrives after
    /// the winner committed reads <c>Completed</c> and answers the closed conflict. A submission
    /// that is waiting on the row lock when the winner commits is released with the Serializable
    /// serialization failure; the shared entry contract forbids replaying the user transaction, so
    /// that loser answers unavailable and its next submission observes the completion — which is
    /// what the operator-facing surface (and the frontend's 503-then-retry path) relies on.
    /// </para>
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

        var winner = Task.Run(() =>
            CompleteAsync(winnerContext, database.Options, database.SetupCode,
                cancellationToken: TestContext.Current.CancellationToken));
        await locked.Task.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);

        var contender = Task.Run(() =>
            CompleteAsync(contenderContext, database.Options, database.SetupCode,
                cancellationToken: TestContext.Current.CancellationToken));

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

        Assert.Equal(SetupCompletionStatus.Committed, results[0].Status);
        Assert.Contains(
            results[1].Status,
            new[] { SetupCompletionStatus.Conflict, SetupCompletionStatus.Unavailable });
        await VerifyCommittedSliceAsync(database);

        // Whatever the loser answered, the completion is durable: the next submission always
        // observes it and answers the closed conflict.
        await using var aftermath = database.CreateContext();
        var resubmission = await CompleteAsync(
            aftermath, database.Options, database.SetupCode,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(SetupCompletionStatus.Conflict, resubmission.Status);
    }

    /// <summary>
    /// A serialization-class transient failure inside the completion transaction is attempted
    /// exactly once — the shared entry contract forbids replaying a user transaction — and answers
    /// unavailable; the next submission, on a clean scope, re-reads the installation and answers
    /// the conflict.
    /// </summary>
    [Fact]
    public async Task TransientFailure_IsAttemptedOnceAndTheNextSubmissionReobservesCompletion()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL setup retry matrix.");

        await using var container = CreatePostgreSqlContainer();
        await container.StartAsync(TestContext.Current.CancellationToken);
        await using var database = await SetupDatabase.CreateAsync(container);

        await using (var firstContext = database.CreateContext())
        {
            var first = await CompleteAsync(
                firstContext, database.Options, database.SetupCode,
                cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal(SetupCompletionStatus.Committed, first.Status);
        }

        var transient = new TransientSerializationFailureInterceptor();
        await using var secondContext = database.CreateServicedContext(transient);
        transient.Armed = true;

        var second = await CompleteAsync(
            secondContext, database.Options, database.SetupCode,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(transient.ThrewOnce);
        Assert.Equal(SetupCompletionStatus.Unavailable, second.Status);
        await VerifyCommittedSliceAsync(database);

        await using var thirdContext = database.CreateContext();
        var third = await CompleteAsync(
            thirdContext, database.Options, database.SetupCode,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(SetupCompletionStatus.Conflict, third.Status);
    }

    /// <summary>
    /// The fixed completion log line carries only the service id and the configuration version:
    /// none of the submitted values — password, setup code, audience, username, public base URL —
    /// may reach a log.
    /// </summary>
    [Fact]
    public async Task CompletionLog_NeverCarriesSubmittedValues()
    {
        await using var database = await SetupDatabase.CreateAsync("SQLite");
        await using var context = database.CreateContext();
        var logger = new RecordingLogger();

        var result = await CompleteAsync(
            context, database.Options, database.SetupCode, logger: logger,
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(SetupCompletionStatus.Committed, result.Status);
        var line = Assert.Single(logger.Lines);
        Assert.Contains("First-run setup completed", line, StringComparison.Ordinal);
        Assert.DoesNotContain(Password, line, StringComparison.Ordinal);
        Assert.DoesNotContain(database.SetupCode, line, StringComparison.Ordinal);
        Assert.DoesNotContain(Username, line, StringComparison.Ordinal);
        Assert.DoesNotContain(PublicBaseUrl, line, StringComparison.Ordinal);
    }

    private static async Task RunCanceledCompletionAsync(
        SetupDatabase database,
        CancellationTokenSource cancellation,
        IInterceptor? interceptor = null,
        IPasswordHasher? hasher = null,
        IPasswordPolicy? policy = null)
    {
        await using var context = database.CreateServicedContext(interceptor);

        OperationCanceledException? exception = null;
        try
        {
            var result = await CompleteAsync(
                context, database.Options, database.SetupCode,
                hasher: hasher, policy: policy, cancellationToken: cancellation.Token);
            Assert.Fail($"Expected cancellation at the checkpoint, got {result.Status}.");
        }
        catch (OperationCanceledException caught)
        {
            exception = caught;
        }

        Assert.NotNull(exception);
        Assert.Equal(cancellation.Token, exception.CancellationToken);
    }

    private static Task<SetupCompletionResult> CompleteAsync(
        IdentityDbContext context,
        DatabaseOptions options,
        string setupCode,
        string? clientIp = ClientIp,
        string username = Username,
        IPasswordHasher? hasher = null,
        IPasswordPolicy? policy = null,
        IServiceSettingRootKeySource? rootKeySource = null,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        hasher ??= CreateFastHasher();
        policy ??= new DefaultPasswordPolicy();
        var masterKeyProvider = new BootstrapMasterKeyProvider(RootKey);
        return SetupCompletionExecutor.CompleteAsync(
            context,
            options,
            new ServiceSettingUpdateService(
                InstallationStores.ServiceId,
                SharedSettingComposition.CreateRegistry(isDevelopment: false),
                new EfCoreServiceSettingUpdateTransaction<IdentityDbContext>(context),
                rootKeySource ?? SharedSettingComposition.CreateRootKeySource(masterKeyProvider)),
            policy,
            new InitialAdministratorSetupContributorFactory(context, hasher, policy),
            logger ?? NullLogger.Instance,
            clientIp,
            ParseCode(setupCode),
            CreateInput(username: username),
            cancellationToken);
    }

    private static SetupCode ParseCode(string setupCode)
    {
        Assert.True(SetupCode.TryParse(setupCode, out var parsed), "The seeded code must parse.");
        return parsed!;
    }

    private static JsonElement CreateInput(
        string publicBaseUrl = PublicBaseUrl,
        bool allowNonHttpsIssuer = false,
        string jwtAudience = "SignaCore.Services",
        string username = Username,
        string password = Password) =>
        JsonSerializer.SerializeToElement(new
        {
            publicBaseUrl,
            allowNonHttpsIssuer,
            jwtAudience,
            username,
            password,
        });

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
    /// The committed slice: one administrator with a verifiable hash, one first-version shared
    /// settings aggregate with all keys as envelopes for secrets, exactly one legacy audit row
    /// linked to the created account, the shared per-key audit projection of the aggregate write,
    /// and a consumed setup code. The legacy <c>system_settings</c> table stays empty: it is
    /// read-only legacy data since the aggregate became the write authority.
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

        // The shared aggregate is the first version and carries the complete catalog: the rendered
        // setup values plus defaults, with secrets as shared-protector envelopes.
        var aggregate = await SharedSettingTestDatabase.LoadAggregateAsync(context);
        Assert.NotNull(aggregate);
        Assert.Equal(1, aggregate!.Version);
        Assert.Equal(username, aggregate.UpdatedBy);
        var aggregateValues = SharedSettingTestDatabase.ParseValues(aggregate);
        var expectedKeys = ServiceSettingDefinitions.Table
            .Select(definition => definition.Key)
            .ToHashSet(StringComparer.Ordinal);
        Assert.Equal(expectedKeys, aggregateValues.Keys.ToHashSet(StringComparer.Ordinal));
        Assert.Equal(PublicBaseUrl, aggregateValues["endpoints.public_base_url"]);
        Assert.Equal(PublicBaseUrl, aggregateValues["jwt.issuer"]);
        Assert.Equal(username, aggregateValues["admin.username"]);
        var sensitiveKeys = ServiceSettingDefinitions.Table
            .Where(definition => definition.IsSensitive)
            .Select(definition => definition.Key)
            .ToHashSet(StringComparer.Ordinal);
        Assert.NotEmpty(sensitiveKeys);
        foreach (var sensitiveKey in sensitiveKeys)
        {
            Assert.StartsWith("sm:v1:", aggregateValues[sensitiveKey], StringComparison.Ordinal);
        }

        // The retired legacy table is gone; the switched completion wrote the aggregate only.
        Assert.False(await SharedSettingTestDatabase.LegacyTableExistsAsync(
            context, TestContext.Current.CancellationToken));

        // The aggregate write also produced its value-free shared audit projection, one row per
        // changed key, without any submitted value.
        var sharedAuditJson = await SharedSettingTestDatabase.LoadSharedAuditJsonAsync(context);
        // The per-key configuration audits only: the installation event also lives in the shared
        // table now and is asserted separately below.
        Assert.Equal(
            expectedKeys.Count,
            sharedAuditJson.Count(row => row.StartsWith("configuration.changed|", StringComparison.Ordinal)));
        Assert.All(sharedAuditJson, row => Assert.DoesNotContain(PublicBaseUrl, row, StringComparison.Ordinal));

        var audit = Assert.Single(
            (await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(context, TestContext.Current.CancellationToken))
            .Where(row => row.Action == "installation.completed"));
        Assert.Equal("installation.completed", audit.Action);
        Assert.Equal("service", audit.TargetType);
        Assert.Equal("signacore", audit.TargetId);
        Assert.Equal(credential.AccountId.ToString(), audit.OperatorId);
        Assert.Equal(username, audit.OperatorDisplayName);
        Assert.Equal("setup_code", audit.OperatorSource);
        Assert.Contains("ConfigurationVersion=1", audit.SecurityDescription, StringComparison.Ordinal);
        Assert.DoesNotContain(PublicBaseUrl, audit.SecurityDescription, StringComparison.Ordinal);
        Assert.Equal(ClientIp, audit.ClientIp);
        // The synthetic password never reached the audit row.
        Assert.DoesNotContain(Password, audit.SecurityDescription ?? string.Empty, StringComparison.Ordinal);
    }

    /// <summary>
    /// Nothing from a refused, failed, or canceled attempt reached the database: no accounts,
    /// credentials, aggregate, shared audit rows, or legacy audit rows were created, and the
    /// installation is still pending with its setup code intact.
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
        Assert.Null(await SharedSettingTestDatabase.LoadAggregateAsync(context));
        Assert.Empty(await SharedSettingTestDatabase.LoadSharedAuditJsonAsync(context));
        Assert.False(await SharedSettingTestDatabase.LegacyTableExistsAsync(
            context, TestContext.Current.CancellationToken));
        Assert.Empty((await SharedSettingTestDatabase.LoadSharedAuditRowsAsync(
                    context, TestContext.Current.CancellationToken))
                .Where(row => row.Action.StartsWith("installation.", StringComparison.Ordinal)));
    }

    private static bool ShouldRunContainerMatrix() =>
        string.Equals(
            Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS"),
            "true",
            StringComparison.OrdinalIgnoreCase);

    private sealed class RecordingLogger : ILogger
    {
        public List<string> Lines { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) => Lines.Add(formatter(state, exception));
    }

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

    private sealed class ThrowingRootKeySource : IServiceSettingRootKeySource
    {
        public ValueTask<string> GetRootKeyAsync(CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("synthetic root key failure");
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
    /// Fails the setup transaction's commit so the staged slice meets a deterministic commit
    /// failure after the single save succeeded.
    /// </summary>
    private sealed class FailingCommitInterceptor : DbTransactionInterceptor
    {
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(
            DbTransaction transaction,
            TransactionEventData eventData,
            InterceptionResult result,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("synthetic commit failure");
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
    /// Cancels after the commit finished without throwing from the interceptor: only the
    /// executor's post-settlement cancellation check can still observe this cancellation, which is
    /// exactly what the test asserts against.
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
    /// Throws one PostgreSQL serialization-failure error inside the transaction; with the retrying
    /// execution strategy disabled the completion must answer unavailable after exactly one
    /// attempt instead of replaying the user transaction.
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
    /// share one open connection; PostgreSQL contexts connect through the provider's pool with the
    /// retrying execution strategy disabled, matching the PendingSetup host's registration.
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
                    () => CreatePostgreSqlOptionsBuilder(options),
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
                () => CreatePostgreSqlOptionsBuilder(options),
                options,
                seedVersion: null,
                interceptor: null);
        }

        private static DbContextOptionsBuilder<IdentityDbContext> CreatePostgreSqlOptionsBuilder(
            DatabaseOptions options)
        {
            var builder = new DbContextOptionsBuilder<IdentityDbContext>();
            builder.UseIdentityDatabase(options, enableRetryOnFailure: false);
            return builder;
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
