using System.Data.Common;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using Xunit;
using SignaCore.Tests.Integration;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// Pins the storage and domain semantics of the shared authorization-request continuation
/// (<c>PS-03</c>) on a file-backed SQLite database running the real migration chain: one-time
/// plaintext handle, digest-only persistence, binding snapshots, expiry without consumption, atomic
/// one-time consumption with captured instants, cross-instance recovery through the shared database
/// alone, unavailable-without-write lookups, sensitive-value containment (<c>DF-05</c>), and
/// retention cleanup as one rollback-able unit.
/// <para>
/// The real-provider schema matrix and the two-connection PostgreSQL concurrency proof live in
/// <see cref="ServerDatabaseContractTests"/> and <see cref="SqliteDatabaseContractTests"/>. The
/// <c>DatabaseContractTests</c> suffix is deliberate: CI's Database Contract Test stage filters on
/// <c>FullyQualifiedName~DatabaseContractTests</c>, and this group needs no Docker.
/// </para>
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class AuthorizationRequestDatabaseContractTests
{
    private const string ClientId = "continuation-contract-app";
    private const string RegisteredRedirectUri = "https://client.example.com/callback?tenant=one";
    private const string CanonicalScope = "openid profile";
    private const string StateCanary = "StateCanary_7f3a9b2c4d5e6f70819a";
    private const string NonceCanary = "NonceCanary_4c8d2e6f0a1b3c5d7e9f";
    private const string CodeChallenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    /// <summary>AC-3 / AC-4: plaintext once, digest-only row, byte-exact binding snapshots.</summary>
    [Fact]
    public async Task Create_ReturnsPlaintextHandleOnce_AndPersistsDigestSnapshotOnly()
    {
        await using var database = new SqliteFileDatabase();
        var options = await database.InitializeAsync();
        var applicationId = await SeedApplicationAsync(options);
        var now = DateTimeOffset.UtcNow;

        AuthorizationRequestCreation creation;
        await using (var context = new IdentityDbContext(options))
        {
            creation = await CreateStore(context).CreateAsync(
                CreateAccepted(applicationId),
                now,
                TestContext.Current.CancellationToken);
        }

        AssertLoginHandleShape(creation.LoginHandle);

        await using var verification = new IdentityDbContext(options);
        var row = await verification.AuthorizationRequests
            .AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(creation.Id, row.Id);
        Assert.True(LoginHandleDigest.IsDigest(row.HandleDigest));
        Assert.Equal(LoginHandleDigest.Compute(creation.LoginHandle), row.HandleDigest);
        Assert.Equal(applicationId, row.AppRegistrationId);
        Assert.Equal(RegisteredRedirectUri, row.RedirectUri);
        Assert.Equal(CanonicalScope, row.Scope);
        Assert.Equal(StateCanary, row.State);
        Assert.Equal(NonceCanary, row.Nonce);
        Assert.Equal(CodeChallenge, row.CodeChallenge);
        Assert.Equal(now.UtcTicks / 10, row.CreatedAt.UtcTicks / 10);
        Assert.Equal(
            now.AddMinutes(IdentityConstants.LoginHandleLifetimeMinutes).UtcTicks / 10,
            row.ExpiresAt.UtcTicks / 10);
        Assert.Null(row.ConsumedAt);

        // The plaintext exists only in the one-time creation result: no column of any table holds it.
        var dumps = await DumpTablesAsync(options);
        Assert.DoesNotContain(creation.LoginHandle, string.Concat(dumps.Values));

        // High-entropy source: every handle is fresh, full-length, and unique.
        var handles = new HashSet<string>(StringComparer.Ordinal) { creation.LoginHandle };
        await using var entropyContext = new IdentityDbContext(options);
        var store = CreateStore(entropyContext);
        for (var index = 0; index < 24; index++)
        {
            var next = await store.CreateAsync(
                CreateAccepted(applicationId),
                now,
                TestContext.Current.CancellationToken);
            AssertLoginHandleShape(next.LoginHandle);
            Assert.True(handles.Add(next.LoginHandle));
        }

        Assert.Equal(25, handles.Count);
    }

    /// <summary><c>DF-05</c> at the persistence boundary: a plaintext handle staged on the entity
    /// is forced into the versioned digest and never reaches a column.</summary>
    [Fact]
    public async Task Add_WithPlaintextHandle_StoresDigestNotPlaintext()
    {
        await using var database = new SqliteFileDatabase();
        var options = await database.InitializeAsync();
        var applicationId = await SeedApplicationAsync(options);
        const string plaintextHandle = "plaintext-handle-0123456789Abcdefghijklmnop";
        var now = DateTimeOffset.UtcNow;

        await using (var context = new IdentityDbContext(options))
        {
            var repository = new AuthorizationRequestRepository(context);
            await repository.AddAsync(
                new AuthorizationRequestEntity
                {
                    Id = Guid.NewGuid(),
                    HandleDigest = plaintextHandle,
                    AppRegistrationId = applicationId,
                    RedirectUri = RegisteredRedirectUri,
                    Scope = CanonicalScope,
                    State = StateCanary,
                    Nonce = NonceCanary,
                    CodeChallenge = CodeChallenge,
                    CreatedAt = now,
                    ExpiresAt = now.AddMinutes(IdentityConstants.LoginHandleLifetimeMinutes)
                },
                TestContext.Current.CancellationToken);
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        await using var verification = new IdentityDbContext(options);
        var stored = await verification.AuthorizationRequests
            .AsNoTracking()
            .Select(row => row.HandleDigest)
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(LoginHandleDigest.Compute(plaintextHandle), stored);

        var dumps = await DumpTablesAsync(options);
        Assert.DoesNotContain(plaintextHandle, string.Concat(dumps.Values));
    }

    /// <summary>
    /// AC-5 / AC-10: expired, consumed, missing, and malformed handles all resolve to the single
    /// unavailable answer with no state write, no invented state, and no replay/audit record. The
    /// expiry boundary is <c>expires_at &lt;= now</c>, and expiry never writes <c>consumed_at</c>.
    /// </summary>
    [Fact]
    public async Task GetActive_MissingExpiredConsumedOrMalformed_IsSingleUnavailableWithoutWrites()
    {
        await using var database = new SqliteFileDatabase();
        var options = await database.InitializeAsync();
        var applicationId = await SeedApplicationAsync(options);
        var createdAt = DateTimeOffset.UtcNow.AddMinutes(-1);

        string handle;
        Guid requestId;
        await using (var context = new IdentityDbContext(options))
        {
            var creation = await CreateStore(context).CreateAsync(
                CreateAccepted(applicationId),
                createdAt,
                TestContext.Current.CancellationToken);
            handle = creation.LoginHandle;
            requestId = creation.Id;
        }

        var beforeDumps = await DumpTablesAsync(options);

        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            var cancellationToken = TestContext.Current.CancellationToken;

            // Active inside the lifetime.
            var active = await store.GetActiveAsync(handle, createdAt.AddMinutes(1), cancellationToken);
            Assert.NotNull(active);
            Assert.Equal(requestId, active.Id);

            // Expired at and beyond the boundary: expires_at <= now is unavailable, and expiry is
            // not consumption — consumed_at must stay null.
            var atExpiry = createdAt.AddMinutes(IdentityConstants.LoginHandleLifetimeMinutes);
            Assert.Null(await store.GetActiveAsync(handle, atExpiry, cancellationToken));
            Assert.Null(await store.GetActiveAsync(handle, atExpiry.AddSeconds(1), cancellationToken));

            // Missing digest and malformed raw input: same single unavailable answer, never a query
            // keyed by unvalidated input.
            Assert.Null(await store.GetActiveAsync(
                "unknown-but-well-formed-0123456789abcdefghi", atExpiry, cancellationToken));
            foreach (var malformed in new[]
                     {
                         new string('a', 42),
                         new string('a', 44),
                         "dBjftJeZ4CVP-mB92K27uhbUJU1p1r.wW1gFWFOEjXk",
                         "dBjftJeZ4CVP+mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                         "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX ",
                         string.Empty
                     })
            {
                Assert.Null(await store.GetActiveAsync(malformed, atExpiry, cancellationToken));
            }

            // The expired row was never marked consumed.
            var expiredRow = await context.AuthorizationRequests
                .AsNoTracking()
                .SingleAsync(row => row.Id == requestId, cancellationToken);
            Assert.Null(expiredRow.ConsumedAt);

            // A live row disappears from lookups once consumed, without any extra write.
            var liveNow = createdAt.AddMinutes(1);
            Assert.True(await store.TryConsumeAsync(handle, liveNow, cancellationToken));
            Assert.Null(await store.GetActiveAsync(handle, liveNow, cancellationToken));
        }

        // AC-10: every unavailable lookup above — missing, expired, malformed — wrote nothing
        // beyond the single committed consumption, and produced no audit or replay record.
        var afterDumps = await DumpTablesAsync(options);
        Assert.Equal(beforeDumps.Keys, afterDumps.Keys);
        foreach (var (table, beforeDump) in beforeDumps)
        {
            if (table == "authorization_requests")
            {
                continue;
            }

            Assert.Equal(beforeDump, afterDumps[table]);
        }

        Assert.Equal(string.Empty, afterDumps["service_audit_logs"]);
        Assert.Equal(string.Empty, afterDumps["login_histories"]);

        await using var verification = new IdentityDbContext(options);
        var consumedRow = await verification.AuthorizationRequests
            .AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.NotNull(consumedRow.ConsumedAt);
    }

    /// <summary>
    /// AC-6: two sequential consumptions of the same handle — the first succeeds, the second
    /// observes the committed consumption result and changes nothing.
    /// </summary>
    [Fact]
    public async Task TryConsume_SequentialCalls_ConsumeExactlyOnceWithCapturedInstant()
    {
        await using var database = new SqliteFileDatabase();
        var options = await database.InitializeAsync();
        var applicationId = await SeedApplicationAsync(options);
        var createdAt = DateTimeOffset.UtcNow.AddMinutes(-2);

        string handle;
        await using (var context = new IdentityDbContext(options))
        {
            handle = (await CreateStore(context).CreateAsync(
                CreateAccepted(applicationId),
                createdAt,
                TestContext.Current.CancellationToken)).LoginHandle;
        }

        var firstInstant = createdAt.AddMinutes(1);
        var secondInstant = createdAt.AddMinutes(2);
        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            Assert.True(await store.TryConsumeAsync(handle, firstInstant, TestContext.Current.CancellationToken));
            Assert.False(await store.TryConsumeAsync(handle, secondInstant, TestContext.Current.CancellationToken));
        }

        await using var verification = new IdentityDbContext(options);
        var row = await verification.AuthorizationRequests
            .AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.NotNull(row.ConsumedAt);
        Assert.Equal(firstInstant.UtcTicks / 10, row.ConsumedAt.Value.UtcTicks / 10);

        // An expired handle is never consumable, and expiry is not recorded as consumption.
        await using (var expiredContext = new IdentityDbContext(options))
        {
            var store = CreateStore(expiredContext);
            var expiredCreation = await store.CreateAsync(
                CreateAccepted(applicationId),
                DateTimeOffset.UtcNow.AddMinutes(-30),
                TestContext.Current.CancellationToken);
            Assert.False(await store.TryConsumeAsync(
                expiredCreation.LoginHandle,
                DateTimeOffset.UtcNow,
                TestContext.Current.CancellationToken));
            Assert.False(await store.TryConsumeAsync(
                new string('b', 43),
                DateTimeOffset.UtcNow,
                TestContext.Current.CancellationToken));

            var expiredRow = await expiredContext.AuthorizationRequests
                .AsNoTracking()
                .SingleAsync(item => item.Id == expiredCreation.Id, TestContext.Current.CancellationToken);
            Assert.Null(expiredRow.ConsumedAt);
        }
    }

    /// <summary>
    /// <c>EV-01</c> composition and <c>EV-18</c> direction one: inside a caller-owned transaction
    /// the consumption joins it — a rollback before commit leaves the row unconsumed and still
    /// consumable, a commit makes the consumption authoritative.
    /// </summary>
    [Fact]
    public async Task TryConsume_InsideAmbientTransaction_CommitsAndRollbacksWithCaller()
    {
        await using var database = new SqliteFileDatabase();
        var options = await database.InitializeAsync();
        var applicationId = await SeedApplicationAsync(options);
        var createdAt = DateTimeOffset.UtcNow.AddMinutes(-1);

        string rollbackHandle;
        string commitHandle;
        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            rollbackHandle = (await store.CreateAsync(
                CreateAccepted(applicationId), createdAt, TestContext.Current.CancellationToken)).LoginHandle;
            commitHandle = (await store.CreateAsync(
                CreateAccepted(applicationId), createdAt, TestContext.Current.CancellationToken)).LoginHandle;
        }

        var consumeInstant = createdAt.AddMinutes(1);

        await using (var rollbackContext = new IdentityDbContext(options))
        {
            var store = CreateStore(rollbackContext);
            var strategy = rollbackContext.Database.CreateExecutionStrategy();
            await strategy.ExecuteAsync(async () =>
            {
                await using var transaction = await rollbackContext.Database.BeginTransactionAsync(
                    TestContext.Current.CancellationToken);
                Assert.True(await store.TryConsumeAsync(
                    rollbackHandle, consumeInstant, TestContext.Current.CancellationToken));
                await transaction.RollbackAsync(TestContext.Current.CancellationToken);
            });

            await AssertUnconsumedAsync(options, rollbackHandle);

            // The rolled-back row is still live: the later standalone consumption succeeds.
            Assert.True(await store.TryConsumeAsync(
                rollbackHandle, consumeInstant, TestContext.Current.CancellationToken));
        }

        await using (var commitContext = new IdentityDbContext(options))
        {
            var store = CreateStore(commitContext);
            var strategy = commitContext.Database.CreateExecutionStrategy();
            await strategy.ExecuteAsync(async () =>
            {
                await using var transaction = await commitContext.Database.BeginTransactionAsync(
                    TestContext.Current.CancellationToken);
                Assert.True(await store.TryConsumeAsync(
                    commitHandle, consumeInstant, TestContext.Current.CancellationToken));
                await transaction.CommitAsync(TestContext.Current.CancellationToken);
            });

            Assert.False(await store.TryConsumeAsync(
                commitHandle, consumeInstant.AddSeconds(1), TestContext.Current.CancellationToken));
        }

        await AssertConsumedAtAsync(options, commitHandle, consumeInstant);
    }

    /// <summary>
    /// AC-9 / <c>SC-20</c>, both directions at the commit boundary: cancellation observed before the
    /// commit rolls the consumption back (the row stays unconsumed); cancellation observed after the
    /// commit leaves the committed consumption authoritative.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TryConsume_CommitCancellation_PreservesAtomicConsumption(bool afterCommit)
    {
        await using var database = new SqliteFileDatabase();
        var options = await database.InitializeAsync();
        var applicationId = await SeedApplicationAsync(options);
        var createdAt = DateTimeOffset.UtcNow.AddMinutes(-1);

        string handle;
        await using (var seedContext = new IdentityDbContext(options))
        {
            handle = (await CreateStore(seedContext).CreateAsync(
                CreateAccepted(applicationId),
                createdAt,
                TestContext.Current.CancellationToken)).LoginHandle;
        }

        using var cancellation = new CancellationTokenSource();
        var interceptor = new CommitCancellationInterceptor(cancellation, afterCommit);
        var consumeInstant = createdAt.AddMinutes(1);

        await using (var context = new IdentityDbContext(database.BuildOptions(interceptor)))
        {
            var store = CreateStore(context);
            var operation = () => store.TryConsumeAsync(
                handle, consumeInstant, cancellation.Token);
            if (afterCommit)
            {
                Assert.True(await operation());
            }
            else
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(operation);
            }
        }

        Assert.Equal(1, interceptor.CommitAttempts);
        if (afterCommit)
        {
            await AssertConsumedAtAsync(options, handle, consumeInstant);
        }
        else
        {
            await AssertUnconsumedAsync(options, handle);

            // The rolled-back row remains consumable afterwards.
            await using var recoveryContext = new IdentityDbContext(options);
            Assert.True(await CreateStore(recoveryContext).TryConsumeAsync(
                handle, consumeInstant, TestContext.Current.CancellationToken));
        }
    }

    /// <summary>
    /// AC-8: instance B recovers instance A's row through the shared database alone. The store's
    /// only dependencies are the repository and the unit of work — no cookie, no Data Protection,
    /// no protected blob takes part in the recovery.
    /// </summary>
    [Fact]
    public async Task GetActive_AcrossInstances_RecoversFromSharedDatabaseOnly()
    {
        var constructor = Assert.Single(typeof(AuthorizationRequestStore).GetConstructors());
        Assert.Equal(
            [typeof(IAuthorizationRequestRepository), typeof(IUnitOfWork)],
            constructor.GetParameters().Select(parameter => parameter.ParameterType));

        await using var database = new SqliteFileDatabase();
        var instanceAOptions = await database.InitializeAsync();
        var applicationId = await SeedApplicationAsync(instanceAOptions);
        var now = DateTimeOffset.UtcNow;

        AuthorizationRequestCreation creation;
        await using (var instanceA = new IdentityDbContext(instanceAOptions))
        {
            creation = await CreateStore(instanceA).CreateAsync(
                CreateAccepted(applicationId), now, TestContext.Current.CancellationToken);
        }

        // Instance B: an independently built context over the same shared database.
        var instanceBOptions = database.BuildOptions();
        await using (var instanceB = new IdentityDbContext(instanceBOptions))
        {
            var store = CreateStore(instanceB);
            var recovered = await store.GetActiveAsync(
                creation.LoginHandle, now.AddMinutes(1), TestContext.Current.CancellationToken);
            Assert.NotNull(recovered);
            Assert.Equal(creation.Id, recovered.Id);
            Assert.Equal(applicationId, recovered.AppRegistrationId);
            Assert.Equal(RegisteredRedirectUri, recovered.RedirectUri);
            Assert.Equal(CanonicalScope, recovered.Scope);
            Assert.Equal(StateCanary, recovered.State);
            Assert.Equal(NonceCanary, recovered.Nonce);
            Assert.Equal(CodeChallenge, recovered.CodeChallenge);

            Assert.True(await store.TryConsumeAsync(
                creation.LoginHandle, now.AddMinutes(2), TestContext.Current.CancellationToken));
        }

        // Instance A observes the consumption instance B committed.
        await using (var instanceA = new IdentityDbContext(instanceAOptions))
        {
            Assert.Null(await CreateStore(instanceA).GetActiveAsync(
                creation.LoginHandle, now.AddMinutes(3), TestContext.Current.CancellationToken));
        }
    }

    /// <summary>
    /// AC-11 / <c>DF-05</c>: with identifiable plaintext handle, state, and nonce driving every
    /// path — creation (including a failing foreign-key creation), active lookup, missing lookup,
    /// consumption, repeated consumption, and cleanup — the plaintext handle appears in no table,
    /// the state/nonce snapshots appear only in their own columns, the audit tables stay empty, and
    /// no exception message carries any of the sensitive values.
    /// </summary>
    [Fact]
    public async Task SensitiveValues_NeverLeakAcrossAnyPath()
    {
        await using var database = new SqliteFileDatabase();
        var options = await database.InitializeAsync();
        var applicationId = await SeedApplicationAsync(options);
        var now = DateTimeOffset.UtcNow;
        var observedExceptions = new List<string>();

        string handle;
        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            var cancellationToken = TestContext.Current.CancellationToken;
            handle = (await store.CreateAsync(
                CreateAccepted(applicationId), now, cancellationToken)).LoginHandle;

            // A creation that violates the restrictive client reference must fail without leaking
            // the snapshot values through the exception.
            try
            {
                await store.CreateAsync(
                    CreateAccepted(Guid.NewGuid()), now, cancellationToken);
                Assert.Fail("Creating a continuation for an unknown application must fail.");
            }
            catch (Exception exception)
            {
                observedExceptions.Add(exception.ToString());
            }

            await store.GetActiveAsync(handle, now.AddMinutes(1), cancellationToken);
            await store.GetActiveAsync(
                "missing-but-well-formed-0123456789abcdefghi", now, cancellationToken);
            Assert.True(await store.TryConsumeAsync(handle, now.AddMinutes(2), cancellationToken));
            Assert.False(await store.TryConsumeAsync(handle, now.AddMinutes(3), cancellationToken));
            // Cleanup runs against the retention cutoff; the fresh rows stay so the scan below
            // proves the snapshots exist exactly in their own columns and nowhere else.
            await store.CleanupExpiredAsync(now, cancellationToken);
        }

        var dumps = await DumpTablesAsync(options);
        var wholeDatabase = string.Concat(dumps.Values);
        Assert.DoesNotContain(handle, wholeDatabase);
        Assert.Contains(StateCanary, dumps["authorization_requests"]);
        Assert.Contains(NonceCanary, dumps["authorization_requests"]);
        Assert.DoesNotContain(StateCanary, dumps["service_audit_logs"] + dumps["login_histories"]);
        Assert.Equal(string.Empty, dumps["service_audit_logs"]);
        Assert.Equal(string.Empty, dumps["login_histories"]);
        foreach (var (table, dump) in dumps)
        {
            if (table != "authorization_requests")
            {
                Assert.DoesNotContain(StateCanary, dump);
                Assert.DoesNotContain(NonceCanary, dump);
            }
        }

        foreach (var message in observedExceptions)
        {
            Assert.DoesNotContain(handle, message);
            Assert.DoesNotContain(StateCanary, message);
            Assert.DoesNotContain(NonceCanary, message);
        }
    }

    /// <summary>
    /// AC-12: cleanup deletes only rows expired beyond the retention window, keeps rows inside
    /// their lifetime or inside the window (consumed or not), never nulls a reference to enable a
    /// delete, keeps the restrictive client reference enforced, and rolls the whole unit back when
    /// cancellation arrives before the commit.
    /// </summary>
    [Fact]
    public async Task Cleanup_RemovesOnlyPastRetention_KeepsReferences_AndRollsBackAsOneUnit()
    {
        await using var database = new SqliteFileDatabase();
        var options = await database.InitializeAsync();
        var applicationId = await SeedApplicationAsync(options);
        var now = DateTimeOffset.UtcNow;

        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            var cancellationToken = TestContext.Current.CancellationToken;

            // Expired beyond the 24h retention window: deleted.
            await store.CreateAsync(
                CreateAccepted(applicationId),
                now.AddHours(-(IdentityConstants.AuthorizationRequestRetentionHours + 1)),
                cancellationToken);
            // Expired inside the retention window: kept.
            await store.CreateAsync(CreateAccepted(applicationId), now.AddHours(-2), cancellationToken);
            // Still live: kept.
            await store.CreateAsync(CreateAccepted(applicationId), now, cancellationToken);
            // Consumed, expired inside the window: kept — a committed consumption stays recorded.
            var consumedInsideCreatedAt = now.AddHours(-3);
            var consumedInside = await store.CreateAsync(
                CreateAccepted(applicationId), consumedInsideCreatedAt, cancellationToken);
            Assert.True(await store.TryConsumeAsync(
                consumedInside.LoginHandle, consumedInsideCreatedAt.AddMinutes(1), cancellationToken));
            // Consumed, expired beyond the window: deleted.
            var consumedBeyondCreatedAt =
                now.AddHours(-(IdentityConstants.AuthorizationRequestRetentionHours + 6));
            var consumedBeyond = await store.CreateAsync(
                CreateAccepted(applicationId),
                consumedBeyondCreatedAt,
                cancellationToken);
            Assert.True(await store.TryConsumeAsync(
                consumedBeyond.LoginHandle,
                consumedBeyondCreatedAt.AddMinutes(1),
                cancellationToken));

            var deleted = await store.CleanupExpiredAsync(now, cancellationToken);
            Assert.Equal(2, deleted);

            var survivors = await context.AuthorizationRequests
                .AsNoTracking()
                .ToListAsync(cancellationToken);
            Assert.Equal(3, survivors.Count);
            Assert.All(survivors, row => Assert.Equal(applicationId, row.AppRegistrationId));
            Assert.Contains(survivors, row => row.Id == consumedInside.Id);

            // The restrictive reference is never nulled or cascaded away: deleting the application
            // while continuation rows exist fails at the database. The tracker is cleared first so
            // the failure is the database's RESTRICT enforcement, not EF's client-side cascade check.
            context.ChangeTracker.Clear();
            var application = await context.AppRegistrations
                .SingleAsync(app => app.Id == applicationId, cancellationToken);
            context.AppRegistrations.Remove(application);
            await Assert.ThrowsAsync<DbUpdateException>(
                () => context.SaveChangesAsync(cancellationToken));
        }

        // A cancellation observed before the cleanup commit rolls the whole unit back.
        await using var rollbackDatabase = new SqliteFileDatabase();
        var rollbackOptions = await rollbackDatabase.InitializeAsync();
        var rollbackApplicationId = await SeedApplicationAsync(rollbackOptions);
        var rollbackNow = DateTimeOffset.UtcNow;

        string rollbackHandle;
        await using (var seedContext = new IdentityDbContext(rollbackOptions))
        {
            rollbackHandle = (await CreateStore(seedContext).CreateAsync(
                CreateAccepted(rollbackApplicationId),
                rollbackNow.AddHours(-48),
                TestContext.Current.CancellationToken)).LoginHandle;
        }

        using var cancellation = new CancellationTokenSource();
        var interceptor = new CommitCancellationInterceptor(cancellation, afterCommit: false);
        await using (var cleanupContext = new IdentityDbContext(rollbackDatabase.BuildOptions(interceptor)))
        {
            var store = CreateStore(cleanupContext);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => store.CleanupExpiredAsync(rollbackNow, cancellation.Token));
        }

        Assert.Equal(1, interceptor.CommitAttempts);
        await using var verification = new IdentityDbContext(rollbackOptions);
        var rolledBackRow = await verification.AuthorizationRequests
            .AsNoTracking()
            .SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(LoginHandleDigest.Compute(rollbackHandle), rolledBackRow.HandleDigest);
    }

    private static OidcAuthorizationValidationResult.Accepted CreateAccepted(Guid applicationId) => new(
        ClientId,
        applicationId,
        RegisteredRedirectUri,
        CanonicalScope,
        StateCanary,
        NonceCanary,
        CodeChallenge);

    private static AuthorizationRequestStore CreateStore(IdentityDbContext context) => new(
        new AuthorizationRequestRepository(context),
        new EfCoreUnitOfWork(context));

    private static void AssertLoginHandleShape(string handle)
    {
        Assert.Equal(IdentityConstants.LoginHandleLength, handle.Length);
        Assert.All(handle, character =>
            Assert.True(
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_',
                $"Unexpected login_handle character '{character}'."));
    }

    private static async Task<Guid> SeedApplicationAsync(
        DbContextOptions<IdentityDbContext> options)
    {
        await using var context = new IdentityDbContext(options);
        var application = new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = ClientId,
            AppSecretHash = "hash",
            AppName = "Continuation Contract",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
        context.AppRegistrations.Add(application);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        return application.Id;
    }

    private static async Task AssertUnconsumedAsync(
        DbContextOptions<IdentityDbContext> options,
        string handle)
    {
        await using var context = new IdentityDbContext(options);
        var row = await context.AuthorizationRequests
            .AsNoTracking()
            .SingleAsync(
                item => item.HandleDigest == LoginHandleDigest.Compute(handle),
                TestContext.Current.CancellationToken);
        Assert.Null(row.ConsumedAt);
    }

    private static async Task AssertConsumedAtAsync(
        DbContextOptions<IdentityDbContext> options,
        string handle,
        DateTimeOffset expectedInstant)
    {
        await using var context = new IdentityDbContext(options);
        var row = await context.AuthorizationRequests
            .AsNoTracking()
            .SingleAsync(
                item => item.HandleDigest == LoginHandleDigest.Compute(handle),
                TestContext.Current.CancellationToken);
        Assert.NotNull(row.ConsumedAt);
        Assert.Equal(expectedInstant.UtcTicks / 10, row.ConsumedAt.Value.UtcTicks / 10);
    }

    /// <summary>
    /// Dumps every user table into <c>column=value</c> text so sensitive-value scans cover the whole
    /// database rather than the columns a test happens to know about.
    /// </summary>
    private static async Task<Dictionary<string, string>> DumpTablesAsync(
        DbContextOptions<IdentityDbContext> options)
    {
        await using var context = new IdentityDbContext(options);
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        var connection = context.Database.GetDbConnection();

        var tableNames = new List<string>();
        await using (var tableCommand = connection.CreateCommand())
        {
            tableCommand.CommandText =
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name";
            await using var reader = await tableCommand.ExecuteReaderAsync(
                TestContext.Current.CancellationToken);
            while (await reader.ReadAsync(TestContext.Current.CancellationToken))
            {
                tableNames.Add(reader.GetString(0));
            }
        }

        var dumps = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var tableName in tableNames)
        {
            var dump = new StringBuilder();
            await using var command = connection.CreateCommand();
            command.CommandText = $"SELECT * FROM \"{tableName}\"";
            await using var reader = await command.ExecuteReaderAsync(
                TestContext.Current.CancellationToken);
            while (await reader.ReadAsync(TestContext.Current.CancellationToken))
            {
                for (var ordinal = 0; ordinal < reader.FieldCount; ordinal++)
                {
                    dump.Append(reader.GetName(ordinal))
                        .Append('=')
                        .Append(reader.IsDBNull(ordinal) ? "NULL" : reader.GetValue(ordinal))
                        .Append('|');
                }

                dump.AppendLine();
            }

            dumps[tableName] = dump.ToString();
        }

        return dumps;
    }

    private sealed class SqliteFileDatabase : IAsyncDisposable
    {
        private readonly string _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-authz-request-{Guid.NewGuid():N}.db");

        public DbContextOptions<IdentityDbContext> BuildOptions(IInterceptor? interceptor = null)
        {
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(new DatabaseOptions
            {
                Provider = "SQLite",
                ConnectionString = $"Data Source={_databasePath};Default Timeout=30"
            });
            if (interceptor != null)
            {
                optionsBuilder.AddInterceptors(interceptor);
            }

            return optionsBuilder.Options;
        }

        public async Task<DbContextOptions<IdentityDbContext>> InitializeAsync()
        {
            var options = BuildOptions();
            await using var context = new IdentityDbContext(options);
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
            return options;
        }

        public ValueTask DisposeAsync()
        {
            TestSqlitePools.ClearAll();
            if (File.Exists(_databasePath))
            {
                File.Delete(_databasePath);
            }

            return ValueTask.CompletedTask;
        }
    }

    private sealed class CommitCancellationInterceptor(
        CancellationTokenSource cancellation,
        bool afterCommit) : DbTransactionInterceptor
    {
        public int CommitAttempts { get; private set; }

        public override ValueTask<InterceptionResult> TransactionCommittingAsync(
            DbTransaction transaction,
            TransactionEventData eventData,
            InterceptionResult result,
            CancellationToken cancellationToken = default)
        {
            CommitAttempts++;
            if (!afterCommit)
            {
                cancellation.Cancel();
                cancellationToken.ThrowIfCancellationRequested();
            }

            return ValueTask.FromResult(result);
        }

        public override Task TransactionCommittedAsync(
            DbTransaction transaction,
            TransactionEndEventData eventData,
            CancellationToken cancellationToken = default)
        {
            cancellation.Cancel();
            return Task.CompletedTask;
        }
    }
}
