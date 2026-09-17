using System.Data.Common;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.IntegrationTests.Integration;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The SQLite half of the <c>PS-04</c> identity-session contract: the exact fresh schema, the
/// additive upgrade with a symmetric <c>Down</c>, the creation shape and credential-ownership
/// proof, the five-way classification under one captured instant, the bounded activity slide, the
/// first-write-wins revocation, ambient-transaction participation and the lock precondition, the
/// single-instance form of the concurrency outcomes, cross-instance recovery, the commit-boundary
/// cancellation and replay semantics, the retention cleanup, and the <c>DF-06</c> guarantee that
/// no session id reaches an exception string. The PostgreSQL half — the real concurrency and
/// locking matrix — lives in <see cref="ServerDatabaseContractTests"/>.
/// <para>
/// The <c>DatabaseContractTests</c> suffix is deliberate: CI's Database Contract Test stage
/// filters on <c>FullyQualifiedName~DatabaseContractTests</c>, and this group needs no Docker.
/// Multi-instance SQLite is not supported (<c>PS-22</c>); "another instance" here means another
/// options-built context over the same file, which is the single-writer recovery shape.
/// </para>
/// </summary>
public sealed class IdentitySessionDatabaseContractTests
{
    private const string Username = "session-contract-user";

    // ---- Acceptance 1: the fresh SQLite schema ----

    [Fact]
    public async Task FreshDatabase_MatchesThePs04SchemaContract()
    {
        await using var database = new SqliteSessionDatabase();
        var options = await database.InitializeAsync();
        await using var context = new IdentityDbContext(options);

        // The exact 10-column set, in order, with nullability and the provider storage types.
        var columns = await ReadPragmaAsync(context, "PRAGMA table_info(identity_sessions)");
        Assert.Equal(
            new[]
            {
                ("id", "TEXT", true),
                ("account_id", "TEXT", true),
                ("password_credential_id", "TEXT", true),
                ("auth_method", "TEXT", true),
                ("auth_time", "INTEGER", true),
                ("last_seen_at", "INTEGER", true),
                ("idle_expires_at", "INTEGER", true),
                ("absolute_expires_at", "INTEGER", true),
                ("revoked_at", "INTEGER", false),
                ("revocation_reason", "TEXT", false)
            },
            columns.Select(row => (row[1], row[2], row[3] == "1")).ToArray());

        // The lookup indexes on both restrictive references exist.
        var indexNames = await ReadPragmaAsync(context, "PRAGMA index_list(identity_sessions)");
        var indexedColumns = new List<string>();
        foreach (var index in indexNames)
        {
            var indexColumns = await ReadPragmaAsync(context, $"PRAGMA index_info(\"{index[1]}\")");
            if (indexColumns.Count == 1)
            {
                indexedColumns.Add(indexColumns[0][2]);
            }
        }

        Assert.Contains("account_id", indexedColumns);
        Assert.Contains("password_credential_id", indexedColumns);

        // PS-23: both references are restrictive; nothing cascades.
        var foreignKeys = await ReadPragmaAsync(context, "PRAGMA foreign_key_list(identity_sessions)");
        Assert.Equal(2, foreignKeys.Count);
        Assert.Contains(foreignKeys, key =>
            key[2] == "accounts" && key[3] == "account_id" && key[4] == "id"
            && string.Equals(key[6], "RESTRICT", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(foreignKeys, key =>
            key[2] == "password_credentials" && key[3] == "password_credential_id" && key[4] == "id"
            && string.Equals(key[6], "RESTRICT", StringComparison.OrdinalIgnoreCase));

        // The revocation pairing check exists in the DDL...
        var ddl = await ReadScalarAsync(
            context,
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'identity_sessions'");
        Assert.Contains("CK_identity_sessions_revocation_pair", ddl, StringComparison.Ordinal);

        // ...and is enforced: half of the revocation pair fails, the full pair and the empty pair
        // both succeed.
        var (accountId, credentialId) = await SeedAccountWithCredentialAsync(options);
        await AssertHalfPairRejectedAsync(context, accountId, credentialId, revokedAtOnly: true);
        await AssertHalfPairRejectedAsync(context, accountId, credentialId, revokedAtOnly: false);

        // Orphan references fail in both directions.
        await AssertOrphanRejectedAsync(context, accountId, credentialId, orphanAccount: true);
        await AssertOrphanRejectedAsync(context, accountId, credentialId, orphanAccount: false);

        // Deleting a referenced account or credential fails without cascading.
        context.ChangeTracker.Clear();
        context.IdentitySessions.Add(CreateValidSession(accountId, credentialId));
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);

        context.ChangeTracker.Clear();
        var account = await context.Accounts
            .SingleAsync(row => row.Id == accountId, TestContext.Current.CancellationToken);
        context.Accounts.Remove(account);
        await Assert.ThrowsAsync<DbUpdateException>(() =>
            context.SaveChangesAsync(TestContext.Current.CancellationToken));
        context.ChangeTracker.Clear();

        var credential = await context.PasswordCredentials
            .SingleAsync(row => row.Id == credentialId, TestContext.Current.CancellationToken);
        context.PasswordCredentials.Remove(credential);
        await Assert.ThrowsAsync<DbUpdateException>(() =>
            context.SaveChangesAsync(TestContext.Current.CancellationToken));
        context.ChangeTracker.Clear();

        Assert.Single(await context.IdentitySessions
            .AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    // ---- Acceptance 2: the additive upgrade and symmetric Down ----

    [Fact]
    public async Task UpgradeFromAddAuthorizationRequests_IsAdditiveAndDownIsSymmetric()
    {
        const string preSessionMigration = "20260916073317_AddAuthorizationRequests";
        // The migration under test, pinned: later migrations in the chain legitimately change
        // refresh_tokens (the family columns), which is not this migration's contract.
        const string sessionMigration = "20260916103412_AddIdentitySessions";
        await using var database = new SqliteSessionDatabase();
        var options = database.BuildOptions();
        await using var context = new IdentityDbContext(options);
        var cancellationToken = TestContext.Current.CancellationToken;
        var migrator = context.GetService<IMigrator>();
        await migrator.MigrateAsync(preSessionMigration, cancellationToken);

        var createdAt = DateTimeOffset.UtcNow;
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var appId = Guid.NewGuid();
        var tokenId = Guid.NewGuid();
        var tokenDigest = RefreshTokenDigest.Compute("session-upgrade-token");
        var handle = "session-upgrade-handle-0123456789abcdefghijk";

        context.Accounts.Add(new AccountEntity
        {
            Id = accountId, IsActive = true, CreatedAt = createdAt
        });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = credentialId, AccountId = accountId, Username = Username,
            PasswordHash = "hash", CreatedAt = createdAt
        });
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = appId, AppId = "session-upgrade-app", AppSecretHash = "hash",
            AppName = "Session Upgrade", IsActive = true, CreatedAt = createdAt
        });
        context.AuthorizationRequests.Add(new AuthorizationRequestEntity
        {
            Id = Guid.NewGuid(),
            HandleDigest = LoginHandleDigest.Compute(handle),
            AppRegistrationId = appId,
            RedirectUri = "https://client.example.test/callback",
            Scope = "openid",
            State = "upgrade-state",
            Nonce = "upgrade-nonce",
            CodeChallenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            CreatedAt = createdAt,
            ExpiresAt = createdAt.AddMinutes(IdentityConstants.LoginHandleLifetimeMinutes)
        });
        await context.SaveChangesAsync(cancellationToken);

        // The legacy token row is seeded with raw SQL: the migration version under test predates
        // the family columns a current-EF-model INSERT would name.
        await RefreshTokenFamilyTestSupport.InsertLegacyRefreshTokenSqliteAsync(
            context, tokenId, accountId, tokenDigest, createdAt, createdAt.AddHours(1),
            "session-upgrade-app");

        var accountsBefore = await GetSqliteColumnsAsync(context, "accounts");
        var credentialsBefore = await GetSqliteColumnsAsync(context, "password_credentials");
        var appsBefore = await GetSqliteColumnsAsync(context, "app_registrations");
        var tokensBefore = await GetSqliteColumnsAsync(context, "refresh_tokens");
        var continuationsBefore = await GetSqliteColumnsAsync(context, "authorization_requests");
        Assert.False(await SqliteTableExistsAsync(context, "identity_sessions"));

        await migrator.MigrateAsync(sessionMigration, cancellationToken);

        Assert.True(await SqliteTableExistsAsync(context, "identity_sessions"));
        Assert.Empty(await context.IdentitySessions.AsNoTracking().ToListAsync(cancellationToken));
        Assert.True(accountsBefore.SetEquals(await GetSqliteColumnsAsync(context, "accounts")));
        Assert.True(credentialsBefore.SetEquals(await GetSqliteColumnsAsync(context, "password_credentials")));
        Assert.True(appsBefore.SetEquals(await GetSqliteColumnsAsync(context, "app_registrations")));
        Assert.True(tokensBefore.SetEquals(await GetSqliteColumnsAsync(context, "refresh_tokens")));
        Assert.True(continuationsBefore.SetEquals(await GetSqliteColumnsAsync(context, "authorization_requests")));
        await AssertSeedUnchangedAsync(
            context, accountId, credentialId, appId, tokenId, tokenDigest, handle, createdAt);

        context.ChangeTracker.Clear();
        await migrator.MigrateAsync(preSessionMigration, cancellationToken);
        Assert.False(await SqliteTableExistsAsync(context, "identity_sessions"));
        Assert.True(accountsBefore.SetEquals(await GetSqliteColumnsAsync(context, "accounts")));
        Assert.True(credentialsBefore.SetEquals(await GetSqliteColumnsAsync(context, "password_credentials")));
        Assert.True(appsBefore.SetEquals(await GetSqliteColumnsAsync(context, "app_registrations")));
        Assert.True(tokensBefore.SetEquals(await GetSqliteColumnsAsync(context, "refresh_tokens")));
        Assert.True(continuationsBefore.SetEquals(await GetSqliteColumnsAsync(context, "authorization_requests")));
        await AssertSeedUnchangedAsync(
            context, accountId, credentialId, appId, tokenId, tokenDigest, handle, createdAt);

        await migrator.MigrateAsync(sessionMigration, cancellationToken);
        Assert.True(await SqliteTableExistsAsync(context, "identity_sessions"));
    }

    // ---- Acceptance 3: creation ----

    [Fact]
    public async Task Creation_FixesTheSessionShape_AndProvesCredentialOwnership()
    {
        await using var database = new SqliteSessionDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId) = await SeedAccountWithCredentialAsync(options);
        var (_, otherCredentialId) = await SeedAccountWithCredentialAsync(options, "session-contract-other");
        var now = Microsecond(DateTimeOffset.UtcNow);

        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            var before = await DumpTablesAsync(options);

            var foreign = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                store.CreateAsync(accountId, otherCredentialId, now, TestContext.Current.CancellationToken));
            var missing = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                store.CreateAsync(accountId, Guid.NewGuid(), now, TestContext.Current.CancellationToken));

            // Zero writes for both refusals, and the messages name no identifier (DF-06/DF-13).
            Assert.Equal(before, await DumpTablesAsync(options));
            foreach (var exception in new[] { foreign, missing })
            {
                var text = exception.ToString();
                Assert.DoesNotContain(accountId.ToString(), text, StringComparison.Ordinal);
                Assert.DoesNotContain(otherCredentialId.ToString(), text, StringComparison.Ordinal);
                Assert.DoesNotContain(credentialId.ToString(), text, StringComparison.Ordinal);
            }

            // 25 creations produce 25 distinct fresh ids and the fixed PS-04 shape.
            var ids = new HashSet<Guid>();
            for (var index = 0; index < 25; index++)
            {
                var session = await store.CreateAsync(
                    accountId, credentialId, now, TestContext.Current.CancellationToken);
                Assert.True(ids.Add(session.Id));
                Assert.Equal(accountId, session.AccountId);
                Assert.Equal(credentialId, session.PasswordCredentialId);
                Assert.Equal(IdentityConstants.AuthMethodPassword, session.AuthMethod);
                Assert.Equal(now, session.AuthTime);
                Assert.Equal(now, session.LastSeenAt);
                Assert.Equal(
                    now.AddMinutes(IdentityConstants.IdentitySessionIdleTimeoutMinutes),
                    session.IdleExpiresAt);
                Assert.Equal(
                    now.AddSeconds(IdentityConstants.MaxIdentitySessionAgeSeconds),
                    session.AbsoluteExpiresAt);
                Assert.Null(session.RevokedAt);
                Assert.Null(session.RevocationReason);
            }

            var rows = await context.IdentitySessions.AsNoTracking()
                .ToListAsync(TestContext.Current.CancellationToken);
            Assert.Equal(25, rows.Count);
            Assert.Equal(25, rows.Select(row => row.Id).Distinct().Count());
        }
    }

    // ---- Acceptance 4: classification under one captured instant ----

    [Fact]
    public async Task Get_ClassifiesUnderOneCapturedInstant_WithZeroWrites()
    {
        await using var database = new SqliteSessionDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId) = await SeedAccountWithCredentialAsync(options);
        var authTime = Microsecond(DateTimeOffset.UtcNow.AddHours(-1));
        var idle = authTime.AddMinutes(IdentityConstants.IdentitySessionIdleTimeoutMinutes);
        var absolute = authTime.AddSeconds(IdentityConstants.MaxIdentitySessionAgeSeconds);

        Guid sessionId;
        await using (var context = new IdentityDbContext(options))
        {
            sessionId = (await CreateStore(context).CreateAsync(
                accountId, credentialId, authTime, TestContext.Current.CancellationToken)).Id;
        }

        // A capped row whose idle deadline equals the absolute deadline reports the absolute
        // expiry, and a revoked row stays revoked whatever the expiry columns say.
        var cappedId = await InsertSessionAsync(
            options, accountId, credentialId, authTime,
            session => session.IdleExpiresAt = session.AbsoluteExpiresAt);
        var revokedId = await InsertSessionAsync(
            options, accountId, credentialId, authTime,
            session =>
            {
                session.IdleExpiresAt = authTime.AddMinutes(1);
                session.RevokedAt = authTime.AddMinutes(2);
                session.RevocationReason = "logout";
            });

        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            var before = await DumpTablesAsync(options);

            var active = await store.GetAsync(sessionId, idle.AddTicks(-10), TestContext.Current.CancellationToken);
            Assert.Equal(IdentitySessionState.Active, active.State);
            Assert.NotNull(active.Session);

            // The boundary is inclusive: the instant equal to the deadline is already expired.
            var idleExpired = await store.GetAsync(sessionId, idle, TestContext.Current.CancellationToken);
            Assert.Equal(IdentitySessionState.IdleExpired, idleExpired.State);

            var pastIdleBeforeAbsolute = await store.GetAsync(sessionId, absolute.AddTicks(-10), TestContext.Current.CancellationToken);
            Assert.Equal(IdentitySessionState.IdleExpired, pastIdleBeforeAbsolute.State);

            var absoluteExpired = await store.GetAsync(sessionId, absolute, TestContext.Current.CancellationToken);
            Assert.Equal(IdentitySessionState.AbsoluteExpired, absoluteExpired.State);

            var capped = await store.GetAsync(cappedId, absolute, TestContext.Current.CancellationToken);
            Assert.Equal(IdentitySessionState.AbsoluteExpired, capped.State);

            var revoked = await store.GetAsync(revokedId, absolute, TestContext.Current.CancellationToken);
            Assert.Equal(IdentitySessionState.Revoked, revoked.State);

            var missing = await store.GetAsync(Guid.NewGuid(), DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
            Assert.Equal(IdentitySessionState.Missing, missing.State);
            Assert.Null(missing.Session);

            // Reads never write: expiry invented no revocation and touched no column.
            Assert.Equal(before, await DumpTablesAsync(options));
        }
    }

    // ---- Acceptance 5: the bounded activity slide ----

    [Fact]
    public async Task TouchActivity_SlidesOnlyStaleUsableRows_AndCapsAtTheAbsoluteDeadline()
    {
        await using var database = new SqliteSessionDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId) = await SeedAccountWithCredentialAsync(options);
        var authTime = Microsecond(DateTimeOffset.UtcNow.AddMinutes(-5));

        Guid staleId;
        await using (var context = new IdentityDbContext(options))
        {
            staleId = (await CreateStore(context).CreateAsync(
                accountId, credentialId, authTime, TestContext.Current.CancellationToken)).Id;
        }

        var revokedId = await InsertSessionAsync(
            options, accountId, credentialId, authTime,
            session =>
            {
                session.LastSeenAt = authTime;
                session.RevokedAt = authTime.AddMinutes(1);
                session.RevocationReason = "administrative";
            });
        var idleExpiredId = await InsertSessionAsync(
            options, accountId, credentialId, authTime.AddHours(-1),
            session => session.IdleExpiresAt = authTime.AddMinutes(-30));
        var absoluteExpiredId = await InsertSessionAsync(
            options, accountId, credentialId, authTime.AddHours(-13),
            session =>
            {
                session.IdleExpiresAt = authTime.AddHours(-12);
                session.AbsoluteExpiresAt = authTime.AddHours(-1);
            });
        var nearAbsoluteId = await InsertSessionAsync(
            options, accountId, credentialId, authTime,
            session =>
            {
                session.LastSeenAt = authTime.AddMinutes(3);
                session.IdleExpiresAt = authTime.AddMinutes(10);
                session.AbsoluteExpiresAt = authTime.AddMinutes(20);
            });

        // The immutable columns of every row, captured before any update path runs.
        var immutableBefore = new Dictionary<Guid, (DateTimeOffset AuthTime, DateTimeOffset Absolute)>();
        foreach (var id in new[] { staleId, revokedId, idleExpiredId, absoluteExpiredId, nearAbsoluteId })
        {
            var row = await GetRowAsync(options, id);
            immutableBefore[id] = (row.AuthTime, row.AbsoluteExpiresAt);
        }

        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            var cancellationToken = TestContext.Current.CancellationToken;

            // Younger than the one-minute threshold: no write at all.
            var youngInstant = authTime.AddMinutes(1).AddTicks(-10);
            var beforeYoung = await DumpTablesAsync(options);
            Assert.Equal(
                IdentitySessionActivityResult.NotStale,
                await store.TouchActivityAsync(staleId, youngInstant, cancellationToken));
            Assert.Equal(beforeYoung, await DumpTablesAsync(options));

            // Exactly at the threshold: touched, and the idle deadline slides by the fixed timeout.
            var touchInstant = authTime.AddMinutes(1);
            Assert.Equal(
                IdentitySessionActivityResult.Touched,
                await store.TouchActivityAsync(staleId, touchInstant, cancellationToken));
            var touched = await GetRowAsync(options, staleId);
            Assert.Equal(touchInstant, touched.LastSeenAt);
            Assert.Equal(
                touchInstant.AddMinutes(IdentityConstants.IdentitySessionIdleTimeoutMinutes),
                touched.IdleExpiresAt);
            Assert.Equal(
                authTime.AddSeconds(IdentityConstants.MaxIdentitySessionAgeSeconds),
                touched.AbsoluteExpiresAt);
            Assert.Equal(authTime, touched.AuthTime);

            // A second touch inside the same minute window writes nothing.
            Assert.Equal(
                IdentitySessionActivityResult.NotStale,
                await store.TouchActivityAsync(staleId, touchInstant, cancellationToken));
            Assert.Equal(touchInstant, (await GetRowAsync(options, staleId)).LastSeenAt);

            // The slide is capped at the row's own absolute deadline.
            var nearInstant = authTime.AddMinutes(5);
            Assert.Equal(
                IdentitySessionActivityResult.Touched,
                await store.TouchActivityAsync(nearAbsoluteId, nearInstant, cancellationToken));
            var capped = await GetRowAsync(options, nearAbsoluteId);
            Assert.Equal(capped.AbsoluteExpiresAt, capped.IdleExpiresAt);
            Assert.True(capped.IdleExpiresAt <= capped.AbsoluteExpiresAt);

            // Unusable rows are answered without a write.
            var beforeUnusable = await DumpTablesAsync(options);
            foreach (var unusable in new[] { revokedId, idleExpiredId, absoluteExpiredId, Guid.NewGuid() })
            {
                Assert.Equal(
                    IdentitySessionActivityResult.Unavailable,
                    await store.TouchActivityAsync(unusable, nearInstant, cancellationToken));
            }

            Assert.Equal(beforeUnusable, await DumpTablesAsync(options));

            // The immutable columns survived every path.
            foreach (var (id, before) in immutableBefore)
            {
                var row = await GetRowAsync(options, id);
                Assert.Equal(before.AuthTime, row.AuthTime);
                Assert.Equal(before.Absolute, row.AbsoluteExpiresAt);
            }
        }
    }

    // ---- Acceptance 6: revocation ----

    [Fact]
    public async Task Revocation_FirstWriteIsAuthoritative()
    {
        await using var database = new SqliteSessionDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId) = await SeedAccountWithCredentialAsync(options);
        var authTime = Microsecond(DateTimeOffset.UtcNow.AddHours(-1));

        Guid sessionId;
        await using (var context = new IdentityDbContext(options))
        {
            sessionId = (await CreateStore(context).CreateAsync(
                accountId, credentialId, authTime, TestContext.Current.CancellationToken)).Id;
        }

        // An expired-but-unrevoked row is still revocable: an explicit fact, no expiry rewrite.
        var expiredId = await InsertSessionAsync(
            options, accountId, credentialId, authTime.AddHours(-13),
            session =>
            {
                session.IdleExpiresAt = authTime.AddHours(-12);
                session.AbsoluteExpiresAt = authTime.AddHours(-1);
            });

        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            var cancellationToken = TestContext.Current.CancellationToken;
            var firstInstant = Microsecond(DateTimeOffset.UtcNow);
            var secondInstant = firstInstant.AddMinutes(1);

            Assert.Equal(
                IdentitySessionRevocationResult.Revoked,
                await store.RevokeAsync(
                    sessionId, IdentitySessionRevocationReason.Logout, firstInstant, cancellationToken));
            var afterFirst = await GetRowAsync(options, sessionId);
            Assert.Equal(firstInstant, afterFirst.RevokedAt);
            Assert.Equal("logout", afterFirst.RevocationReason);

            // A later revocation — whatever its reason — changes nothing.
            Assert.Equal(
                IdentitySessionRevocationResult.AlreadyRevoked,
                await store.RevokeAsync(
                    sessionId, IdentitySessionRevocationReason.CodeReplay, secondInstant, cancellationToken));
            var afterSecond = await GetRowAsync(options, sessionId);
            Assert.Equal(firstInstant, afterSecond.RevokedAt);
            Assert.Equal("logout", afterSecond.RevocationReason);

            var beforeMissing = await DumpTablesAsync(options);
            Assert.Equal(
                IdentitySessionRevocationResult.Missing,
                await store.RevokeAsync(
                    Guid.NewGuid(), IdentitySessionRevocationReason.Administrative, firstInstant, cancellationToken));
            Assert.Equal(beforeMissing, await DumpTablesAsync(options));

            Assert.Equal(
                IdentitySessionRevocationResult.Revoked,
                await store.RevokeAsync(
                    expiredId, IdentitySessionRevocationReason.Administrative, firstInstant, cancellationToken));
            var expiredRow = await GetRowAsync(options, expiredId);
            Assert.Equal(firstInstant, expiredRow.RevokedAt);
            Assert.Equal("administrative", expiredRow.RevocationReason);
            Assert.Equal(authTime.AddHours(-12), expiredRow.IdleExpiresAt);
            Assert.Equal(authTime.AddHours(-1), expiredRow.AbsoluteExpiresAt);

            // The third canonical reason stores its exact value.
            var thirdId = await InsertSessionAsync(options, accountId, credentialId, authTime);
            Assert.Equal(
                IdentitySessionRevocationResult.Revoked,
                await store.RevokeAsync(
                    thirdId, IdentitySessionRevocationReason.CodeReplay, firstInstant, cancellationToken));
            Assert.Equal("code_replay", (await GetRowAsync(options, thirdId)).RevocationReason);
        }
    }

    // ---- Acceptance 7: ambient transactions and the lock precondition ----

    [Fact]
    public async Task WriteOperations_JoinTheCallerTransaction_AndLockingRequiresOne()
    {
        await using var database = new SqliteSessionDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId) = await SeedAccountWithCredentialAsync(options);
        var authTime = Microsecond(DateTimeOffset.UtcNow.AddMinutes(-5));

        Guid staleId;
        Guid revokeId;
        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            staleId = (await store.CreateAsync(
                accountId, credentialId, authTime, TestContext.Current.CancellationToken)).Id;
            revokeId = (await store.CreateAsync(
                accountId, credentialId, authTime, TestContext.Current.CancellationToken)).Id;
        }

        var now = Microsecond(DateTimeOffset.UtcNow);
        var before = await DumpTablesAsync(options);

        // Rollback: the created row vanishes, the touch and the revocation leave no trace.
        await RunInTransactionAsync(options, async (context, transaction) =>
        {
            var store = CreateStore(context);
            await store.CreateAsync(accountId, credentialId, now, TestContext.Current.CancellationToken);
            Assert.Equal(
                IdentitySessionActivityResult.Touched,
                await store.TouchActivityAsync(staleId, now, TestContext.Current.CancellationToken));
            Assert.Equal(
                IdentitySessionRevocationResult.Revoked,
                await store.RevokeAsync(
                    revokeId, IdentitySessionRevocationReason.Logout, now, TestContext.Current.CancellationToken));
            await transaction.RollbackAsync(TestContext.Current.CancellationToken);
        });
        Assert.Equal(before, await DumpTablesAsync(options));

        // Commit: all three writes become visible together.
        var createdId = Guid.Empty;
        await RunInTransactionAsync(options, async (context, transaction) =>
        {
            var store = CreateStore(context);
            createdId = (await store.CreateAsync(
                accountId, credentialId, now, TestContext.Current.CancellationToken)).Id;
            Assert.Equal(
                IdentitySessionActivityResult.Touched,
                await store.TouchActivityAsync(staleId, now, TestContext.Current.CancellationToken));
            Assert.Equal(
                IdentitySessionRevocationResult.Revoked,
                await store.RevokeAsync(
                    revokeId, IdentitySessionRevocationReason.Logout, now, TestContext.Current.CancellationToken));
            await transaction.CommitAsync(TestContext.Current.CancellationToken);
        });
        var committedCreated = await GetRowAsync(options, createdId);
        Assert.Equal(now, committedCreated.AuthTime);
        Assert.Equal(now, (await GetRowAsync(options, staleId)).LastSeenAt);
        Assert.Equal(now, (await GetRowAsync(options, revokeId)).RevokedAt);

        // The lock requires a caller-owned transaction...
        await using (var locklessContext = new IdentityDbContext(options))
        {
            var store = CreateStore(locklessContext);
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                store.LockAsync(staleId, TestContext.Current.CancellationToken));
            Assert.DoesNotContain(staleId.ToString(), exception.ToString(), StringComparison.Ordinal);
        }

        // ...and inside one it returns the row (SQLite: a plain read under the file-level writer
        // lock), or null for a missing id.
        await RunInTransactionAsync(options, async (context, transaction) =>
        {
            var store = CreateStore(context);
            var locked = await store.LockAsync(staleId, TestContext.Current.CancellationToken);
            Assert.NotNull(locked);
            Assert.Equal(staleId, locked!.Id);
            Assert.Null(await store.LockAsync(Guid.NewGuid(), TestContext.Current.CancellationToken));
            await transaction.RollbackAsync(TestContext.Current.CancellationToken);
        });
    }

    // ---- Acceptance 9: the single-instance form of the concurrency outcomes ----

    [Fact]
    public async Task SingleInstance_SequentialOperations_ReachTheSameOutcomes()
    {
        await using var database = new SqliteSessionDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId) = await SeedAccountWithCredentialAsync(options);
        var authTime = Microsecond(DateTimeOffset.UtcNow.AddMinutes(-5));

        Guid staleId;
        Guid revokeTargetId;
        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            staleId = (await store.CreateAsync(
                accountId, credentialId, authTime, TestContext.Current.CancellationToken)).Id;
            revokeTargetId = (await store.CreateAsync(
                accountId, credentialId, authTime, TestContext.Current.CancellationToken)).Id;
        }

        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            var cancellationToken = TestContext.Current.CancellationToken;
            var firstNow = Microsecond(DateTimeOffset.UtcNow);
            var secondNow = firstNow.AddMilliseconds(50);

            // (a) Two activity updates inside the same minute window: exactly one writes.
            var results = new[]
            {
                await store.TouchActivityAsync(staleId, firstNow, cancellationToken),
                await store.TouchActivityAsync(staleId, secondNow, cancellationToken)
            };
            Assert.Equal(IdentitySessionActivityResult.Touched, results[0]);
            Assert.Equal(IdentitySessionActivityResult.NotStale, results[1]);
            Assert.Equal(firstNow, (await GetRowAsync(options, staleId)).LastSeenAt);

            // (b) Two revocations with different reasons: exactly one wins, its facts persist.
            var revocations = new[]
            {
                await store.RevokeAsync(
                    revokeTargetId, IdentitySessionRevocationReason.Logout, firstNow, cancellationToken),
                await store.RevokeAsync(
                    revokeTargetId, IdentitySessionRevocationReason.CodeReplay, secondNow, cancellationToken)
            };
            Assert.Equal(IdentitySessionRevocationResult.Revoked, revocations[0]);
            Assert.Equal(IdentitySessionRevocationResult.AlreadyRevoked, revocations[1]);
            var revokedRow = await GetRowAsync(options, revokeTargetId);
            Assert.Equal(firstNow, revokedRow.RevokedAt);
            Assert.Equal("logout", revokedRow.RevocationReason);
        }
    }

    // ---- Acceptance 10: cross-instance recovery and the dependency surface ----

    [Fact]
    public async Task AnotherInstance_RecoversUpdatesAndRevokes_WithoutAnyHttpSurface()
    {
        await using var database = new SqliteSessionDatabase();
        var optionsA = await database.InitializeAsync();
        var (accountId, credentialId) = await SeedAccountWithCredentialAsync(optionsA);
        var authTime = Microsecond(DateTimeOffset.UtcNow.AddMinutes(-5));

        Guid sessionId;
        await using (var contextA = new IdentityDbContext(optionsA))
        {
            sessionId = (await CreateStore(contextA).CreateAsync(
                accountId, credentialId, authTime, TestContext.Current.CancellationToken)).Id;
        }

        // Instance B builds its own options over the same database and recovers the session.
        var optionsB = database.BuildOptions();
        var now = Microsecond(DateTimeOffset.UtcNow);
        await using (var contextB = new IdentityDbContext(optionsB))
        {
            var storeB = CreateStore(contextB);
            var lookup = await storeB.GetAsync(sessionId, now, TestContext.Current.CancellationToken);
            Assert.Equal(IdentitySessionState.Active, lookup.State);
            Assert.Equal(
                IdentitySessionActivityResult.Touched,
                await storeB.TouchActivityAsync(sessionId, now, TestContext.Current.CancellationToken));
            Assert.Equal(
                IdentitySessionRevocationResult.Revoked,
                await storeB.RevokeAsync(
                    sessionId, IdentitySessionRevocationReason.Logout, now, TestContext.Current.CancellationToken));
        }

        await using (var contextA = new IdentityDbContext(optionsA))
        {
            var lookupA = await CreateStore(contextA).GetAsync(
                sessionId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
            Assert.Equal(IdentitySessionState.Revoked, lookupA.State);
            Assert.Equal(now, lookupA.Session!.RevokedAt);
            Assert.Equal(now, lookupA.Session.LastSeenAt);
        }

        // The store has no HTTP, cookie, or Data Protection surface at all.
        var constructor = Assert.Single(typeof(IdentitySessionStore).GetConstructors());
        foreach (var parameter in constructor.GetParameters())
        {
            var typeName = parameter.ParameterType.FullName ?? string.Empty;
            Assert.DoesNotContain("DataProtection", typeName, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Cookie", typeName, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("HttpContext", typeName, StringComparison.OrdinalIgnoreCase);
        }
    }

    // ---- Acceptance 11: commit-boundary cancellation and replay ----

    [Theory]
    [InlineData("create", false)]
    [InlineData("create", true)]
    [InlineData("touch", false)]
    [InlineData("touch", true)]
    [InlineData("revoke", false)]
    [InlineData("revoke", true)]
    [InlineData("cleanup", false)]
    [InlineData("cleanup", true)]
    public async Task Cancellation_AtTheCommitBoundary_IsBounded(string operation, bool afterCommit)
    {
        using var cancellation = new CancellationTokenSource();
        await using var database = new SqliteSessionDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId) = await SeedAccountWithCredentialAsync(options);
        var authTime = Microsecond(DateTimeOffset.UtcNow.AddMinutes(-5));
        var now = Microsecond(DateTimeOffset.UtcNow);

        Guid sessionId = Guid.Empty;
        if (operation is "touch" or "revoke")
        {
            await using var seedContext = new IdentityDbContext(options);
            sessionId = (await CreateStore(seedContext).CreateAsync(
                accountId, credentialId, authTime, TestContext.Current.CancellationToken)).Id;
        }

        if (operation == "cleanup")
        {
            // One row well beyond the retention window: the cleanup has something to delete.
            await InsertSessionAsync(
                options, accountId, credentialId, now.AddHours(-48),
                session =>
                {
                    session.IdleExpiresAt = now.AddHours(-30);
                    session.AbsoluteExpiresAt = now.AddHours(-36);
                });
        }

        // The commit boundary of a standalone creation is its SaveChanges, which carries no
        // interceptable transaction of its own; the shape production actually commits creation in
        // is the caller-owned ambient transaction (the EV-01 success transaction), so that is the
        // boundary this case cancels at. The update/delete operations own explicit transactions
        // inside the execution strategy and are cancelled at theirs.
        var commitInterceptor = new CommitCancellationInterceptor(cancellation, afterCommit);
        var interceptorOptions = database.BuildOptions(commitInterceptor);

        await using var context = new IdentityDbContext(interceptorOptions);
        var store = CreateStore(context);

        Func<Task> unit = operation switch
        {
            "create" => async () =>
            {
                await using var transaction = await context.Database
                    .BeginTransactionAsync(cancellation.Token);
                await store.CreateAsync(accountId, credentialId, now, cancellation.Token);
                await transaction.CommitAsync(cancellation.Token);
            },
            "touch" => async () => Assert.Equal(
                IdentitySessionActivityResult.Touched,
                await store.TouchActivityAsync(sessionId, now, cancellation.Token)),
            "revoke" => async () => Assert.Equal(
                IdentitySessionRevocationResult.Revoked,
                await store.RevokeAsync(
                    sessionId, IdentitySessionRevocationReason.Logout, now, cancellation.Token)),
            "cleanup" => async () => Assert.Equal(
                1,
                await store.CleanupExpiredAsync(now, cancellation.Token)),
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };

        if (afterCommit)
        {
            // The committed fact stays authoritative; the late cancellation may or may not surface.
            try
            {
                await unit();
            }
            catch (OperationCanceledException)
            {
            }
        }
        else
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(unit);
        }

        Assert.Equal(1, commitInterceptor.CommitAttempts);

        await using var verification = new IdentityDbContext(options);
        var rows = await verification.IdentitySessions.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken);
        switch (operation)
        {
            case "create":
                Assert.Equal(afterCommit ? 1 : 0, rows.Count);
                break;
            case "touch":
                var touchedRow = Assert.Single(rows);
                Assert.Equal(afterCommit ? now : authTime, touchedRow.LastSeenAt);
                break;
            case "revoke":
                var revokedRow = Assert.Single(rows);
                Assert.Equal(afterCommit, revokedRow.RevokedAt is not null);
                if (afterCommit)
                {
                    Assert.Equal(now, revokedRow.RevokedAt);
                    Assert.Equal("logout", revokedRow.RevocationReason);
                }

                break;
            case "cleanup":
                Assert.Equal(afterCommit ? 0 : 1, rows.Count);
                break;
        }
    }

    [Fact]
    public async Task TransientFailures_ReplayEachUnitExactlyOnce()
    {
        await using var database = new SqliteSessionDatabase();
        var plainOptions = await database.InitializeAsync();
        var (accountId, credentialId) = await SeedAccountWithCredentialAsync(plainOptions);
        var authTime = Microsecond(DateTimeOffset.UtcNow.AddMinutes(-5));

        // Creation: one injected INSERT failure, one committed row.
        var insertInterceptor = new TransientFailureInterceptor(
            "INSERT INTO \"identity_sessions\"", failuresToInject: 1);
        var insertOptions = database.BuildRetryingOptions(insertInterceptor);
        Guid createdId;
        await using (var context = new IdentityDbContext(insertOptions))
        {
            createdId = (await CreateStore(context).CreateAsync(
                accountId, credentialId, authTime, TestContext.Current.CancellationToken)).Id;
        }

        Assert.Equal(1, insertInterceptor.InjectedFailures);
        var created = await GetRowAsync(database.BuildOptions(), createdId);
        Assert.Equal(authTime, created.AuthTime);

        // Revocation: one injected UPDATE failure inside the explicit transaction, still exactly
        // one Revoked outcome and one stored reason.
        var updateInterceptor = new TransientFailureInterceptor(
            "UPDATE \"identity_sessions\"", failuresToInject: 1);
        var updateOptions = database.BuildRetryingOptions(updateInterceptor);
        await using (var context = new IdentityDbContext(updateOptions))
        {
            var store = CreateStore(context);
            Assert.Equal(
                IdentitySessionRevocationResult.Revoked,
                await store.RevokeAsync(
                    createdId, IdentitySessionRevocationReason.Logout,
                    DateTimeOffset.UtcNow, TestContext.Current.CancellationToken));
        }

        Assert.Equal(1, updateInterceptor.InjectedFailures);
        await using (var verification = new IdentityDbContext(database.BuildOptions()))
        {
            var store = CreateStore(verification);
            Assert.Equal(
                IdentitySessionRevocationResult.AlreadyRevoked,
                await store.RevokeAsync(
                    createdId, IdentitySessionRevocationReason.CodeReplay,
                    DateTimeOffset.UtcNow, TestContext.Current.CancellationToken));
            var rows = await verification.IdentitySessions.AsNoTracking()
                .ToListAsync(TestContext.Current.CancellationToken);
            var row = Assert.Single(rows);
            Assert.Equal("logout", row.RevocationReason);
        }
    }

    // ---- Acceptance 12: the retention cleanup ----

    [Fact]
    public async Task Cleanup_DeletesOnlyBeyondTheRetentionWindow_AsOneUnit()
    {
        await using var database = new SqliteSessionDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId) = await SeedAccountWithCredentialAsync(options);
        var now = Microsecond(DateTimeOffset.UtcNow);
        var cutoff = now.AddHours(-IdentityConstants.IdentitySessionRetentionHours);

        // Deleted: idle-expired beyond the window.
        await InsertSessionAsync(options, accountId, credentialId, cutoff.AddHours(-3),
            session => session.IdleExpiresAt = cutoff.AddMinutes(-1));
        // Deleted: revoked beyond the window (even though its idle deadline is in the future).
        await InsertSessionAsync(options, accountId, credentialId, cutoff.AddHours(-3),
            session =>
            {
                session.IdleExpiresAt = now.AddMinutes(10);
                session.RevokedAt = cutoff.AddMinutes(-1);
                session.RevocationReason = "logout";
            });
        // Kept: idle-expired inside the window.
        await InsertSessionAsync(options, accountId, credentialId, cutoff.AddHours(-1),
            session => session.IdleExpiresAt = cutoff.AddMinutes(1));
        // Kept: revoked inside the window (and its idle deadline is inside the window too).
        await InsertSessionAsync(options, accountId, credentialId, cutoff.AddHours(-1),
            session =>
            {
                session.IdleExpiresAt = cutoff.AddMinutes(1);
                session.RevokedAt = cutoff.AddMinutes(1);
                session.RevocationReason = "administrative";
            });
        // Kept: unexpired.
        await InsertSessionAsync(options, accountId, credentialId, now.AddMinutes(-1));

        await using (var context = new IdentityDbContext(options))
        {
            var deleted = await CreateStore(context).CleanupExpiredAsync(
                now, TestContext.Current.CancellationToken);
            Assert.Equal(2, deleted);
        }

        var remaining = await CountRowsAsync(options);
        Assert.Equal(3, remaining);

        // A cancelled cleanup rolls the whole unit back.
        using var cancellation = new CancellationTokenSource();
        var cancelledOptions = database.BuildOptions(
            new CommitCancellationInterceptor(cancellation, afterCommit: false));
        await using (var context = new IdentityDbContext(cancelledOptions))
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                CreateStore(context).CleanupExpiredAsync(
                    now.AddHours(25), cancellation.Token));
        }

        Assert.Equal(3, await CountRowsAsync(options));
    }

    // ---- Acceptance 13: no session id in any exception string ----

    [Fact]
    public async Task SessionIds_NeverReachExceptionStrings()
    {
        await using var database = new SqliteSessionDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId) = await SeedAccountWithCredentialAsync(options);
        var (_, otherCredentialId) = await SeedAccountWithCredentialAsync(options, "session-contract-other");
        var now = Microsecond(DateTimeOffset.UtcNow);
        var exceptions = new List<Exception>();
        var sessionIds = new List<Guid>();

        await using var context = new IdentityDbContext(options);
        var store = CreateStore(context);

        var created = await store.CreateAsync(
            accountId, credentialId, now, TestContext.Current.CancellationToken);
        sessionIds.Add(created.Id);

        exceptions.Add(await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.CreateAsync(
                accountId, otherCredentialId, now, TestContext.Current.CancellationToken)));

        exceptions.Add(await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.LockAsync(created.Id, TestContext.Current.CancellationToken)));

        using (var cancellation = new CancellationTokenSource())
        {
            var cancelledOptions = database.BuildOptions(
                new CommitCancellationInterceptor(cancellation, afterCommit: false));
            await using var cancelledContext = new IdentityDbContext(cancelledOptions);
            var cancelledStore = CreateStore(cancelledContext);
            exceptions.Add(await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                cancelledStore.RevokeAsync(
                    created.Id, IdentitySessionRevocationReason.Logout, now, cancellation.Token)));
        }

        // The scan is proven non-empty by the captured exceptions themselves.
        Assert.Equal(3, exceptions.Count);
        Assert.All(exceptions, exception =>
        {
            var text = exception.ToString();
            Assert.All(sessionIds, id =>
            {
                Assert.DoesNotContain(id.ToString("D"), text, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(id.ToString("N"), text, StringComparison.OrdinalIgnoreCase);
            });
        });
    }

    // ---- Helpers ----

    /// <summary>
    /// The SQLite mapping stores instants as Unix microseconds, so every test instant that is
    /// later compared against a stored value is truncated to that grid first; a 100-nanosecond
    /// clock (Linux CI) would otherwise make the exact-equality assertions platform-dependent.
    /// Derived instants (AddMinutes etc.) keep the truncation.
    /// </summary>
    private static DateTimeOffset Microsecond(DateTimeOffset value) =>
        new(value.UtcTicks / 10 * 10, TimeSpan.Zero);

    private static IdentitySessionStore CreateStore(IdentityDbContext context) => new(
        new IdentitySessionRepository(context),
        new EfCoreUnitOfWork(context));

    private static async Task<(Guid AccountId, Guid CredentialId)> SeedAccountWithCredentialAsync(
        DbContextOptions<IdentityDbContext> options,
        string username = Username)
    {
        await using var context = new IdentityDbContext(options);
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = credentialId,
            AccountId = accountId,
            Username = username,
            PasswordHash = "hash",
            CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        return (accountId, credentialId);
    }

    private static IdentitySessionEntity CreateValidSession(
        Guid accountId,
        Guid credentialId,
        DateTimeOffset? authTime = null)
    {
        var now = Microsecond(authTime ?? DateTimeOffset.UtcNow);
        return new IdentitySessionEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            PasswordCredentialId = credentialId,
            AuthMethod = IdentityConstants.AuthMethodPassword,
            AuthTime = now,
            LastSeenAt = now,
            IdleExpiresAt = now.AddMinutes(IdentityConstants.IdentitySessionIdleTimeoutMinutes),
            AbsoluteExpiresAt = now.AddSeconds(IdentityConstants.MaxIdentitySessionAgeSeconds)
        };
    }

    private static async Task<Guid> InsertSessionAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid accountId,
        Guid credentialId,
        DateTimeOffset? authTime = null,
        Action<IdentitySessionEntity>? mutate = null)
    {
        var session = CreateValidSession(accountId, credentialId, authTime);
        mutate?.Invoke(session);
        await using var context = new IdentityDbContext(options);
        context.IdentitySessions.Add(session);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        return session.Id;
    }

    private static async Task<IdentitySessionEntity> GetRowAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid sessionId)
    {
        await using var context = new IdentityDbContext(options);
        return await context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == sessionId, TestContext.Current.CancellationToken);
    }

    private static async Task<int> CountRowsAsync(DbContextOptions<IdentityDbContext> options)
    {
        await using var context = new IdentityDbContext(options);
        return await context.IdentitySessions
            .AsNoTracking()
            .CountAsync(TestContext.Current.CancellationToken);
    }

    private static async Task RunInTransactionAsync(
        DbContextOptions<IdentityDbContext> options,
        Func<IdentityDbContext, IDbContextTransaction, Task> action)
    {
        await using var context = new IdentityDbContext(options);
        await using var transaction = await context.Database
            .BeginTransactionAsync(TestContext.Current.CancellationToken);
        await action(context, transaction);
    }

    private static async Task AssertHalfPairRejectedAsync(
        IdentityDbContext context,
        Guid accountId,
        Guid credentialId,
        bool revokedAtOnly)
    {
        var session = CreateValidSession(accountId, credentialId);
        if (revokedAtOnly)
        {
            session.RevokedAt = DateTimeOffset.UtcNow;
        }
        else
        {
            session.RevocationReason = "logout";
        }

        context.IdentitySessions.Add(session);
        await Assert.ThrowsAsync<DbUpdateException>(() =>
            context.SaveChangesAsync(TestContext.Current.CancellationToken));
        context.ChangeTracker.Clear();
    }

    private static async Task AssertOrphanRejectedAsync(
        IdentityDbContext context,
        Guid accountId,
        Guid credentialId,
        bool orphanAccount)
    {
        var session = CreateValidSession(
            orphanAccount ? Guid.NewGuid() : accountId,
            orphanAccount ? credentialId : Guid.NewGuid());
        context.IdentitySessions.Add(session);
        await Assert.ThrowsAsync<DbUpdateException>(() =>
            context.SaveChangesAsync(TestContext.Current.CancellationToken));
        context.ChangeTracker.Clear();
    }

    private static async Task AssertSeedUnchangedAsync(
        IdentityDbContext context,
        Guid accountId,
        Guid credentialId,
        Guid appId,
        Guid tokenId,
        string tokenDigest,
        string handle,
        DateTimeOffset createdAt)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var account = await context.Accounts.AsNoTracking()
            .SingleAsync(row => row.Id == accountId, cancellationToken);
        Assert.True(account.IsActive);
        Assert.Equal(createdAt.UtcTicks / 10, account.CreatedAt.UtcTicks / 10);

        var credential = await context.PasswordCredentials.AsNoTracking()
            .SingleAsync(row => row.Id == credentialId, cancellationToken);
        Assert.Equal(Username, credential.Username);
        Assert.Equal("hash", credential.PasswordHash);
        Assert.Equal(createdAt.UtcTicks / 10, credential.CreatedAt.UtcTicks / 10);

        var application = await context.AppRegistrations.AsNoTracking()
            .SingleAsync(row => row.Id == appId, cancellationToken);
        Assert.Equal("session-upgrade-app", application.AppId);
        Assert.Equal("hash", application.AppSecretHash);
        Assert.True(application.IsActive);
        Assert.Equal(createdAt.UtcTicks / 10, application.CreatedAt.UtcTicks / 10);

        // The Down state predates the family columns, so the token row is read with raw SQL
        // instead of the current EF model.
        var token = await RefreshTokenFamilyTestSupport.ReadRefreshTokenRowSqliteAsync(
            context, tokenId);
        Assert.Equal(tokenDigest, token.TokenValue);
        Assert.False(token.IsRevoked);
        Assert.Equal(
            RefreshTokenFamilyTestSupport.ToSqliteMicroseconds(createdAt),
            RefreshTokenFamilyTestSupport.ToSqliteMicroseconds(token.CreatedAt));

        var continuation = await context.AuthorizationRequests.AsNoTracking()
            .SingleAsync(row => row.HandleDigest == LoginHandleDigest.Compute(handle), cancellationToken);
        Assert.Equal(appId, continuation.AppRegistrationId);
        Assert.Null(continuation.ConsumedAt);
        Assert.Equal(createdAt.UtcTicks / 10, continuation.CreatedAt.UtcTicks / 10);
    }

    private static async Task<List<string[]>> ReadPragmaAsync(
        IdentityDbContext context,
        string pragma)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = pragma;
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        var rows = new List<string[]>();
        while (await reader.ReadAsync(TestContext.Current.CancellationToken))
        {
            var row = new string[reader.FieldCount];
            for (var ordinal = 0; ordinal < reader.FieldCount; ordinal++)
            {
                row[ordinal] = reader.IsDBNull(ordinal) ? string.Empty : reader.GetValue(ordinal)?.ToString() ?? string.Empty;
            }

            rows.Add(row);
        }

        return rows;
    }

    private static async Task<string> ReadScalarAsync(IdentityDbContext context, string sql)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = sql;
        return (string?)await command.ExecuteScalarAsync(TestContext.Current.CancellationToken)
            ?? string.Empty;
    }

    private static async Task<bool> SqliteTableExistsAsync(IdentityDbContext context, string tableName)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = $name";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "$name";
        parameter.Value = tableName;
        command.Parameters.Add(parameter);
        return Convert.ToInt64(
            await command.ExecuteScalarAsync(TestContext.Current.CancellationToken)) > 0;
    }

    private static async Task<HashSet<string>> GetSqliteColumnsAsync(
        IdentityDbContext context,
        string tableName)
    {
        var rows = await ReadPragmaAsync(context, $"PRAGMA table_info({tableName})");
        return rows.Select(row => row[1]).ToHashSet(StringComparer.Ordinal);
    }

    /// <summary>
    /// Dumps every user table into <c>column=value</c> text so the zero-write proofs cover the
    /// whole database rather than the columns a test happens to know about.
    /// </summary>
    private static async Task<string> DumpTablesAsync(DbContextOptions<IdentityDbContext> options)
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

        var dump = new StringBuilder();
        foreach (var tableName in tableNames)
        {
            dump.Append("## ").AppendLine(tableName);
            await using var command = connection.CreateCommand();
            command.CommandText = $"SELECT * FROM \"{tableName}\" ORDER BY 1";
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
        }

        return dump.ToString();
    }

    /// <summary>
    /// A file-backed SQLite test database on the production migration chain, onto which a
    /// retrying execution strategy and interceptors are attached as needed.
    /// </summary>
    private sealed class SqliteSessionDatabase : IAsyncDisposable
    {
        private readonly string _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-identity-session-{Guid.NewGuid():N}.db");

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

        /// <summary>
        /// The replay-matrix options: SQLite has no <c>EnableRetryOnFailure</c>, so a retrying
        /// strategy is installed by hand, equivalent to <c>RetriesOnFailure == true</c> under the
        /// production PostgreSQL configuration.
        /// </summary>
        public DbContextOptions<IdentityDbContext> BuildRetryingOptions(IInterceptor interceptor)
        {
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseSqlite(
                $"Data Source={_databasePath};Default Timeout=30",
                providerOptions =>
                {
                    providerOptions.MigrationsAssembly("SignaCore.Database.Migrations.Sqlite");
                    providerOptions.ExecutionStrategy(
                        dependencies => new TestRetryingExecutionStrategy(dependencies));
                });
            optionsBuilder.AddInterceptors(interceptor);
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
            SqliteConnection.ClearAllPools();
            if (File.Exists(_databasePath))
            {
                File.Delete(_databasePath);
            }

            return ValueTask.CompletedTask;
        }
    }

    private sealed class TestRetryingExecutionStrategy : ExecutionStrategy
    {
        public TestRetryingExecutionStrategy(ExecutionStrategyDependencies dependencies)
            : base(dependencies, maxRetryCount: 3, maxRetryDelay: TimeSpan.FromMilliseconds(1))
        {
        }

        protected override bool ShouldRetryOn(Exception exception)
        {
            return exception is InjectedTransientException
                || exception.InnerException is InjectedTransientException;
        }
    }

    private sealed class InjectedTransientException : Exception
    {
        public InjectedTransientException()
            : base("Injected transient database failure.")
        {
        }
    }

    private sealed class TransientFailureInterceptor(string commandFragment, int failuresToInject)
        : DbCommandInterceptor
    {
        public int InjectedFailures { get; private set; }

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfShouldFail(command);
            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            // The SQLite provider runs its INSERT/UPDATE statements through a reader (it appends
            // the changes() probe), so the injection point must cover both shapes.
            ThrowIfShouldFail(command);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }

        private void ThrowIfShouldFail(DbCommand command)
        {
            if (InjectedFailures >= failuresToInject
                || !command.CommandText.Contains(commandFragment, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            InjectedFailures++;
            throw new InjectedTransientException();
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
