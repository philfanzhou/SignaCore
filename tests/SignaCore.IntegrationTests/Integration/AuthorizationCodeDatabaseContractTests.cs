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
/// The SQLite half of the <c>PS-05</c> authorization-code contract: the exact fresh schema, the
/// additive upgrade with a symmetric <c>Down</c>, the creation shape (plaintext returned once,
/// digest-only storage), the four-way classification under one captured instant, the RFC 7636
/// binding verification, the one-shot sequential consumption, ambient-transaction participation
/// and the session-then-code lock order, the single-instance form of the concurrency outcomes,
/// cross-instance recovery, the commit-boundary cancellation and replay semantics, the retention
/// cleanup including the session-reference coordination, and the <c>DF-03</c>/<c>DF-04</c>
/// guarantee that neither the plaintext code nor the PKCE verifier reaches storage or any
/// exception string. The PostgreSQL half — the real lock-order concurrency matrix — lives in
/// <see cref="ServerDatabaseContractTests"/>.
/// <para>
/// The <c>DatabaseContractTests</c> suffix is deliberate: CI's Database Contract Test stage
/// filters on <c>FullyQualifiedName~DatabaseContractTests</c>, and this group needs no Docker.
/// Multi-instance SQLite is not supported (<c>PS-22</c>); "another instance" here means another
/// options-built context over the same file, which is the single-writer recovery shape.
/// </para>
/// </summary>
public sealed class AuthorizationCodeDatabaseContractTests
{
    private const string Username = "code-contract-user";
    private const string ClientId = "code-contract-app";

    // RFC 7636 appendix B: the verifier and its BASE64URL(SHA256(verifier)) challenge.
    private const string Rfc7636Verifier =
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string Rfc7636Challenge =
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    // ---- Acceptance 1: the fresh SQLite schema ----

    [Fact]
    public async Task FreshDatabase_MatchesThePs05SchemaContract()
    {
        await using var database = new SqliteCodeDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId, appId) = await SeedAsync(options);
        var sessionId = await InsertSessionAsync(options, accountId, credentialId);

        await using var context = new IdentityDbContext(options);

        // The exact 14-column set with nullability and the provider storage types. The family
        // migration rebuilt this table on SQLite to add the deferred PS-23 reference, so the
        // physical column order is the rebuild's; the contract is the name set, not the order.
        var columns = await ReadPragmaAsync(context, "PRAGMA table_info(authorization_codes)");
        Assert.Equal(
            new HashSet<(string, string, bool)>
            {
                ("id", "TEXT", true),
                ("code_digest", "TEXT", true),
                ("app_registration_id", "TEXT", true),
                ("account_id", "TEXT", true),
                ("identity_session_id", "TEXT", true),
                ("redirect_uri", "TEXT", true),
                ("scope", "TEXT", true),
                ("nonce", "TEXT", true),
                ("code_challenge", "TEXT", true),
                ("auth_time", "INTEGER", true),
                ("created_at", "INTEGER", true),
                ("expires_at", "INTEGER", true),
                ("consumed_at", "INTEGER", false),
                ("refresh_family_id", "TEXT", false)
            },
            columns.Select(row => (row[1], row[2], row[3] == "1")).ToHashSet());

        // The unique code_digest index and the identity_session_id index exist.
        var indexNames = await ReadPragmaAsync(context, "PRAGMA index_list(authorization_codes)");
        var uniqueIndexedColumns = new HashSet<string>(StringComparer.Ordinal);
        var indexedColumns = new HashSet<string>(StringComparer.Ordinal);
        foreach (var index in indexNames)
        {
            var indexColumns = await ReadPragmaAsync(
                context, $"PRAGMA index_info(\"{index[1]}\")");
            if (indexColumns.Count == 1)
            {
                indexedColumns.Add(indexColumns[0][2]);
                if (string.Equals(index[2], "1", StringComparison.Ordinal))
                {
                    uniqueIndexedColumns.Add(indexColumns[0][2]);
                }
            }
        }

        Assert.Contains("code_digest", uniqueIndexedColumns);
        Assert.Contains("identity_session_id", indexedColumns);
        Assert.Contains("refresh_family_id", indexedColumns);

        // PS-23: the three table-creating references plus the deferred family-root reference
        // added by the family migration are restrictive; nothing cascades.
        var foreignKeys = await ReadPragmaAsync(
            context, "PRAGMA foreign_key_list(authorization_codes)");
        Assert.Equal(4, foreignKeys.Count);
        Assert.Contains(foreignKeys, key =>
            key[2] == "app_registrations" && key[3] == "app_registration_id" && key[4] == "id"
            && string.Equals(key[6], "RESTRICT", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(foreignKeys, key =>
            key[2] == "accounts" && key[3] == "account_id" && key[4] == "id"
            && string.Equals(key[6], "RESTRICT", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(foreignKeys, key =>
            key[2] == "identity_sessions" && key[3] == "identity_session_id" && key[4] == "id"
            && string.Equals(key[6], "RESTRICT", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(foreignKeys, key =>
            key[2] == "refresh_tokens" && key[3] == "refresh_family_id" && key[4] == "id"
            && string.Equals(key[6], "RESTRICT", StringComparison.OrdinalIgnoreCase));

        // The family/consumption pairing check exists in the DDL...
        var ddl = await ReadScalarAsync(
            context,
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'authorization_codes'");
        Assert.Contains(
            "CK_authorization_codes_family_requires_consumption", ddl, StringComparison.Ordinal);

        // ...and is enforced: a family link without consumption fails, while family-with-
        // consumption and the empty pair both succeed. The family link now also resolves the
        // deferred PS-23 reference, so the pairing cases link a real singleton root.
        var rootId = Guid.NewGuid();
        context.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = rootId,
            FamilyId = rootId,
            AccountId = accountId,
            TokenValue = RefreshTokenDigest.Compute("ps05-family-root-token"),
            CreatedAt = Microsecond(DateTimeOffset.UtcNow),
            ExpiresAt = Microsecond(DateTimeOffset.UtcNow).AddHours(1),
            AppId = ClientId
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();

        await AssertFamilyRejectedAsync(context, accountId, appId, sessionId, rootId);
        await InsertValidCodeAsync(
            context, accountId, appId, sessionId,
            code => code.RefreshFamilyId = rootId,
            consumed: true);
        context.ChangeTracker.Clear();

        // Orphan references fail in all three directions.
        await AssertOrphanRejectedAsync(context, accountId, appId, sessionId, "account");
        await AssertOrphanRejectedAsync(context, accountId, appId, sessionId, "app");
        await AssertOrphanRejectedAsync(context, accountId, appId, sessionId, "session");

        // Deleting a referenced account, application, or session fails without cascading.
        var referenced = await InsertValidCodeAsync(context, accountId, appId, sessionId);
        context.ChangeTracker.Clear();

        foreach (var target in new[] { "account", "app", "session" })
        {
            await AssertDeleteBlockedAsync(context, target,
                target == "account" ? accountId
                : target == "app" ? appId
                : sessionId);
        }

        Assert.NotNull(await context.AuthorizationCodes.AsNoTracking()
            .SingleAsync(code => code.Id == referenced.Id, TestContext.Current.CancellationToken));
        Assert.True(await context.IdentitySessions.AsNoTracking()
            .AnyAsync(session => session.Id == sessionId, TestContext.Current.CancellationToken));
    }

    // ---- Acceptance 2: the additive upgrade and symmetric Down ----

    [Fact]
    public async Task UpgradeFromAddIdentitySessions_IsAdditiveAndDownIsSymmetric()
    {
        const string preCodeMigration = "20260916103412_AddIdentitySessions";
        // The migration under test, pinned: later migrations in the chain legitimately change
        // refresh_tokens (the family columns), which is not this migration's contract.
        const string codeMigration = "20260916160633_AddAuthorizationCodes";
        await using var database = new SqliteCodeDatabase();
        var options = database.BuildOptions();
        await using var context = new IdentityDbContext(options);
        var cancellationToken = TestContext.Current.CancellationToken;
        var migrator = context.GetService<IMigrator>();
        await migrator.MigrateAsync(preCodeMigration, cancellationToken);

        var createdAt = Microsecond(DateTimeOffset.UtcNow);
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var appId = Guid.NewGuid();
        var tokenId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var tokenDigest = RefreshTokenDigest.Compute("code-upgrade-token");
        var handle = "code-upgrade-handle-0123456789abcdefghij";

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
            Id = appId, AppId = ClientId, AppSecretHash = "hash",
            AppName = "Code Upgrade", IsActive = true, CreatedAt = createdAt
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
            CodeChallenge = Rfc7636Challenge,
            CreatedAt = createdAt,
            ExpiresAt = createdAt.AddMinutes(IdentityConstants.LoginHandleLifetimeMinutes)
        });
        context.IdentitySessions.Add(CreateValidSession(accountId, credentialId, sessionId, createdAt));
        await context.SaveChangesAsync(cancellationToken);

        // The legacy token row is seeded with raw SQL: the migration version under test predates
        // the family columns a current-EF-model INSERT would name.
        await RefreshTokenFamilyTestSupport.InsertLegacyRefreshTokenSqliteAsync(
            context, tokenId, accountId, tokenDigest, createdAt, createdAt.AddHours(1), ClientId);

        var accountsBefore = await GetSqliteColumnsAsync(context, "accounts");
        var credentialsBefore = await GetSqliteColumnsAsync(context, "password_credentials");
        var appsBefore = await GetSqliteColumnsAsync(context, "app_registrations");
        var tokensBefore = await GetSqliteColumnsAsync(context, "refresh_tokens");
        var continuationsBefore = await GetSqliteColumnsAsync(context, "authorization_requests");
        var sessionsBefore = await GetSqliteColumnsAsync(context, "identity_sessions");
        Assert.False(await SqliteTableExistsAsync(context, "authorization_codes"));

        await migrator.MigrateAsync(codeMigration, cancellationToken);

        Assert.True(await SqliteTableExistsAsync(context, "authorization_codes"));
        Assert.Empty(await context.AuthorizationCodes.AsNoTracking().ToListAsync(cancellationToken));
        Assert.True(accountsBefore.SetEquals(await GetSqliteColumnsAsync(context, "accounts")));
        Assert.True(credentialsBefore.SetEquals(
            await GetSqliteColumnsAsync(context, "password_credentials")));
        Assert.True(appsBefore.SetEquals(await GetSqliteColumnsAsync(context, "app_registrations")));
        Assert.True(tokensBefore.SetEquals(await GetSqliteColumnsAsync(context, "refresh_tokens")));
        Assert.True(continuationsBefore.SetEquals(
            await GetSqliteColumnsAsync(context, "authorization_requests")));
        Assert.True(sessionsBefore.SetEquals(
            await GetSqliteColumnsAsync(context, "identity_sessions")));
        await AssertSeedUnchangedAsync(context, accountId, appId, tokenId, sessionId, tokenDigest);

        context.ChangeTracker.Clear();
        await migrator.MigrateAsync(preCodeMigration, cancellationToken);
        Assert.False(await SqliteTableExistsAsync(context, "authorization_codes"));
        Assert.True(sessionsBefore.SetEquals(
            await GetSqliteColumnsAsync(context, "identity_sessions")));
        await AssertSeedUnchangedAsync(context, accountId, appId, tokenId, sessionId, tokenDigest);

        await migrator.MigrateAsync(codeMigration, cancellationToken);
        Assert.True(await SqliteTableExistsAsync(context, "authorization_codes"));
    }

    // ---- Acceptance 3: creation ----

    [Fact]
    public async Task Creation_ReturnsThePlaintextOnce_AndStoresOnlyTheDigest()
    {
        await using var database = new SqliteCodeDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId, appId) = await SeedAsync(options);
        var authTime = Microsecond(DateTimeOffset.UtcNow.AddMinutes(-5));
        var now = Microsecond(DateTimeOffset.UtcNow);
        var cancellationToken = TestContext.Current.CancellationToken;

        var session = await CreateSessionViaStoreAsync(options, accountId, credentialId, authTime);

        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            var codes = new List<string>();
            var ids = new HashSet<Guid>();

            for (var index = 0; index < 25; index++)
            {
                var creation = await store.CreateAsync(
                    session, CreateBinding(appId), now, cancellationToken);
                Assert.True(ids.Add(creation.Id));
                Assert.Equal(IdentityConstants.AuthorizationCodeLength, creation.Code.Length);
                Assert.All(creation.Code, character =>
                    Assert.True(char.IsAsciiLetterOrDigit(character) || character is '-' or '_'));
                codes.Add(creation.Code);
            }

            Assert.Equal(25, codes.Distinct(StringComparer.Ordinal).Count());

            var rows = await context.AuthorizationCodes.AsNoTracking()
                .ToListAsync(cancellationToken);
            Assert.Equal(25, rows.Count);
            foreach (var row in rows)
            {
                var matchingCode = codes.Single(
                    code => AuthorizationCodeDigest.Compute(code) == row.CodeDigest);
                Assert.NotEmpty(matchingCode);
                Assert.Equal(accountId, row.AccountId);
                Assert.Equal(session.Id, row.IdentitySessionId);
                Assert.Equal(session.AuthTime, row.AuthTime);
                Assert.Equal(now, row.CreatedAt);
                Assert.Equal(
                    now.AddSeconds(IdentityConstants.AuthorizationCodeLifetimeSeconds),
                    row.ExpiresAt);
                Assert.Null(row.ConsumedAt);
                Assert.Null(row.RefreshFamilyId);
            }

            // The whole database carries no plaintext code (DF-03).
            var dump = await DumpTablesAsync(options);
            foreach (var code in codes)
            {
                Assert.DoesNotContain(code, dump, StringComparison.Ordinal);
            }
        }

        // Creation inside a caller-owned transaction that rolls back leaves no row.
        var countBefore = await CountCodesAsync(options);
        await RunInTransactionAsync(options, async (transactionContext, transaction) =>
        {
            await CreateStore(transactionContext).CreateAsync(
                session, CreateBinding(appId), now, cancellationToken);
            await transaction.RollbackAsync(cancellationToken);
        });

        Assert.Equal(countBefore, await CountCodesAsync(options));
    }

    // ---- Acceptance 4: classification under one captured instant ----

    [Fact]
    public async Task Find_ClassifiesUnderOneCapturedInstant_WithZeroWrites()
    {
        await using var database = new SqliteCodeDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId, appId) = await SeedAsync(options);
        var now = Microsecond(DateTimeOffset.UtcNow);
        var cancellationToken = TestContext.Current.CancellationToken;

        var session = await CreateSessionViaStoreAsync(options, accountId, credentialId, now);

        string unconsumedCode;
        string consumedCode;
        Guid consumedId;
        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            unconsumedCode = (await store.CreateAsync(
                session, CreateBinding(appId), now, cancellationToken)).Code;
            var consumedCreation = await store.CreateAsync(
                session, CreateBinding(appId), now, cancellationToken);
            consumedCode = consumedCreation.Code;
            consumedId = consumedCreation.Id;
            Assert.True(await store.TryConsumeAsync(consumedId, now.AddMilliseconds(1), cancellationToken));
        }

        // A row both consumed and past its expiry: still Consumed, never Expired or Missing (EV-24).
        string expiredConsumedCode;
        Guid expiredConsumedCreationId;
        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            var creation = await store.CreateAsync(session, CreateBinding(appId), now, cancellationToken);
            expiredConsumedCode = creation.Code;
            expiredConsumedCreationId = creation.Id;
        }

        var expiry = now.AddSeconds(IdentityConstants.AuthorizationCodeLifetimeSeconds);
        await using (var mutateContext = new IdentityDbContext(options))
        {
            var row = await mutateContext.AuthorizationCodes
                .SingleAsync(code => code.Id == expiredConsumedCreationId, cancellationToken);
            row.ExpiresAt = now.AddHours(-1);
            row.ConsumedAt = now.AddMinutes(-30);
            await mutateContext.SaveChangesAsync(cancellationToken);
        }

        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            var before = await DumpTablesAsync(options);

            // Malformed shapes and an unknown legal shape share the single Missing answer.
            foreach (var malformed in new[]
                     {
                         string.Empty,
                         "short",
                         "invalid!character-0123456789abcdefghijklmnopq",
                         "unknown-legal-shape-0123456789abcdefghijk"
                     })
            {
                var missing = await store.FindAsync(malformed, expiry, cancellationToken);
                Assert.Equal(AuthorizationCodeState.Missing, missing.State);
                Assert.Null(missing.Entity);
            }

            // One microsecond before the deadline: Unconsumed; at the deadline: Expired.
            var beforeExpiry = await store.FindAsync(
                unconsumedCode, expiry.AddTicks(-10), cancellationToken);
            Assert.Equal(AuthorizationCodeState.Unconsumed, beforeExpiry.State);
            Assert.NotNull(beforeExpiry.Entity);

            var atExpiry = await store.FindAsync(unconsumedCode, expiry, cancellationToken);
            Assert.Equal(AuthorizationCodeState.Expired, atExpiry.State);
            Assert.NotNull(atExpiry.Entity);

            // A consumed row is Consumed whatever the clock says.
            Assert.Equal(AuthorizationCodeState.Consumed,
                (await store.FindAsync(consumedCode, expiry, cancellationToken)).State);
            Assert.Equal(AuthorizationCodeState.Consumed,
                (await store.FindAsync(consumedCode, expiry.AddHours(1), cancellationToken)).State);
            Assert.Equal(AuthorizationCodeState.Consumed,
                (await store.FindAsync(expiredConsumedCode, expiry, cancellationToken)).State);

            // Reads never write.
            Assert.Equal(before, await DumpTablesAsync(options));
        }
    }

    // ---- Acceptance 5: the RFC 7636 binding verification ----

    [Fact]
    public void VerifyBinding_AcceptsTheRfc7636Vector_AndRejectsEveryMismatch()
    {
        var appId = Guid.NewGuid();
        var code = new AuthorizationCodeEntity
        {
            Id = Guid.NewGuid(),
            CodeDigest = AuthorizationCodeDigest.Compute("binding-code"),
            AppRegistrationId = appId,
            AccountId = Guid.NewGuid(),
            IdentitySessionId = Guid.NewGuid(),
            RedirectUri = "https://client.example.test/callback",
            Scope = "openid profile",
            Nonce = "binding-nonce",
            CodeChallenge = Rfc7636Challenge,
            AuthTime = DateTimeOffset.UtcNow,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(
                IdentityConstants.AuthorizationCodeLifetimeSeconds)
        };
        var store = new AuthorizationCodeStore(
            new MockRepository(), new MockUnitOfWork());

        // The RFC 7636 appendix B vector verifies.
        Assert.True(store.VerifyBinding(code, appId, code.RedirectUri, Rfc7636Verifier));

        // Wrong application, redirect case, trailing slash, and verifier value all fail.
        Assert.False(store.VerifyBinding(code, Guid.NewGuid(), code.RedirectUri, Rfc7636Verifier));
        Assert.False(store.VerifyBinding(
            code, appId, "https://CLIENT.example.test/callback", Rfc7636Verifier));
        Assert.False(store.VerifyBinding(
            code, appId, code.RedirectUri + "/", Rfc7636Verifier));

        var corrupted = Rfc7636Verifier.ToCharArray();
        corrupted[^1] = corrupted[^1] == 'k' ? 'j' : 'k';
        Assert.False(store.VerifyBinding(
            code, appId, code.RedirectUri, new string(corrupted)));

        // The IN-24 shape gate: 42 and 129 characters and an illegal character all fail.
        Assert.False(store.VerifyBinding(code, appId, code.RedirectUri, Rfc7636Verifier[1..]));
        Assert.False(store.VerifyBinding(
            code, appId, code.RedirectUri, Rfc7636Verifier + "padding-padding-padding!"));
        Assert.False(store.VerifyBinding(
            code, appId, code.RedirectUri, Rfc7636Verifier.Replace('_', '+')));
        Assert.False(store.VerifyBinding(code, appId, code.RedirectUri, string.Empty));
        Assert.Throws<ArgumentNullException>(() =>
            store.VerifyBinding(null!, appId, code.RedirectUri, Rfc7636Verifier));
    }

    // ---- Acceptance 6: sequential one-shot consumption ----

    [Fact]
    public async Task SequentialConsumption_IsOneShot_AndExpiryNeverConsumes()
    {
        await using var database = new SqliteCodeDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId, appId) = await SeedAsync(options);
        var now = Microsecond(DateTimeOffset.UtcNow);
        var cancellationToken = TestContext.Current.CancellationToken;

        var session = await CreateSessionViaStoreAsync(options, accountId, credentialId, now);
        Guid codeId;
        await using (var context = new IdentityDbContext(options))
        {
            codeId = (await CreateStore(context).CreateAsync(
                session, CreateBinding(appId), now, cancellationToken)).Id;
        }

        var expiredId = await InsertCodeAsync(
            options, accountId, appId, session.Id, now.AddHours(-1));

        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            var consumeInstant = now.AddMilliseconds(1);

            Assert.True(await store.TryConsumeAsync(codeId, consumeInstant, cancellationToken));
            var consumed = await GetCodeRowAsync(options, codeId);
            Assert.Equal(consumeInstant, consumed.ConsumedAt);

            var secondInstant = consumeInstant.AddMilliseconds(1);
            Assert.False(await store.TryConsumeAsync(codeId, secondInstant, cancellationToken));
            consumed = await GetCodeRowAsync(options, codeId);
            Assert.Equal(consumeInstant, consumed.ConsumedAt);

            // An expired unconsumed row is never consumed by the conditional update.
            Assert.False(await store.TryConsumeAsync(
                expiredId, DateTimeOffset.UtcNow, cancellationToken));
            Assert.Null((await GetCodeRowAsync(options, expiredId)).ConsumedAt);
        }
    }

    // ---- Acceptance 7: ambient transactions and the lock precondition ----

    [Fact]
    public async Task WriteOperations_JoinTheCallerTransaction_AndCodeLockKeepsTheSessionTracked()
    {
        await using var database = new SqliteCodeDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId, appId) = await SeedAsync(options);
        var now = Microsecond(DateTimeOffset.UtcNow);
        var cancellationToken = TestContext.Current.CancellationToken;

        // Rollback: the created code and its consumption vanish together.
        var before = await DumpTablesAsync(options);
        Guid rolledBackId = Guid.Empty;
        await RunInTransactionAsync(options, async (context, transaction) =>
        {
            var sessionStore = new IdentitySessionStore(
                new IdentitySessionRepository(context), new EfCoreUnitOfWork(context));
            var codeStore = CreateStore(context);
            var session = await sessionStore.CreateAsync(accountId, credentialId, now, cancellationToken);
            var creation = await codeStore.CreateAsync(
                session, CreateBinding(appId), now, cancellationToken);
            rolledBackId = creation.Id;
            Assert.True(await codeStore.TryConsumeAsync(creation.Id, now, cancellationToken));
            await transaction.RollbackAsync(cancellationToken);
        });
        Assert.Equal(before, await DumpTablesAsync(options));
        Assert.NotEqual(Guid.Empty, rolledBackId);

        // Commit: creation and consumption become visible together, and the row can no longer be
        // consumed again.
        Guid committedId = Guid.Empty;
        await RunInTransactionAsync(options, async (context, transaction) =>
        {
            var sessionStore = new IdentitySessionStore(
                new IdentitySessionRepository(context), new EfCoreUnitOfWork(context));
            var codeStore = CreateStore(context);
            var session = await sessionStore.CreateAsync(accountId, credentialId, now, cancellationToken);
            var creation = await codeStore.CreateAsync(
                session, CreateBinding(appId), now, cancellationToken);
            committedId = creation.Id;
            Assert.True(await codeStore.TryConsumeAsync(creation.Id, now, cancellationToken));
            await transaction.CommitAsync(cancellationToken);
        });
        Assert.NotNull((await GetCodeRowAsync(options, committedId)).ConsumedAt);

        // The lock requires a caller-owned transaction; the message names no id or code.
        await using (var locklessContext = new IdentityDbContext(options))
        {
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                CreateStore(locklessContext).LockAsync(committedId, cancellationToken));
            Assert.DoesNotContain(
                committedId.ToString(), exception.ToString(), StringComparison.Ordinal);
        }

        // Inside one, after the session lock the code lock returns the row while the session
        // entity stays tracked (EV-20 lock order).
        Guid lockedSessionId = Guid.Empty;
        await RunInTransactionAsync(options, async (context, transaction) =>
        {
            var sessionStore = new IdentitySessionStore(
                new IdentitySessionRepository(context), new EfCoreUnitOfWork(context));
            var codeStore = CreateStore(context);
            var session = await sessionStore.CreateAsync(accountId, credentialId, now, cancellationToken);
            var creation = await codeStore.CreateAsync(
                session, CreateBinding(appId), now, cancellationToken);
            lockedSessionId = session.Id;

            var lockedSession = await sessionStore.LockAsync(session.Id, cancellationToken);
            Assert.NotNull(lockedSession);
            var lockedCode = await codeStore.LockAsync(creation.Id, cancellationToken);
            Assert.NotNull(lockedCode);
            Assert.Equal(creation.Id, lockedCode!.Id);

            var entry = context.Entry(lockedSession!);
            Assert.NotEqual(EntityState.Detached, entry.State);
            Assert.Null(await codeStore.LockAsync(Guid.NewGuid(), cancellationToken));
            await transaction.RollbackAsync(cancellationToken);
        });
        Assert.NotEqual(Guid.Empty, lockedSessionId);
    }

    // ---- Acceptance 9: cross-instance recovery and the dependency surface ----

    [Fact]
    public async Task AnotherInstance_LooksUpLocksAndConsumes_WithoutAnyHttpSurface()
    {
        await using var database = new SqliteCodeDatabase();
        var optionsA = await database.InitializeAsync();
        var (accountId, credentialId, appId) = await SeedAsync(optionsA);
        var now = Microsecond(DateTimeOffset.UtcNow);
        var cancellationToken = TestContext.Current.CancellationToken;

        var session = await CreateSessionViaStoreAsync(optionsA, accountId, credentialId, now);
        string code;
        Guid codeId;
        var binding = CreateBinding(appId);
        await using (var contextA = new IdentityDbContext(optionsA))
        {
            var creation = await CreateStore(contextA).CreateAsync(
                session, binding, now, cancellationToken);
            code = creation.Code;
            codeId = creation.Id;
        }

        // Instance B builds its own options over the same database, classifies, locks (after the
        // session lock), verifies, and consumes the code A created.
        var optionsB = database.BuildOptions();
        var consumeInstant = Microsecond(DateTimeOffset.UtcNow);
        await using (var contextB = new IdentityDbContext(optionsB))
        {
            var sessionStore = new IdentitySessionStore(
                new IdentitySessionRepository(contextB), new EfCoreUnitOfWork(contextB));
            var codeStore = CreateStore(contextB);
            var lookup = await codeStore.FindAsync(code, consumeInstant, cancellationToken);
            Assert.Equal(AuthorizationCodeState.Unconsumed, lookup.State);

            await using var transaction = await contextB.Database
                .BeginTransactionAsync(cancellationToken);
            await sessionStore.LockAsync(lookup.Entity!.IdentitySessionId, cancellationToken);
            var locked = await codeStore.LockAsync(codeId, cancellationToken);
            Assert.NotNull(locked);
            Assert.True(codeStore.VerifyBinding(locked!, appId, binding.RedirectUri, Rfc7636Verifier));
            Assert.True(await codeStore.TryConsumeAsync(codeId, consumeInstant, cancellationToken));
            await transaction.CommitAsync(cancellationToken);
        }

        await using (var contextA2 = new IdentityDbContext(optionsA))
        {
            var lookup = await CreateStore(contextA2).FindAsync(
                code, DateTimeOffset.UtcNow, cancellationToken);
            Assert.Equal(AuthorizationCodeState.Consumed, lookup.State);
        }

        // The store has no HTTP, cookie, or Data Protection surface at all.
        var constructor = Assert.Single(typeof(AuthorizationCodeStore).GetConstructors());
        foreach (var parameter in constructor.GetParameters())
        {
            var typeName = parameter.ParameterType.FullName ?? string.Empty;
            Assert.DoesNotContain("DataProtection", typeName, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Cookie", typeName, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("HttpContext", typeName, StringComparison.OrdinalIgnoreCase);
        }
    }

    // ---- Acceptance 10: commit-boundary cancellation ----

    [Theory]
    [InlineData("create", false)]
    [InlineData("create", true)]
    [InlineData("consume", false)]
    [InlineData("consume", true)]
    [InlineData("cleanup", false)]
    [InlineData("cleanup", true)]
    public async Task Cancellation_AtTheCommitBoundary_IsBounded(string operation, bool afterCommit)
    {
        using var cancellation = new CancellationTokenSource();
        await using var database = new SqliteCodeDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId, appId) = await SeedAsync(options);
        var authTime = Microsecond(DateTimeOffset.UtcNow.AddMinutes(-5));
        var now = Microsecond(DateTimeOffset.UtcNow);
        var cancellationToken = TestContext.Current.CancellationToken;

        var session = await CreateSessionViaStoreAsync(options, accountId, credentialId, authTime);
        Guid codeId;
        await using (var seedContext = new IdentityDbContext(options))
        {
            codeId = (await CreateStore(seedContext).CreateAsync(
                session, CreateBinding(appId), now, cancellationToken)).Id;
        }

        if (operation == "cleanup")
        {
            await InsertCodeAsync(options, accountId, appId, session.Id,
                now.AddHours(-48),
                code => code.ExpiresAt = now.AddHours(-25));
        }

        // The commit boundary of a standalone creation is its SaveChanges, which carries no
        // interceptable transaction of its own; the shape production actually commits creation in
        // is the caller-owned ambient transaction (the EV-01 success transaction), so that is the
        // boundary this case cancels at. The consume/cleanup operations own explicit transactions
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
                await store.CreateAsync(session, CreateBinding(appId), now, cancellation.Token);
                await transaction.CommitAsync(cancellation.Token);
            },
            "consume" => async () => Assert.True(await store.TryConsumeAsync(
                codeId, now.AddMilliseconds(1), cancellation.Token)),
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
        var rows = await verification.AuthorizationCodes.AsNoTracking()
            .ToListAsync(cancellationToken);
        switch (operation)
        {
            case "create":
                Assert.Equal(afterCommit ? 2 : 1, rows.Count);
                break;
            case "consume":
                var consumedRow = Assert.Single(rows);
                Assert.Equal(afterCommit, consumedRow.ConsumedAt is not null);
                if (afterCommit)
                {
                    Assert.Equal(now.AddMilliseconds(1), consumedRow.ConsumedAt);
                }

                break;
            case "cleanup":
                // The seeded past-retention row is gone only when the cleanup committed; the
                // live row survives either way.
                Assert.Equal(afterCommit ? 1 : 2, rows.Count);
                break;
        }
    }

    // ---- Acceptance 11: transient replay ----

    [Fact]
    public async Task TransientFailures_ReplayConsumeAndCleanupExactlyOnce()
    {
        await using var database = new SqliteCodeDatabase();
        var plainOptions = await database.InitializeAsync();
        var (accountId, credentialId, appId) = await SeedAsync(plainOptions);
        var now = Microsecond(DateTimeOffset.UtcNow);
        var cancellationToken = TestContext.Current.CancellationToken;

        var session = await CreateSessionViaStoreAsync(plainOptions, accountId, credentialId, now);
        Guid codeId;
        await using (var context = new IdentityDbContext(plainOptions))
        {
            codeId = (await CreateStore(context).CreateAsync(
                session, CreateBinding(appId), now, cancellationToken)).Id;
        }

        var expiredId = await InsertCodeAsync(
            plainOptions, accountId, appId, session.Id,
            now.AddHours(-48),
            code => code.ExpiresAt = now.AddHours(-25));

        // Consumption: one injected UPDATE failure inside the explicit transaction, still exactly
        // one effective consumption.
        var consumeInterceptor = new TransientFailureInterceptor(
            "UPDATE \"authorization_codes\"", failuresToInject: 1);
        var consumeOptions = database.BuildRetryingOptions(consumeInterceptor);
        await using (var context = new IdentityDbContext(consumeOptions))
        {
            Assert.True(await CreateStore(context).TryConsumeAsync(
                codeId, now.AddMilliseconds(1), cancellationToken));
        }

        Assert.Equal(1, consumeInterceptor.InjectedFailures);
        Assert.Equal(
            now.AddMilliseconds(1),
            (await GetCodeRowAsync(plainOptions, codeId)).ConsumedAt);

        // Cleanup: one injected DELETE failure, replayed as a whole, exactly one deleted row.
        var cleanupInterceptor = new TransientFailureInterceptor(
            "DELETE FROM \"authorization_codes\"", failuresToInject: 1);
        var cleanupOptions = database.BuildRetryingOptions(cleanupInterceptor);
        await using (var context = new IdentityDbContext(cleanupOptions))
        {
            Assert.Equal(
                1,
                await CreateStore(context).CleanupExpiredAsync(now, cancellationToken));
        }

        Assert.Equal(1, cleanupInterceptor.InjectedFailures);
        await using (var verification = new IdentityDbContext(plainOptions))
        {
            var remaining = await verification.AuthorizationCodes.AsNoTracking()
                .ToListAsync(cancellationToken);
            var row = Assert.Single(remaining);
            Assert.Equal(codeId, row.Id);
            Assert.Equal(now.AddMilliseconds(1), row.ConsumedAt);
        }

        _ = expiredId;
    }

    // ---- Acceptance 12: the retention cleanup and the session coordination ----

    [Fact]
    public async Task Cleanup_DeletesOnlyBeyondTheRetentionWindow_AsOneUnit()
    {
        await using var database = new SqliteCodeDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId, appId) = await SeedAsync(options);
        var now = Microsecond(DateTimeOffset.UtcNow);
        var cutoff = now.AddHours(-IdentityConstants.AuthorizationCodeRetentionHours);
        var cancellationToken = TestContext.Current.CancellationToken;
        var session = await CreateSessionViaStoreAsync(
            options, accountId, credentialId, DateTimeOffset.UtcNow);
        var sessionId = session.Id;

        // Deleted: expires exactly at the cutoff, unconsumed.
        await InsertCodeAsync(options, accountId, appId, sessionId,
            cutoff.AddHours(-2), code => code.ExpiresAt = cutoff);
        // Deleted: consumed beyond the window — same window as unconsumed.
        await InsertCodeAsync(options, accountId, appId, sessionId,
            cutoff.AddHours(-2), code =>
            {
                code.ExpiresAt = cutoff;
                code.ConsumedAt = cutoff.AddSeconds(30);
            });
        // Kept: one microsecond inside the window.
        var keptId = await InsertCodeAsync(options, accountId, appId, sessionId,
            cutoff.AddMinutes(1), code => code.ExpiresAt = cutoff.AddTicks(10));
        // Kept: still inside its 60-second lifetime.
        var liveId = await InsertCodeAsync(options, accountId, appId, sessionId, now);

        await using (var context = new IdentityDbContext(options))
        {
            var deleted = await CreateStore(context).CleanupExpiredAsync(now, cancellationToken);
            Assert.Equal(2, deleted);
        }

        await using (var verification = new IdentityDbContext(options))
        {
            var remaining = await verification.AuthorizationCodes.AsNoTracking()
                .ToListAsync(cancellationToken);
            Assert.Equal(2, remaining.Count);
            Assert.Contains(remaining, row => row.Id == keptId);
            Assert.Contains(remaining, row => row.Id == liveId);
        }

        // A cancelled cleanup rolls the whole unit back.
        using var cancellation = new CancellationTokenSource();
        var cancelledOptions = database.BuildOptions(
            new CommitCancellationInterceptor(cancellation, afterCommit: false));
        await using (var context = new IdentityDbContext(cancelledOptions))
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                CreateStore(context).CleanupExpiredAsync(now.AddHours(25), cancellation.Token));
        }

        await using (var verification = new IdentityDbContext(options))
        {
            Assert.Equal(2, await verification.AuthorizationCodes
                .AsNoTracking()
                .CountAsync(cancellationToken));
        }
    }

    [Fact]
    public async Task SessionCleanup_KeepsReferencedSessions_ThenDeletesAfterTheCodeGoes()
    {
        await using var database = new SqliteCodeDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId, appId) = await SeedAsync(options);
        var now = Microsecond(DateTimeOffset.UtcNow);
        var cancellationToken = TestContext.Current.CancellationToken;

        // The session's own retention window ended hours ago; a code still inside its retention
        // window references it (the SC-05 storage shape: the session was revoked shortly after
        // the code was issued).
        var sessionId = await InsertSessionAsync(
            options, accountId, credentialId,
            session =>
            {
                var baseline = now.AddHours(-40);
                session.AuthTime = baseline;
                session.LastSeenAt = baseline;
                session.IdleExpiresAt = baseline.AddMinutes(30);
                session.AbsoluteExpiresAt = baseline.AddHours(12);
                session.RevokedAt = baseline.AddMinutes(35);
                session.RevocationReason = "logout";
            });
        await InsertCodeAsync(options, accountId, appId, sessionId,
            now.AddMinutes(-10),
            code => code.ExpiresAt = now.AddMinutes(-9));

        await using var context = new IdentityDbContext(options);
        var sessionStore = new IdentitySessionStore(
            new IdentitySessionRepository(context), new EfCoreUnitOfWork(context));
        var codeStore = CreateStore(context);

        // The session cleanup skips the referenced session without throwing, and the code — ten
        // minutes old — is inside its own retention window, so both cleanups delete nothing.
        Assert.Equal(0, await sessionStore.CleanupExpiredAsync(now, cancellationToken));
        Assert.True(await context.IdentitySessions.AsNoTracking()
            .AnyAsync(session => session.Id == sessionId, cancellationToken));
        Assert.Equal(0, await codeStore.CleanupExpiredAsync(now, cancellationToken));
        Assert.True(await context.IdentitySessions.AsNoTracking()
            .AnyAsync(session => session.Id == sessionId, cancellationToken));

        // Once the code is past its retention window, the same round deletes the code first and
        // the session right after.
        var future = now.AddHours(25);
        Assert.Equal(1, await codeStore.CleanupExpiredAsync(future, cancellationToken));
        Assert.Equal(1, await sessionStore.CleanupExpiredAsync(future, cancellationToken));
        Assert.False(await context.IdentitySessions.AsNoTracking()
            .AnyAsync(session => session.Id == sessionId, cancellationToken));
    }

    // ---- Acceptance 13: sensitive values ----

    [Fact]
    public async Task SensitiveValues_NeverReachStorageOrExceptions()
    {
        await using var database = new SqliteCodeDatabase();
        var options = await database.InitializeAsync();
        var (accountId, credentialId, appId) = await SeedAsync(options);
        var now = Microsecond(DateTimeOffset.UtcNow);
        var cancellationToken = TestContext.Current.CancellationToken;

        const string canaryVerifier = "CanaryVerifier_0123456789abcdefghijklmnopqrstuv";
        const string canaryChallenge = "CanaryChallenge_0123456789abcdefghijklmnopq";
        const string canaryNonce = "CanaryNonce_0123456789abcdefghijklmnop";
        Assert.Equal(43, canaryChallenge.Length);

        var session = await CreateSessionViaStoreAsync(options, accountId, credentialId, now);
        string canaryCode;
        Guid codeId;
        var exceptions = new List<Exception>();

        await using (var context = new IdentityDbContext(options))
        {
            var store = CreateStore(context);
            var binding = new AuthorizationCodeBinding(
                appId,
                "https://client.example.test/callback",
                "openid",
                canaryNonce,
                canaryChallenge);
            var creation = await store.CreateAsync(session, binding, now, cancellationToken);
            canaryCode = creation.Code;
            codeId = creation.Id;

            // Walk the binding path with the canary verifier.
            store.VerifyBinding(
                (await store.FindAsync(canaryCode, now, cancellationToken)).Entity!,
                appId,
                binding.RedirectUri,
                canaryVerifier);

            exceptions.Add(await Assert.ThrowsAsync<InvalidOperationException>(() =>
                store.LockAsync(codeId, cancellationToken)));

            using var cancellation = new CancellationTokenSource();
            var cancelledOptions = database.BuildOptions(
                new CommitCancellationInterceptor(cancellation, afterCommit: false));
            await using var cancelledContext = new IdentityDbContext(cancelledOptions);
            exceptions.Add(await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                CreateStore(cancelledContext).TryConsumeAsync(codeId, now, cancellation.Token)));
        }

        // The plaintext code and the verifier are in no stored column; the whole database carries
        // neither value.
        var dump = await DumpTablesAsync(options);
        Assert.DoesNotContain(canaryCode, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(canaryVerifier, dump, StringComparison.Ordinal);

        // No exception string carries the code, verifier, nonce, or challenge.
        Assert.Equal(2, exceptions.Count);
        Assert.All(exceptions, exception =>
        {
            var text = exception.ToString();
            Assert.DoesNotContain(canaryCode, text, StringComparison.Ordinal);
            Assert.DoesNotContain(canaryVerifier, text, StringComparison.Ordinal);
            Assert.DoesNotContain(canaryNonce, text, StringComparison.Ordinal);
            Assert.DoesNotContain(canaryChallenge, text, StringComparison.Ordinal);
        });
    }

    // ---- Helpers ----

    private static DateTimeOffset Microsecond(DateTimeOffset value) =>
        new(value.UtcTicks / 10 * 10, TimeSpan.Zero);

    private static AuthorizationCodeStore CreateStore(IdentityDbContext context) => new(
        new AuthorizationCodeRepository(context),
        new EfCoreUnitOfWork(context));

    private static AuthorizationCodeBinding CreateBinding(
        Guid appId,
        string redirectUri = "https://client.example.test/callback",
        string scope = "openid profile",
        string nonce = "code-contract-nonce",
        string codeChallenge = Rfc7636Challenge) =>
        new(appId, redirectUri, scope, nonce, codeChallenge);

    private static async Task<IdentitySessionEntity> CreateSessionViaStoreAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid accountId,
        Guid credentialId,
        DateTimeOffset authTime)
    {
        await using var context = new IdentityDbContext(options);
        return await new IdentitySessionStore(
            new IdentitySessionRepository(context),
            new EfCoreUnitOfWork(context)).CreateAsync(
            accountId, credentialId, authTime, TestContext.Current.CancellationToken);
    }

    private static async Task<(Guid AccountId, Guid CredentialId, Guid AppId)> SeedAsync(
        DbContextOptions<IdentityDbContext> options)
    {
        await using var context = new IdentityDbContext(options);
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var appId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity
        {
            Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow
        });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = credentialId, AccountId = accountId, Username = Username,
            PasswordHash = "hash", CreatedAt = DateTimeOffset.UtcNow
        });
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = appId, AppId = ClientId, AppSecretHash = "hash",
            AppName = "Code Contract", IsActive = true, CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        return (accountId, credentialId, appId);
    }

    private static IdentitySessionEntity CreateValidSession(
        Guid accountId,
        Guid credentialId,
        Guid sessionId,
        DateTimeOffset? authTime = null)
    {
        var now = Microsecond(authTime ?? DateTimeOffset.UtcNow);
        return new IdentitySessionEntity
        {
            Id = sessionId,
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
        Action<IdentitySessionEntity>? mutate = null)
    {
        var session = CreateValidSession(accountId, credentialId, Guid.NewGuid());
        mutate?.Invoke(session);
        await using var context = new IdentityDbContext(options);
        context.IdentitySessions.Add(session);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        return session.Id;
    }

    private static AuthorizationCodeEntity CreateValidCode(
        Guid accountId,
        Guid appId,
        Guid sessionId,
        DateTimeOffset createdAt,
        Action<AuthorizationCodeEntity>? mutate = null)
    {
        var code = new AuthorizationCodeEntity
        {
            Id = Guid.NewGuid(),
            CodeDigest = AuthorizationCodeDigest.Compute(
                $"seed-{Guid.NewGuid():N}"),
            AppRegistrationId = appId,
            AccountId = accountId,
            IdentitySessionId = sessionId,
            RedirectUri = "https://client.example.test/callback",
            Scope = "openid",
            Nonce = "code-contract-nonce",
            CodeChallenge = Rfc7636Challenge,
            AuthTime = createdAt,
            CreatedAt = createdAt,
            ExpiresAt = createdAt.AddSeconds(IdentityConstants.AuthorizationCodeLifetimeSeconds)
        };
        mutate?.Invoke(code);
        return code;
    }

    private static async Task<AuthorizationCodeEntity> InsertValidCodeAsync(
        IdentityDbContext context,
        Guid accountId,
        Guid appId,
        Guid sessionId,
        Action<AuthorizationCodeEntity>? mutate = null,
        bool consumed = false)
    {
        var code = CreateValidCode(accountId, appId, sessionId, Microsecond(DateTimeOffset.UtcNow), mutate);
        if (consumed)
        {
            code.ConsumedAt = code.CreatedAt.AddMilliseconds(1);
        }

        context.AuthorizationCodes.Add(code);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();
        return code;
    }

    private static async Task<Guid> InsertCodeAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid accountId,
        Guid appId,
        Guid sessionId,
        DateTimeOffset createdAt,
        Action<AuthorizationCodeEntity>? mutate = null)
    {
        var code = CreateValidCode(accountId, appId, sessionId, Microsecond(createdAt), mutate);
        await using var context = new IdentityDbContext(options);
        context.AuthorizationCodes.Add(code);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        return code.Id;
    }

    private static async Task<AuthorizationCodeEntity> GetCodeRowAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid codeId)
    {
        await using var context = new IdentityDbContext(options);
        return await context.AuthorizationCodes.AsNoTracking()
            .SingleAsync(row => row.Id == codeId, TestContext.Current.CancellationToken);
    }

    private static async Task<int> CountCodesAsync(DbContextOptions<IdentityDbContext> options)
    {
        await using var context = new IdentityDbContext(options);
        return await context.AuthorizationCodes
            .AsNoTracking()
            .CountAsync(TestContext.Current.CancellationToken);
    }

    private static async Task AssertDeleteBlockedAsync(
        IdentityDbContext context,
        string target,
        Guid id)
    {
        switch (target)
        {
            case "account":
                context.Accounts.Remove(await context.Accounts
                    .SingleAsync(row => row.Id == id, TestContext.Current.CancellationToken));
                break;
            case "app":
                context.AppRegistrations.Remove(await context.AppRegistrations
                    .SingleAsync(row => row.Id == id, TestContext.Current.CancellationToken));
                break;
            case "session":
                context.IdentitySessions.Remove(await context.IdentitySessions
                    .SingleAsync(row => row.Id == id, TestContext.Current.CancellationToken));
                break;
        }

        await Assert.ThrowsAsync<DbUpdateException>(() =>
            context.SaveChangesAsync(TestContext.Current.CancellationToken));
        context.ChangeTracker.Clear();
    }

    private static async Task AssertFamilyRejectedAsync(
        IdentityDbContext context,
        Guid accountId,
        Guid appId,
        Guid sessionId,
        Guid rootId)
    {
        var code = CreateValidCode(accountId, appId, sessionId, Microsecond(DateTimeOffset.UtcNow));
        code.RefreshFamilyId = rootId;
        context.AuthorizationCodes.Add(code);
        await Assert.ThrowsAsync<DbUpdateException>(() =>
            context.SaveChangesAsync(TestContext.Current.CancellationToken));
        context.ChangeTracker.Clear();
    }

    private static async Task AssertOrphanRejectedAsync(
        IdentityDbContext context,
        Guid accountId,
        Guid appId,
        Guid sessionId,
        string orphan)
    {
        var code = CreateValidCode(accountId, appId, sessionId, Microsecond(DateTimeOffset.UtcNow));
        switch (orphan)
        {
            case "account":
                code.AccountId = Guid.NewGuid();
                break;
            case "app":
                code.AppRegistrationId = Guid.NewGuid();
                break;
            case "session":
                code.IdentitySessionId = Guid.NewGuid();
                break;
        }

        context.AuthorizationCodes.Add(code);
        await Assert.ThrowsAsync<DbUpdateException>(() =>
            context.SaveChangesAsync(TestContext.Current.CancellationToken));
        context.ChangeTracker.Clear();
    }

    private static async Task AssertSeedUnchangedAsync(
        IdentityDbContext context,
        Guid accountId,
        Guid appId,
        Guid tokenId,
        Guid sessionId,
        string tokenDigest)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var account = await context.Accounts.AsNoTracking()
            .SingleAsync(row => row.Id == accountId, cancellationToken);
        Assert.True(account.IsActive);

        var application = await context.AppRegistrations.AsNoTracking()
            .SingleAsync(row => row.Id == appId, cancellationToken);
        Assert.Equal(ClientId, application.AppId);
        Assert.True(application.IsActive);

        // The Down state predates the family columns, so the token row is read with raw SQL
        // instead of the current EF model.
        var token = await RefreshTokenFamilyTestSupport.ReadRefreshTokenRowSqliteAsync(
            context, tokenId);
        Assert.Equal(tokenDigest, token.TokenValue);

        var session = await context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == sessionId, cancellationToken);
        Assert.Equal(accountId, session.AccountId);
        Assert.Null(session.RevokedAt);
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
                row[ordinal] = reader.IsDBNull(ordinal)
                    ? string.Empty
                    : reader.GetValue(ordinal)?.ToString() ?? string.Empty;
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

    private static async Task<bool> SqliteTableExistsAsync(
        IdentityDbContext context,
        string tableName)
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

    private sealed class MockRepository : IAuthorizationCodeRepository
    {
        public Task AddAsync(
            AuthorizationCodeEntity code,
            CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<AuthorizationCodeEntity?> GetByCodeDigestAsync(
            string codeDigest,
            CancellationToken cancellationToken = default) => Task.FromResult<AuthorizationCodeEntity?>(null);

        public Task<AuthorizationCodeEntity?> LockByIdAsync(
            Guid codeId,
            CancellationToken cancellationToken = default) => Task.FromResult<AuthorizationCodeEntity?>(null);

        public Task<bool> TryConsumeAsync(
            Guid codeId,
            DateTimeOffset now,
            CancellationToken cancellationToken = default) => Task.FromResult(false);

        public Task<int> RemoveExpiredBeforeAsync(
            DateTimeOffset cutoff,
            CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    private sealed class MockUnitOfWork : IUnitOfWork
    {
        public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(0);
    }

    /// <summary>
    /// A file-backed SQLite test database on the production migration chain, onto which a
    /// retrying execution strategy and interceptors are attached as needed.
    /// </summary>
    private sealed class SqliteCodeDatabase : IAsyncDisposable
    {
        private readonly string _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-authorization-code-{Guid.NewGuid():N}.db");

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
