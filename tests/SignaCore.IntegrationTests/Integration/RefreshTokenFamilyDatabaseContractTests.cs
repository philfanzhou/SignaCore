using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using Xunit;
using SignaCore.Tests.Integration;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// The SQLite half of the <c>AC-11</c> storage-only family contract: the exact fresh shape of the
/// six family columns, the two single-row checks, the restrictive references, and the unique
/// child-per-parent index; the backfill upgrade from <c>AddAuthorizationCodes</c> that makes every
/// legacy row a singleton root while preserving every stored value byte for byte; the corrupt-write
/// matrix that the database rejects fail-closed; the restrictive deletion behavior; legacy cleanup
/// and rotation staying away from interactive rows; and the downgrade gate with its round trip.
/// The PostgreSQL half lives in <see cref="ServerDatabaseContractTests"/>. Interactive family
/// write/lookup/consume/revoke semantics belong to #98 and are not exercised here beyond the raw
/// rows the constraints, cleanup, and gate need.
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class RefreshTokenFamilyDatabaseContractTests
{
    private const string CodeMigration = "20260916160633_AddAuthorizationCodes";
    private const string FamilyMigration = "20260917030735_AddRefreshTokenFamilies";
    private const string AppId = "family-contract-app";
    private const string CanonicalScope = "openid profile";

    // ---- Acceptance 1: the fresh schema shape ----

    [Fact]
    public async Task FreshDatabase_HasTheFamilyShapeAndTheDeferredCodeReference()
    {
        await using var database = new SqliteFamilyDatabase();
        var options = await database.InitializeAsync();
        await using var context = new IdentityDbContext(options);
        var cancellationToken = TestContext.Current.CancellationToken;

        // The six family columns with their storage types and nullability.
        var columns = await ReadPragmaAsync(context, "PRAGMA table_info(refresh_tokens)");
        var shape = columns.ToDictionary(row => row[1], row => (row[2], row[3] == "1"));
        Assert.Equal(("TEXT", true), shape["family_id"]);
        Assert.Equal(("TEXT", false), shape["parent_id"]);
        Assert.Equal(("TEXT", false), shape["identity_session_id"]);
        Assert.Equal(("TEXT", false), shape["scope"]);
        Assert.Equal(("INTEGER", false), shape["auth_time"]);
        Assert.Equal(("INTEGER", false), shape["consumed_at"]);
        // The legacy columns survive untouched.
        foreach (var legacy in new[]
                 {
                     "id", "account_id", "token_value", "expires_at", "created_at",
                     "is_revoked", "app_id", "ldap_credential_id", "sms_user_login_id",
                     "wechat_user_login_id", "source_app_id"
                 })
        {
            Assert.Contains(legacy, shape.Keys);
        }

        // The scope length unit is symmetric with authorization_codes.scope (32): the SQLite DDL
        // carries no length, so the model is the authority here.
        var scopeProperty = context.Model.FindEntityType(typeof(RefreshTokenEntity))!
            .FindProperty(nameof(RefreshTokenEntity.Scope))!;
        Assert.Equal(IdentityConstants.MaxOidcAllowedScopesLength, scopeProperty.GetMaxLength());

        // Both family checks exist alongside the retained app_id check, and the code pairing
        // check survives.
        var tokenDdl = await ReadScalarAsync(
            context,
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'refresh_tokens'");
        Assert.Contains("CK_refresh_tokens_app_id_not_empty", tokenDdl, StringComparison.Ordinal);
        Assert.Contains("CK_refresh_tokens_family_marker", tokenDdl, StringComparison.Ordinal);
        Assert.Contains("CK_refresh_tokens_family_shape", tokenDdl, StringComparison.Ordinal);
        var codeDdl = await ReadScalarAsync(
            context,
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'authorization_codes'");
        Assert.Contains(
            "CK_authorization_codes_family_requires_consumption", codeDdl, StringComparison.Ordinal);

        // The three restrictive refresh_tokens references; nothing cascades.
        var foreignKeys = await ReadPragmaAsync(context, "PRAGMA foreign_key_list(refresh_tokens)");
        Assert.Equal(3, foreignKeys.Count);
        Assert.Contains(foreignKeys, key =>
            key[2] == "identity_sessions" && key[3] == "identity_session_id" && key[4] == "id"
            && string.Equals(key[6], "RESTRICT", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(
            2,
            foreignKeys.Count(key =>
                key[2] == "refresh_tokens"
                && string.Equals(key[6], "RESTRICT", StringComparison.OrdinalIgnoreCase)));
        Assert.Contains(foreignKeys, key => key[3] == "family_id");
        Assert.Contains(foreignKeys, key => key[3] == "parent_id");

        // The indexes: the unique child-per-parent index, the family/session lookups, and the
        // retained digest-unique plus three admission indexes.
        var indexes = await ReadPragmaAsync(context, "PRAGMA index_list(refresh_tokens)");
        var uniqueIndexColumns = new HashSet<string>(StringComparer.Ordinal);
        var indexColumns = new HashSet<string>(StringComparer.Ordinal);
        foreach (var index in indexes)
        {
            var indexColumnRows = await ReadPragmaAsync(
                context, $"PRAGMA index_info(\"{index[1]}\")");
            if (indexColumnRows.Count == 1)
            {
                indexColumns.Add(indexColumnRows[0][2]);
                if (string.Equals(index[2], "1", StringComparison.Ordinal))
                {
                    uniqueIndexColumns.Add(indexColumnRows[0][2]);
                }
            }
        }

        Assert.Contains("parent_id", uniqueIndexColumns);
        Assert.Contains("token_value", uniqueIndexColumns);
        Assert.Contains("family_id", indexColumns);
        Assert.Contains("identity_session_id", indexColumns);
        Assert.Contains("ldap_credential_id", indexColumns);
        Assert.Contains("sms_user_login_id", indexColumns);
        Assert.Contains("wechat_user_login_id", indexColumns);

        // The single deferred PS-23 reference now exists on the code side, restrictive + indexed.
        var codeForeignKeys = await ReadPragmaAsync(
            context, "PRAGMA foreign_key_list(authorization_codes)");
        Assert.Contains(codeForeignKeys, key =>
            key[2] == "refresh_tokens" && key[3] == "refresh_family_id" && key[4] == "id"
            && string.Equals(key[6], "RESTRICT", StringComparison.OrdinalIgnoreCase));
        var codeIndexes = await ReadPragmaAsync(context, "PRAGMA index_list(authorization_codes)");
        var codeIndexColumns = new List<string>();
        foreach (var index in codeIndexes)
        {
            var indexColumnRows = await ReadPragmaAsync(
                context, $"PRAGMA index_info(\"{index[1]}\")");
            if (indexColumnRows.Count == 1)
            {
                codeIndexColumns.Add(indexColumnRows[0][2]);
            }
        }

        Assert.Contains("refresh_family_id", codeIndexColumns);
        Assert.Equal(
            string.Empty,
            await ReadScalarAsync(context, "PRAGMA foreign_key_check"));
        await context.Database.CloseConnectionAsync();
    }

    // ---- Acceptance 2 (+9): the backfill upgrade preserves every legacy value ----

    [Fact]
    public async Task UpgradeFromAddAuthorizationCodes_BackfillsSingletonRoots_AndPreservesEveryValue()
    {
        await using var database = new SqliteFamilyDatabase();
        var options = database.BuildOptions();
        await using var context = new IdentityDbContext(options);
        var cancellationToken = TestContext.Current.CancellationToken;
        var migrator = context.GetService<IMigrator>();
        await migrator.MigrateAsync(CodeMigration, cancellationToken);

        var (accountId, _, appId, sessionId) = await SeedBasicsAsync(context);
        var createdAt = DateTimeOffset.UtcNow.AddHours(-2);
        var expiresAt = createdAt.AddHours(1);

        // The five legacy shapes on the pre-family schema, seeded with raw SQL: live, expired,
        // revoked, plaintext (never rewritten; #169 removed the startup conversion), and a
        // cross-application mint. Plus one consumed code with a null family link.
        var liveId = Guid.NewGuid();
        var livePlaintext = "family-upgrade-live-token";
        await RefreshTokenFamilyTestSupport.InsertLegacyRefreshTokenSqliteAsync(
            context, liveId, accountId, RefreshTokenDigest.Compute(livePlaintext),
            createdAt, DateTimeOffset.UtcNow.AddHours(1), AppId);
        await RefreshTokenFamilyTestSupport.InsertLegacyRefreshTokenSqliteAsync(
            context, Guid.NewGuid(), accountId, RefreshTokenDigest.Compute("family-upgrade-expired"),
            createdAt, expiresAt, AppId);
        await RefreshTokenFamilyTestSupport.InsertLegacyRefreshTokenSqliteAsync(
            context, Guid.NewGuid(), accountId, RefreshTokenDigest.Compute("family-upgrade-revoked"),
            createdAt, DateTimeOffset.UtcNow.AddHours(1), AppId, isRevoked: true);
        const string plaintextTokenValue = "legacy-plaintext-token-value";
        await RefreshTokenFamilyTestSupport.InsertLegacyRefreshTokenSqliteAsync(
            context, Guid.NewGuid(), accountId, plaintextTokenValue,
            createdAt, DateTimeOffset.UtcNow.AddHours(1), AppId);
        await RefreshTokenFamilyTestSupport.InsertLegacyRefreshTokenSqliteAsync(
            context, Guid.NewGuid(), accountId, RefreshTokenDigest.Compute("family-upgrade-exchange"),
            createdAt, DateTimeOffset.UtcNow.AddHours(1), AppId,
            sourceAppId: "family-contract-source-app");

        var code = new AuthorizationCodeEntity
        {
            Id = Guid.NewGuid(),
            CodeDigest = AuthorizationCodeDigest.Compute("family-upgrade-code-0123456789abcdefgh"),
            AppRegistrationId = appId,
            AccountId = accountId,
            IdentitySessionId = sessionId,
            RedirectUri = "https://client.example.test/callback",
            Scope = "openid",
            Nonce = "family-upgrade-nonce",
            CodeChallenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            AuthTime = createdAt,
            CreatedAt = createdAt,
            ExpiresAt = createdAt.AddSeconds(IdentityConstants.AuthorizationCodeLifetimeSeconds),
            ConsumedAt = createdAt.AddSeconds(1)
        };
        context.AuthorizationCodes.Add(code);
        await context.SaveChangesAsync(cancellationToken);

        var tokensBefore = await DumpSqlAsync(context, LegacyTokenDumpSql);
        var codesBefore = await DumpSqlAsync(context, CodeDumpSql);

        await migrator.MigrateAsync(cancellationToken: cancellationToken);

        // Every original column value is byte-identical; the code row is untouched.
        Assert.Equal(tokensBefore, await DumpSqlAsync(context, LegacyTokenDumpSql));
        Assert.Equal(codesBefore, await DumpSqlAsync(context, CodeDumpSql));

        // family_id = id on every row, the other five family columns null.
        var familyDump = await DumpSqlAsync(context, """
            SELECT id, family_id, parent_id, identity_session_id, scope, auth_time, consumed_at
            FROM refresh_tokens ORDER BY id
            """);
        foreach (var line in familyDump.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.TrimEnd('\r')))
        {
            var fields = line.Split('|');
            Assert.Equal(fields[0], fields[1]);
            Assert.Equal("NULL", fields[2]);
            Assert.Equal("NULL", fields[3]);
            Assert.Equal("NULL", fields[4]);
            Assert.Equal("NULL", fields[5]);
            Assert.Equal("NULL", fields[6]);
        }

        Assert.Equal(string.Empty, await ReadScalarAsync(context, "PRAGMA foreign_key_check"));
        await context.Database.CloseConnectionAsync();

        // The live legacy token still rotates, and its replacement is a fresh singleton root.
        var repository = new RefreshTokenRepository(context);
        var replacementId = Guid.NewGuid();
        Assert.True(await repository.TryRotateAsync(
            livePlaintext,
            new RefreshTokenEntity
            {
                Id = replacementId,
                AccountId = accountId,
                TokenValue = RefreshTokenDigest.Compute("family-upgrade-rotated"),
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
                AppId = AppId
            },
            cancellationToken));
        await context.SaveChangesAsync(cancellationToken);
        var replacement = await context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == replacementId, cancellationToken);
        Assert.Equal(replacementId, replacement.FamilyId);
        Assert.Null(replacement.ParentId);
        Assert.Null(replacement.IdentitySessionId);
        Assert.Null(replacement.ConsumedAt);
        var rotatedSource = await context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == liveId, cancellationToken);
        Assert.True(rotatedSource.IsRevoked);
        Assert.Null(rotatedSource.ConsumedAt);
    }

    // ---- Acceptance 4 (+9): the corrupt-write matrix fails closed ----

    [Fact]
    public async Task CorruptFamilyWrites_AreRejectedWithoutAnyRowChange()
    {
        await using var database = new SqliteFamilyDatabase();
        var options = await database.InitializeAsync();
        await using var context = new IdentityDbContext(options);
        var cancellationToken = TestContext.Current.CancellationToken;
        var (accountId, _, appId, sessionId) = await SeedBasicsAsync(context);

        // One valid interactive family as the reference point: root plus its single child.
        var authTime = DateTimeOffset.UtcNow.AddMinutes(-5);
        var now = DateTimeOffset.UtcNow;
        var rootId = Guid.NewGuid();
        var childId = Guid.NewGuid();
        await RefreshTokenFamilyTestSupport.InsertInteractiveMemberSqliteAsync(
            context, rootId, accountId, AppId, rootId, parentId: null, sessionId,
            CanonicalScope, authTime, now, now.AddHours(1), consumedAt: now);
        await RefreshTokenFamilyTestSupport.InsertInteractiveMemberSqliteAsync(
            context, childId, accountId, AppId, rootId, parentId: rootId, sessionId,
            CanonicalScope, authTime, now, now.AddHours(1));

        var countBefore = await context.RefreshTokens.AsNoTracking().CountAsync(cancellationToken);
        var codeCountBefore = await context.AuthorizationCodes.AsNoTracking().CountAsync(cancellationToken);

        var missingRowId = Guid.NewGuid();
        var corruptInserts = new (string Label, Func<Task<int>> Insert)[]
        {
            // A partial interactive marker: session and scope without auth_time (root shape,
            // so the marker check is the sole violation).
            ("partial-marker", () =>
            {
                var markerId = Guid.NewGuid();
                return InsertFamilyRowAsync(
                    context, markerId, accountId, AppId,
                    familyId: markerId, parentId: null, sessionId, CanonicalScope,
                    authTime: null, consumedAt: null);
            }),
            // A legacy row that claims a parent (parented to the childless child row, so the
            // unique child index cannot mask the marker violation).
            ("legacy-with-parent", () => InsertFamilyRowAsync(
                context, Guid.NewGuid(), accountId, AppId,
                familyId: childId, parentId: childId, sessionId: null, scope: null,
                authTime: null, consumedAt: null)),
            // A legacy row that claims consumption (root shape, marker violation).
            ("legacy-with-consumed", () =>
            {
                var consumedId = Guid.NewGuid();
                return InsertFamilyRowAsync(
                    context, consumedId, accountId, AppId,
                    familyId: consumedId, parentId: null, sessionId: null, scope: null,
                    authTime: null, consumedAt: now);
            }),
            // A root that names a parent: family = own id with a parent violates the shape
            // check (and the legacy marker branch requires parent NULL).
            ("root-with-parent", () =>
            {
                var selfRootId = Guid.NewGuid();
                return InsertFamilyRowAsync(
                    context, selfRootId, accountId, AppId,
                    familyId: selfRootId, parentId: childId, sessionId: null, scope: null,
                    authTime: null, consumedAt: null);
            }),
            // A row that is its own parent.
            ("self-parent", () =>
            {
                var selfId = Guid.NewGuid();
                return InsertFamilyRowAsync(
                    context, selfId, accountId, AppId,
                    familyId: rootId, parentId: selfId, sessionId: null, scope: null,
                    authTime: null, consumedAt: null);
            }),
            // A family id that resolves no row.
            ("family-missing", () => InsertFamilyRowAsync(
                context, Guid.NewGuid(), accountId, AppId,
                familyId: missingRowId, parentId: missingRowId, sessionId, CanonicalScope,
                authTime, consumedAt: null)),
            // A parent id that resolves no row.
            ("parent-missing", () => InsertFamilyRowAsync(
                context, Guid.NewGuid(), accountId, AppId,
                familyId: rootId, parentId: missingRowId, sessionId, CanonicalScope,
                authTime, consumedAt: null)),
            // A session id that resolves no row (root shape, complete marker — the session
            // reference is the sole violation).
            ("session-missing", () =>
            {
                var sessionRowId = Guid.NewGuid();
                return InsertFamilyRowAsync(
                    context, sessionRowId, accountId, AppId,
                    familyId: sessionRowId, parentId: null, Guid.NewGuid(), CanonicalScope,
                    authTime, consumedAt: null);
            }),
            // A second child of the same parent.
            ("second-child", () => InsertFamilyRowAsync(
                context, Guid.NewGuid(), accountId, AppId,
                familyId: rootId, parentId: rootId, sessionId, CanonicalScope,
                authTime, consumedAt: null)),
        };

        foreach (var (label, insert) in corruptInserts)
        {
            var exception = await Record.ExceptionAsync(insert);
            Assert.NotNull(exception);
            Assert.IsType<SqliteException>(exception);
        }

        // A code whose family link resolves no root.
        await Assert.ThrowsAsync<DbUpdateException>(async () =>
        {
            context.AuthorizationCodes.Add(new AuthorizationCodeEntity
            {
                Id = Guid.NewGuid(),
                CodeDigest = AuthorizationCodeDigest.Compute(
                    "family-orphan-code-0123456789abcdefghijk"),
                AppRegistrationId = appId,
                AccountId = accountId,
                IdentitySessionId = sessionId,
                RedirectUri = "https://client.example.test/callback",
                Scope = CanonicalScope,
                Nonce = "family-orphan-nonce",
                CodeChallenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                AuthTime = authTime,
                CreatedAt = now,
                ExpiresAt = now.AddSeconds(IdentityConstants.AuthorizationCodeLifetimeSeconds),
                ConsumedAt = now,
                RefreshFamilyId = missingRowId
            });
            await context.SaveChangesAsync(cancellationToken);
        });
        context.ChangeTracker.Clear();

        // Zero writes: neither table gained a row.
        Assert.Equal(countBefore, await context.RefreshTokens.AsNoTracking().CountAsync(cancellationToken));
        Assert.Equal(
            codeCountBefore,
            await context.AuthorizationCodes.AsNoTracking().CountAsync(cancellationToken));

        // The valid two-member family itself persisted above proves the checks admit the
        // canonical shapes.
        Assert.Equal(2, await context.RefreshTokens.AsNoTracking()
            .CountAsync(row => row.IdentitySessionId == sessionId, cancellationToken));
    }

    // ---- Acceptance 5: restrictive deletion ----

    [Fact]
    public async Task RestrictiveReferences_BlockReferencedDeletes_ButNotLegacySingletons()
    {
        await using var database = new SqliteFamilyDatabase();
        var options = await database.InitializeAsync();
        await using var context = new IdentityDbContext(options);
        var cancellationToken = TestContext.Current.CancellationToken;
        var (accountId, _, appId, sessionId) = await SeedBasicsAsync(context);

        var authTime = DateTimeOffset.UtcNow.AddMinutes(-5);
        var now = DateTimeOffset.UtcNow;
        var rootId = Guid.NewGuid();
        await RefreshTokenFamilyTestSupport.InsertInteractiveMemberSqliteAsync(
            context, rootId, accountId, AppId, rootId, parentId: null, sessionId,
            CanonicalScope, authTime, now, now.AddHours(1), consumedAt: now);
        await RefreshTokenFamilyTestSupport.InsertInteractiveMemberSqliteAsync(
            context, Guid.NewGuid(), accountId, AppId, rootId, parentId: rootId, sessionId,
            CanonicalScope, authTime, now, now.AddHours(1));

        // A legacy singleton root linked by a consumed code.
        var linkedRootId = Guid.NewGuid();
        await InsertLegacyRootAsync(context, linkedRootId, accountId, now);
        context.AuthorizationCodes.Add(new AuthorizationCodeEntity
        {
            Id = Guid.NewGuid(),
            CodeDigest = AuthorizationCodeDigest.Compute("family-linked-code-0123456789abcdefgh"),
            AppRegistrationId = appId,
            AccountId = accountId,
            IdentitySessionId = sessionId,
            RedirectUri = "https://client.example.test/callback",
            Scope = CanonicalScope,
            Nonce = "family-linked-nonce",
            CodeChallenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            AuthTime = authTime,
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(IdentityConstants.AuthorizationCodeLifetimeSeconds),
            ConsumedAt = now,
            RefreshFamilyId = linkedRootId
        });
        await context.SaveChangesAsync(cancellationToken);
        context.ChangeTracker.Clear();

        // Deleting the root of a child fails; deleting the session of an interactive row fails;
        // deleting the root a code links fails. No cascade anywhere.
        await AssertDeleteRejectedAsync(context, "refresh_tokens", rootId);
        await AssertDeleteRejectedAsync(context, "identity_sessions", sessionId);
        await AssertDeleteRejectedAsync(context, "refresh_tokens", linkedRootId);

        // A legacy singleton deletes fine — alone and through the batch cleanup — because its
        // only reference is itself and nothing points at it.
        var deletableId = Guid.NewGuid();
        await InsertLegacyRootAsync(context, deletableId, accountId, now, expiresAt: now.AddHours(-1));
        await context.Database.ExecuteSqlInterpolatedAsync(
            $"DELETE FROM refresh_tokens WHERE id = {deletableId}", cancellationToken);

        var batchExpiredId = Guid.NewGuid();
        var batchRevokedId = Guid.NewGuid();
        await InsertLegacyRootAsync(context, batchExpiredId, accountId, now, expiresAt: now.AddHours(-1));
        await InsertLegacyRootAsync(context, batchRevokedId, accountId, now, isRevoked: true);
        var deleted = await new RefreshTokenRepository(context)
            .RemoveExpiredAndRevokedAsync(cancellationToken);
        Assert.Equal(2, deleted);
        Assert.False(await context.RefreshTokens.AsNoTracking()
            .AnyAsync(row => row.Id == batchExpiredId || row.Id == batchRevokedId, cancellationToken));
        // The referenced and interactive rows all survive.
        Assert.True(await context.RefreshTokens.AsNoTracking()
            .AnyAsync(row => row.Id == rootId, cancellationToken));
        Assert.True(await context.RefreshTokens.AsNoTracking()
            .AnyAsync(row => row.Id == linkedRootId, cancellationToken));
    }

    // ---- Acceptance 6 (+7): legacy cleanup and rotation stay away from interactive rows ----

    [Fact]
    public async Task LegacyCleanupAndRotation_NeverTouchInteractiveFamilyMembers()
    {
        await using var database = new SqliteFamilyDatabase();
        var options = await database.InitializeAsync();
        await using var context = new IdentityDbContext(options);
        var cancellationToken = TestContext.Current.CancellationToken;
        var (accountId, _, _, sessionId) = await SeedBasicsAsync(context);

        var authTime = DateTimeOffset.UtcNow.AddMinutes(-5);
        var now = DateTimeOffset.UtcNow;
        // An interactive family that is revoked AND expired: the legacy cleanup predicate must
        // still leave it alone, because whole-family deletion under RESTRICT is child-first work
        // that belongs to #98, and a single-statement family delete fails on SQLite.
        var rootId = Guid.NewGuid();
        var childId = Guid.NewGuid();
        await RefreshTokenFamilyTestSupport.InsertInteractiveMemberSqliteAsync(
            context, rootId, accountId, AppId, rootId, parentId: null, sessionId,
            CanonicalScope, authTime, now.AddHours(-2), now.AddHours(-1),
            isRevoked: true, consumedAt: now.AddHours(-1));
        await RefreshTokenFamilyTestSupport.InsertInteractiveMemberSqliteAsync(
            context, childId, accountId, AppId, rootId, parentId: rootId, sessionId,
            CanonicalScope, authTime, now.AddHours(-2), now.AddHours(-1), isRevoked: true);

        var expiredLegacyId = Guid.NewGuid();
        var revokedLegacyId = Guid.NewGuid();
        var liveLegacyId = Guid.NewGuid();
        await InsertLegacyRootAsync(context, expiredLegacyId, accountId, now, expiresAt: now.AddHours(-1));
        await InsertLegacyRootAsync(context, revokedLegacyId, accountId, now, isRevoked: true);
        await InsertLegacyRootAsync(context, liveLegacyId, accountId, now);

        var repository = new RefreshTokenRepository(context);
        var deleted = await repository.RemoveExpiredAndRevokedAsync(cancellationToken);

        Assert.Equal(2, deleted);
        var remaining = await context.RefreshTokens.AsNoTracking()
            .Select(row => row.Id)
            .ToListAsync(cancellationToken);
        Assert.Equal(
            new[] { rootId, childId, liveLegacyId }.OrderBy(id => id),
            remaining.OrderBy(id => id));

        // Legacy rotation of an interactive member's digest refuses without any write: the
        // conditional update excludes interactive rows, so no revocation and no replacement.
        var interactivePlaintext = "family-contract-token-" + rootId.ToString("N");
        var countBefore = remaining.Count;
        Assert.False(await repository.TryRotateAsync(
            interactivePlaintext,
            new RefreshTokenEntity
            {
                Id = Guid.NewGuid(),
                AccountId = accountId,
                TokenValue = RefreshTokenDigest.Compute("family-rotation-replacement"),
                CreatedAt = now,
                ExpiresAt = now.AddHours(1),
                AppId = AppId
            },
            cancellationToken));
        await context.SaveChangesAsync(cancellationToken);
        Assert.Equal(countBefore, await context.RefreshTokens.AsNoTracking().CountAsync(cancellationToken));
        var root = await context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == rootId, cancellationToken);
        Assert.True(root.IsRevoked);
        Assert.Equal(
            RefreshTokenFamilyTestSupport.ToSqliteMicroseconds(now.AddHours(-1)),
            RefreshTokenFamilyTestSupport.ToSqliteMicroseconds(root.ConsumedAt!.Value));
    }

    // ---- Acceptance 7 (family write API): revocations and child-first cleanup ----

    [Fact]
    public async Task FamilyRevocations_AreConditionalInteractiveOnlyAndFirstFactStaysAuthoritative()
    {
        await using var database = new SqliteFamilyDatabase();
        var options = await database.InitializeAsync();
        await using var context = new IdentityDbContext(options);
        var cancellationToken = TestContext.Current.CancellationToken;
        var (accountId, _, _, sessionId) = await SeedBasicsAsync(context);

        var authTime = DateTimeOffset.UtcNow.AddMinutes(-5);
        var now = DateTimeOffset.UtcNow;
        var rootId = Guid.NewGuid();
        var childId = Guid.NewGuid();
        var siblingId = Guid.NewGuid();
        var legacyId = Guid.NewGuid();
        await RefreshTokenFamilyTestSupport.InsertInteractiveMemberSqliteAsync(
            context, rootId, accountId, AppId, rootId, parentId: null, sessionId,
            CanonicalScope, authTime, now, now.AddHours(1));
        await RefreshTokenFamilyTestSupport.InsertInteractiveMemberSqliteAsync(
            context, childId, accountId, AppId, rootId, parentId: rootId, sessionId,
            CanonicalScope, authTime, now, now.AddHours(1));
        await RefreshTokenFamilyTestSupport.InsertInteractiveMemberSqliteAsync(
            context, siblingId, accountId, AppId, siblingId, parentId: null, sessionId,
            CanonicalScope, authTime, now, now.AddHours(1));
        await InsertLegacyRootAsync(context, legacyId, accountId, now);
        await context.SaveChangesAsync(cancellationToken);
        context.ChangeTracker.Clear();

        var repository = new RefreshTokenRepository(context);

        // The unscoped legacy revocation path never touches an interactive member (EV-33).
        // Client-authenticated named revocation has its separate EV-14 contract.
        Assert.False(await repository.TryRevokeAsync(
            "family-contract-token-" + siblingId.ToString("N"), cancellationToken));
        var liveSibling = await context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == siblingId, cancellationToken);
        Assert.False(liveSibling.IsRevoked);

        // EV-24 by root: exactly the named family, both members.
        Assert.Equal(2, await repository.RevokeFamilyAsync(rootId, cancellationToken));
        // Already-revoked members match nothing — the first fact stays authoritative.
        Assert.Equal(0, await repository.RevokeFamilyAsync(rootId, cancellationToken));
        // A legacy singleton id names no interactive family.
        Assert.Equal(0, await repository.RevokeFamilyAsync(legacyId, cancellationToken));

        var revokedAfterRoot = await context.RefreshTokens.AsNoTracking()
            .Where(row => row.IsRevoked).Select(row => row.Id).ToListAsync(cancellationToken);
        Assert.Equal(new[] { rootId, childId }.OrderBy(id => id), revokedAfterRoot.OrderBy(id => id));

        // EV-06/EV-15 by session: every interactive family of the session, never the legacy row.
        Assert.Equal(1, await repository.RevokeBySessionAsync(sessionId, cancellationToken));
        var survivors = await context.RefreshTokens.AsNoTracking()
            .Where(row => !row.IsRevoked).Select(row => row.Id).ToListAsync(cancellationToken);
        Assert.Equal(new[] { legacyId }, survivors);
    }

    [Fact]
    public async Task InteractiveFamilyCleanup_RemovesWholeExpiredFamiliesChildFirst()
    {
        await using var database = new SqliteFamilyDatabase();
        var options = await database.InitializeAsync();
        await using var context = new IdentityDbContext(options);
        var cancellationToken = TestContext.Current.CancellationToken;
        var (accountId, _, appId, sessionId) = await SeedBasicsAsync(context);

        var authTime = DateTimeOffset.UtcNow.AddMinutes(-5);
        var now = DateTimeOffset.UtcNow;

        // An expired interactive family with a child: removed whole, children before roots.
        var expiredRootId = Guid.NewGuid();
        var expiredChildId = Guid.NewGuid();
        await RefreshTokenFamilyTestSupport.InsertInteractiveMemberSqliteAsync(
            context, expiredRootId, accountId, AppId, expiredRootId, parentId: null, sessionId,
            CanonicalScope, authTime, now.AddHours(-3), now.AddHours(-1));
        await RefreshTokenFamilyTestSupport.InsertInteractiveMemberSqliteAsync(
            context, expiredChildId, accountId, AppId, expiredRootId, parentId: expiredRootId, sessionId,
            CanonicalScope, authTime, now.AddHours(-3), now.AddHours(-1));

        // A live family: stays whole even though cleanup runs.
        var liveRootId = Guid.NewGuid();
        await RefreshTokenFamilyTestSupport.InsertInteractiveMemberSqliteAsync(
            context, liveRootId, accountId, AppId, liveRootId, parentId: null, sessionId,
            CanonicalScope, authTime, now, now.AddDays(7));

        // An expired family whose root a retained consumed code still links: stays resolvable so
        // a proved replay can never become a missing code (SC-18).
        var linkedRootId = Guid.NewGuid();
        await RefreshTokenFamilyTestSupport.InsertInteractiveMemberSqliteAsync(
            context, linkedRootId, accountId, AppId, linkedRootId, parentId: null, sessionId,
            CanonicalScope, authTime, now.AddHours(-3), now.AddHours(-1));
        context.AuthorizationCodes.Add(new AuthorizationCodeEntity
        {
            Id = Guid.NewGuid(),
            CodeDigest = AuthorizationCodeDigest.Compute("family-cleanup-linked-code-0123456"),
            AppRegistrationId = appId,
            AccountId = accountId,
            IdentitySessionId = sessionId,
            RedirectUri = "https://client.example.test/callback",
            Scope = CanonicalScope,
            Nonce = "family-cleanup-linked-nonce",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            AuthTime = authTime,
            CreatedAt = now.AddHours(-2),
            ExpiresAt = now.AddHours(-2).AddMinutes(1),
            ConsumedAt = now.AddHours(-2),
            RefreshFamilyId = linkedRootId
        });
        await context.SaveChangesAsync(cancellationToken);
        context.ChangeTracker.Clear();

        var repository = new RefreshTokenRepository(context);
        Assert.Equal(2, await repository.RemoveInteractiveFamiliesAsync(now, cancellationToken));

        var remainingIds = await context.RefreshTokens.AsNoTracking()
            .Select(row => row.Id).ToListAsync(cancellationToken);
        Assert.Equal(
            new[] { liveRootId, linkedRootId }.OrderBy(id => id),
            remainingIds.OrderBy(id => id));

        // Once the linking code is gone the family becomes deletable.
        await context.Database.ExecuteSqlRawAsync(
            "DELETE FROM authorization_codes WHERE refresh_family_id IS NOT NULL", cancellationToken);
        Assert.Equal(1, await repository.RemoveInteractiveFamiliesAsync(now, cancellationToken));
        Assert.Equal(
            new[] { liveRootId },
            await context.RefreshTokens.AsNoTracking().Select(row => row.Id).ToListAsync(cancellationToken));

        // The session delete guard: the session survives while the live family references it,
        // even past its own retention window.
        var sessionRepository = new IdentitySessionRepository(context);
        Assert.Equal(0, await sessionRepository.RemoveExpiredBeforeAsync(
            now.AddYears(1), cancellationToken));
        Assert.Equal(1, await context.IdentitySessions.AsNoTracking()
            .CountAsync(row => row.Id == sessionId, cancellationToken));
    }

    // ---- Acceptance 8 (+9): the downgrade gate and the round trip ----

    [Fact]
    public async Task Down_IsGatedByInteractiveData_AndRoundTripsToTheCodeShape()
    {
        await using var database = new SqliteFamilyDatabase();
        var options = database.BuildOptions();
        await using var context = new IdentityDbContext(options);
        var cancellationToken = TestContext.Current.CancellationToken;
        var migrator = context.GetService<IMigrator>();
        // Staged at the family migration, not the latest: the retirement Down refuses every
        // walk from the current version, so the family gate and the round trip are exercised
        // inside the pre-retirement window where they live.
        await migrator.MigrateAsync(FamilyMigration, cancellationToken);

        var (accountId, _, appId, sessionId) = await SeedBasicsAsync(context);
        var authTime = DateTimeOffset.UtcNow.AddMinutes(-5);
        var now = DateTimeOffset.UtcNow;
        var rootId = Guid.NewGuid();
        await RefreshTokenFamilyTestSupport.InsertInteractiveMemberSqliteAsync(
            context, rootId, accountId, AppId, rootId, parentId: null, sessionId,
            CanonicalScope, authTime, now, now.AddHours(1), consumedAt: now);
        var legacyId = Guid.NewGuid();
        await InsertLegacyRootAsync(context, legacyId, accountId, now);
        var columnsWithFamily = await GetSqliteColumnsAsync(context, "refresh_tokens");
        var interactiveDigest = RefreshTokenFamilyTestSupport.DigestFor(rootId);

        // Gate state 1: an interactive row exists — Down fails and changes nothing.
        var blocked = await Record.ExceptionAsync(() =>
            migrator.MigrateAsync(CodeMigration, cancellationToken));
        Assert.NotNull(blocked);
        Assert.DoesNotContain(interactiveDigest, blocked!.ToString(), StringComparison.Ordinal);
        Assert.True(columnsWithFamily.SetEquals(await GetSqliteColumnsAsync(context, "refresh_tokens")));
        Assert.Equal(1, await context.RefreshTokens.AsNoTracking()
            .CountAsync(row => row.Id == rootId, cancellationToken));

        // Gate state 2: no interactive row, but a consumed code links a root — Down still fails.
        await context.Database.ExecuteSqlInterpolatedAsync(
            $"DELETE FROM refresh_tokens WHERE id = {rootId}", cancellationToken);
        var tokensBefore = await DumpSqlAsync(context, LegacyTokenDumpSql);
        context.AuthorizationCodes.Add(new AuthorizationCodeEntity
        {
            Id = Guid.NewGuid(),
            CodeDigest = AuthorizationCodeDigest.Compute("family-gate-code-0123456789abcdefghijk"),
            AppRegistrationId = appId,
            AccountId = accountId,
            IdentitySessionId = sessionId,
            RedirectUri = "https://client.example.test/callback",
            Scope = CanonicalScope,
            Nonce = "family-gate-nonce",
            CodeChallenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            AuthTime = authTime,
            CreatedAt = now,
            ExpiresAt = now.AddSeconds(IdentityConstants.AuthorizationCodeLifetimeSeconds),
            ConsumedAt = now,
            RefreshFamilyId = legacyId
        });
        await context.SaveChangesAsync(cancellationToken);
        context.ChangeTracker.Clear();

        Assert.NotNull(await Record.ExceptionAsync(() =>
            migrator.MigrateAsync(CodeMigration, cancellationToken)));
        Assert.True(columnsWithFamily.SetEquals(await GetSqliteColumnsAsync(context, "refresh_tokens")));

        // Gate cleared: the code link is gone, Down succeeds, and the shape returns to the
        // AddAuthorizationCodes contract.
        await context.Database.ExecuteSqlRawAsync(
            "DELETE FROM authorization_codes WHERE refresh_family_id IS NOT NULL", cancellationToken);
        await migrator.MigrateAsync(CodeMigration, cancellationToken);

        var columnsAfterDown = await GetSqliteColumnsAsync(context, "refresh_tokens");
        Assert.DoesNotContain("family_id", columnsAfterDown);
        Assert.DoesNotContain("parent_id", columnsAfterDown);
        Assert.DoesNotContain("identity_session_id", columnsAfterDown);
        Assert.DoesNotContain("scope", columnsAfterDown);
        Assert.DoesNotContain("auth_time", columnsAfterDown);
        Assert.DoesNotContain("consumed_at", columnsAfterDown);
        var codeForeignKeys = await ReadPragmaAsync(
            context, "PRAGMA foreign_key_list(authorization_codes)");
        Assert.Equal(3, codeForeignKeys.Count);
        Assert.Equal(tokensBefore, await DumpSqlAsync(context, LegacyTokenDumpSql));

        // Up again: the legacy row is once more the singleton root of its own family.
        await migrator.MigrateAsync(cancellationToken: cancellationToken);
        Assert.Equal(tokensBefore, await DumpSqlAsync(context, LegacyTokenDumpSql));
        var familyDump = await DumpSqlAsync(context, """
            SELECT id, family_id, parent_id, identity_session_id, scope, auth_time, consumed_at
            FROM refresh_tokens ORDER BY id
            """);
        var line = Assert.Single(familyDump.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.TrimEnd('\r')));
        var fields = line.Split('|');
        Assert.Equal(fields[0], fields[1]);
        Assert.Equal("NULL", fields[2]);
        Assert.Equal("NULL", fields[3]);
    }

    // ---- Helpers ----

    /// <summary>
    /// The comparable projection of every legacy column, ordered so the upgrade and the round
    /// trip can compare dumps byte for byte.
    /// </summary>
    private const string LegacyTokenDumpSql = """
        SELECT id, account_id, token_value, created_at, expires_at, is_revoked, app_id,
               ifnull(ldap_credential_id, ''), ifnull(sms_user_login_id, ''),
               ifnull(wechat_user_login_id, ''), ifnull(source_app_id, '')
        FROM refresh_tokens
        ORDER BY id
        """;

    private const string CodeDumpSql = """
        SELECT id, code_digest, app_registration_id, account_id, identity_session_id,
               redirect_uri, scope, nonce, code_challenge, auth_time, created_at, expires_at,
               consumed_at
        FROM authorization_codes
        ORDER BY id
        """;

    private static async Task<(Guid AccountId, Guid CredentialId, Guid AppId, Guid SessionId)>
        SeedBasicsAsync(IdentityDbContext context)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var appId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        context.Accounts.Add(new AccountEntity
        {
            Id = accountId, IsActive = true, CreatedAt = now
        });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = credentialId, AccountId = accountId, Username = "family-contract-user",
            PasswordHash = "hash", CreatedAt = now
        });
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = appId, AppId = AppId, AppSecretHash = "hash",
            AppName = "Family Contract", IsActive = true, CreatedAt = now
        });
        context.IdentitySessions.Add(new IdentitySessionEntity
        {
            Id = sessionId,
            AccountId = accountId,
            PasswordCredentialId = credentialId,
            AuthMethod = IdentityConstants.AuthMethodPassword,
            AuthTime = now,
            LastSeenAt = now,
            IdleExpiresAt = now.AddMinutes(IdentityConstants.IdentitySessionIdleTimeoutMinutes),
            AbsoluteExpiresAt = now.AddSeconds(IdentityConstants.MaxIdentitySessionAgeSeconds)
        });
        await context.SaveChangesAsync(cancellationToken);
        context.ChangeTracker.Clear();
        return (accountId, credentialId, appId, sessionId);
    }

    private static Task InsertLegacyRootAsync(
        IdentityDbContext context,
        Guid tokenId,
        Guid accountId,
        DateTimeOffset now,
        DateTimeOffset? expiresAt = null,
        bool isRevoked = false)
    {
        context.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = tokenId,
            FamilyId = tokenId,
            AccountId = accountId,
            TokenValue = RefreshTokenFamilyTestSupport.DigestFor(tokenId),
            CreatedAt = now,
            ExpiresAt = expiresAt ?? now.AddHours(1),
            IsRevoked = isRevoked,
            AppId = AppId
        });
        return context.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    private static async Task AssertDeleteRejectedAsync(
        IdentityDbContext context, string table, Guid id)
    {
        // The id rides a parameter so the Guid TEXT representation matches the EF-written rows;
        // the table name is one of this test's own two literals.
        var exception = await Record.ExceptionAsync(() =>
            table == "identity_sessions"
                ? context.Database.ExecuteSqlInterpolatedAsync(
                    $"DELETE FROM identity_sessions WHERE id = {id}",
                    TestContext.Current.CancellationToken)
                : context.Database.ExecuteSqlInterpolatedAsync(
                    $"DELETE FROM refresh_tokens WHERE id = {id}",
                    TestContext.Current.CancellationToken));
        Assert.IsType<SqliteException>(exception);
    }

    /// <summary>
    /// The corrupt-write workhorse: one fully parameterized INSERT whose nullable holes let each
    /// case deviate from exactly one admissible shape. Parameter binding also keeps the Guid TEXT
    /// representation identical to every EF-written row, so reference matching is by value only.
    /// </summary>
    private static Task<int> InsertFamilyRowAsync(
        IdentityDbContext context,
        Guid id,
        Guid accountId,
        string appId,
        Guid familyId,
        Guid? parentId,
        Guid? sessionId,
        string? scope,
        DateTimeOffset? authTime,
        DateTimeOffset? consumedAt)
    {
        var created = DateTimeOffset.UtcNow;
        var expires = created.AddHours(1);
        var tokenDigest = RefreshTokenFamilyTestSupport.DigestFor(id);
        var createdMicros = RefreshTokenFamilyTestSupport.ToSqliteMicroseconds(created);
        var expiresMicros = RefreshTokenFamilyTestSupport.ToSqliteMicroseconds(expires);
        long? authTimeMicros = authTime is null
            ? null
            : RefreshTokenFamilyTestSupport.ToSqliteMicroseconds(authTime.Value);
        long? consumedAtMicros = consumedAt is null
            ? null
            : RefreshTokenFamilyTestSupport.ToSqliteMicroseconds(consumedAt.Value);
        return context.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO refresh_tokens
                (id, account_id, token_value, created_at, expires_at, is_revoked, app_id,
                 family_id, parent_id, identity_session_id, scope, auth_time, consumed_at)
            VALUES
                ({id}, {accountId}, {tokenDigest}, {createdMicros}, {expiresMicros}, 0, {appId},
                 {familyId}, {parentId}, {sessionId}, {scope}, {authTimeMicros}, {consumedAtMicros});
            """, TestContext.Current.CancellationToken);
    }

    private static long Micros(DateTimeOffset value) =>
        RefreshTokenFamilyTestSupport.ToSqliteMicroseconds(value);

    private static async Task<string> DumpSqlAsync(IdentityDbContext context, string sql)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = sql;
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        var dump = new StringBuilder();
        while (await reader.ReadAsync(TestContext.Current.CancellationToken))
        {
            for (var ordinal = 0; ordinal < reader.FieldCount; ordinal++)
            {
                dump.Append(reader.IsDBNull(ordinal) ? "NULL" : reader.GetValue(ordinal)?.ToString())
                    .Append('|');
            }

            dump.AppendLine();
        }

        await context.Database.CloseConnectionAsync();
        return dump.ToString();
    }

    private static async Task<string> ReadScalarAsync(IdentityDbContext context, string sql)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = sql;
        var result = await command.ExecuteScalarAsync(TestContext.Current.CancellationToken);
        await context.Database.CloseConnectionAsync();
        return result as string ?? string.Empty;
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

        await context.Database.CloseConnectionAsync();
        return rows;
    }

    private static async Task<HashSet<string>> GetSqliteColumnsAsync(
        IdentityDbContext context,
        string tableName)
    {
        var rows = await ReadPragmaAsync(context, $"PRAGMA table_info({tableName})");
        return rows.Select(row => row[1]).ToHashSet(StringComparer.Ordinal);
    }

    private sealed class SqliteFamilyDatabase : IAsyncDisposable
    {
        private readonly string _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-family-{Guid.NewGuid():N}.db");

        public DbContextOptions<IdentityDbContext> BuildOptions()
        {
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseSqlite(
                $"Data Source={_databasePath}",
                providerOptions =>
                    providerOptions.MigrationsAssembly("SignaCore.Database.Migrations.Sqlite"));
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
}
