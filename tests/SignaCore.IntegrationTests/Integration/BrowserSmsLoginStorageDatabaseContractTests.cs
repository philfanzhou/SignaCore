using System.Data.Common;
using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using SignaCore.IntegrationTests.Integration;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The #443 browser SMS login storage (<c>AC-15</c>) on both providers: the <c>PS-04</c>
/// auth-method reference check and restrictive SMS identity reference, the <c>PS-03</c>
/// <c>sms_code_send_count</c> default and check, the <c>PS-24</c> <c>oidc-sms-code</c> policy,
/// the upgrade over sessions still referenced by codes and interactive refresh families, the
/// fail-closed <c>Down</c> gate and the round trip back to the previous schema, and the
/// single-transaction PostgreSQL upgrade under failure and cancellation.
/// <para>
/// The <c>DatabaseContractTests</c> suffix is deliberate: CI's Database Contract Matrix filters on
/// it and supplies <c>RUN_SIGNACORE_DATABASE_CONTRACTS=true</c> for the PostgreSQL half.
/// </para>
/// </summary>
[Collection(SqliteProcessState.CollectionName)]
[UsesProcessWideSqlitePoolClearing]
public sealed class BrowserSmsLoginStorageDatabaseContractTests
{
    private const string MigrationSuffix = "_AddBrowserSmsLoginStorage";
    private const string AppId = "sms-storage-client";
    private static readonly string[] AffectedTables = ["identity_sessions", "authorization_requests", "oidc_rate_limit_buckets"];
    private static readonly DateTimeOffset Instant = new(2026, 9, 29, 0, 0, 0, TimeSpan.Zero);
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    // ---- The fresh schema: PS-04 check, SMS reference, count column, and policy ----

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task FreshSchema_EnforcesTheAuthMethodReferenceTheSendCountAndTheSmsCodePolicy(string provider)
    {
        await using var fixture = await Harness.CreateAsync(provider);
        await using (var db = fixture.Context())
        {
            await db.Database.MigrateAsync(Ct);
            Assert.False(db.Database.HasPendingModelChanges());
        }

        var seed = await fixture.SeedIdentitiesAsync();

        // Valid rows of both auth methods are admitted; the Sms row comes from the store.
        await using (var db = fixture.Context())
        {
            db.IdentitySessions.Add(Session(seed.AccountId, IdentityConstants.AuthMethodPassword, seed.CredentialId, null));
            await db.SaveChangesAsync(Ct);
            var store = new IdentitySessionStore(new IdentitySessionRepository(db), new EfCoreUnitOfWork(db));
            var sms = await store.CreateSmsAsync(seed.AccountId, seed.SmsLoginId, Instant, Ct);
            Assert.Equal(IdentityConstants.AuthMethodSms, sms.AuthMethod);
            Assert.Null(sms.PasswordCredentialId);
            Assert.Equal(seed.SmsLoginId, sms.SmsUserLoginId);

            // The store refuses another account's SMS identity and a non-SMS identity with zero
            // writes and no identifier in the message.
            foreach (var foreign in new[] { seed.OtherSmsLoginId, seed.WechatLoginId })
            {
                var refusal = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    store.CreateSmsAsync(seed.AccountId, foreign, Instant, Ct));
                Assert.DoesNotContain(foreign.ToString("D"), refusal.ToString(), StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(seed.AccountId.ToString("D"), refusal.ToString(), StringComparison.OrdinalIgnoreCase);
            }
        }

        Assert.Equal(2, await fixture.CountAsync("identity_sessions"));

        // The CHECK rejects both references, neither, a mismatch in either direction, and an
        // unknown auth method, whatever reference it carries.
        foreach (var invalid in new[]
        {
            Session(seed.AccountId, IdentityConstants.AuthMethodPassword, seed.CredentialId, seed.SmsLoginId),
            Session(seed.AccountId, IdentityConstants.AuthMethodSms, seed.CredentialId, seed.SmsLoginId),
            Session(seed.AccountId, IdentityConstants.AuthMethodPassword, null, null),
            Session(seed.AccountId, IdentityConstants.AuthMethodSms, null, null),
            Session(seed.AccountId, IdentityConstants.AuthMethodSms, seed.CredentialId, null),
            Session(seed.AccountId, IdentityConstants.AuthMethodPassword, null, seed.SmsLoginId),
            Session(seed.AccountId, IdentityConstants.AuthMethodLdap, seed.CredentialId, null),
            Session(seed.AccountId, "password", seed.CredentialId, null),
            Session(seed.AccountId, "SMS", null, seed.SmsLoginId)
        })
        {
            await using var write = fixture.Context();
            write.IdentitySessions.Add(invalid);
            await Assert.ThrowsAsync<DbUpdateException>(() => write.SaveChangesAsync(Ct));
        }

        // An orphan SMS reference fails, and deleting a referenced SMS login identity fails
        // without cascading.
        await using (var write = fixture.Context())
        {
            write.IdentitySessions.Add(Session(seed.AccountId, IdentityConstants.AuthMethodSms, null, Guid.NewGuid()));
            await Assert.ThrowsAsync<DbUpdateException>(() => write.SaveChangesAsync(Ct));
        }

        await using (var write = fixture.Context())
        {
            write.UserLogins.Remove(await write.UserLogins.SingleAsync(row => row.Id == seed.SmsLoginId, Ct));
            await Assert.ThrowsAsync<DbUpdateException>(() => write.SaveChangesAsync(Ct));
        }

        Assert.Equal(2, await fixture.CountAsync("identity_sessions"));
        Assert.Equal(1, await fixture.CountAsync("user_logins", $"id = {fixture.GuidLiteral(seed.SmsLoginId)}"));

        // PS-03: an INSERT that omits the count gets 0, the EF model inserts 0, and a negative
        // count is rejected on insert and on update.
        var rawHandle = LoginHandleDigest.Compute("sms-storage-raw-handle-0123456789abcdefghij");
        await using (var db = fixture.Context())
        {
            await BrowserSmsStorageTestSupport.InsertLegacyAuthorizationRequestAsync(
                db, Guid.NewGuid(), rawHandle, seed.AppRegistrationId, Instant);
            var modelled = Continuation(seed.AppRegistrationId, "sms-storage-model-handle-0123456789abcdefgh");
            db.AuthorizationRequests.Add(modelled);
            await db.SaveChangesAsync(Ct);
            db.ChangeTracker.Clear();
            Assert.All(await db.AuthorizationRequests.AsNoTracking().ToListAsync(Ct), row => Assert.Equal(0, row.SmsCodeSendCount));
        }

        Assert.Equal(2, await fixture.CountAsync("authorization_requests", "sms_code_send_count = 0"));
        await using (var db = fixture.Context())
        {
            var negative = Continuation(seed.AppRegistrationId, "sms-storage-negative-handle-0123456789abcd");
            negative.SmsCodeSendCount = -1;
            db.AuthorizationRequests.Add(negative);
            await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync(Ct));
        }

        await using (var db = fixture.Context())
        {
            await Assert.ThrowsAnyAsync<DbException>(() => db.Database.ExecuteSqlRawAsync(
                "UPDATE authorization_requests SET sms_code_send_count = -1", Ct));
            Assert.Equal(1, await db.Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE authorization_requests SET sms_code_send_count = 5 WHERE handle_digest = {rawHandle}", Ct));
        }

        Assert.Equal(1, await fixture.CountAsync("authorization_requests", "sms_code_send_count = 5"));

        // PS-24: oidc-sms-code is admitted, an unknown policy is still rejected, and the budget
        // table carries the fixed 20-per-window budget under the same name.
        await using (var db = fixture.Context())
        {
            db.OidcRateLimitBuckets.Add(Bucket("oidc-sms-code"));
            await db.SaveChangesAsync(Ct);
        }

        await using (var db = fixture.Context())
        {
            db.OidcRateLimitBuckets.Add(Bucket("oidc-sms-codes"));
            await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync(Ct));
        }

        Assert.Equal(1, await fixture.CountAsync("oidc_rate_limit_buckets", "policy = 'oidc-sms-code'"));
        Assert.True(SignaCore.Database.RateLimiting.OidcRateLimitBudgets.TryGetPermitLimit("oidc-sms-code", out var budget));
        Assert.Equal(20, budget);
    }

    // ---- The upgrade over live, referenced Password sessions ----

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Upgrade_PreservesReferencedSessionsContinuationsAndBuckets(string provider)
    {
        await using var fixture = await Harness.CreateAsync(provider);
        var (target, previous) = await fixture.MigrationPairAsync();
        await using (var db = fixture.Context())
        {
            await db.GetService<IMigrator>().MigrateAsync(previous, Ct);
        }

        var seed = await fixture.SeedLegacyGraphAsync();
        var schemaBefore = await fixture.SchemaAsync();
        var dataBefore = await fixture.LegacyDataAsync();

        await using (var db = fixture.Context())
        {
            await db.GetService<IMigrator>().MigrateAsync(target, Ct);
            Assert.False(db.Database.HasPendingModelChanges());
        }

        // Every legacy value, including the referencing code and refresh rows, is unchanged;
        // every existing session becomes a Password row with no SMS reference and every existing
        // continuation starts with a zero count.
        Assert.Equal(dataBefore, await fixture.LegacyDataAsync());
        Assert.Equal(2, await fixture.CountAsync("identity_sessions", "sms_user_login_id IS NULL AND auth_method = 'Password'"));
        Assert.Equal(1, await fixture.CountAsync("authorization_requests", "sms_code_send_count = 0"));
        Assert.NotEqual(schemaBefore, await fixture.SchemaAsync());
        var indexes = await fixture.IndexNamesAsync();
        Assert.Contains("IX_identity_sessions_sms_user_login_id", indexes);
        foreach (var name in new[]
        {
            "IX_identity_sessions_account_id", "IX_identity_sessions_password_credential_id",
            "IX_authorization_requests_handle_digest", "IX_authorization_requests_app_registration_id",
            "IX_oidc_rate_limit_buckets_window_expires_at", "IX_authorization_codes_identity_session_id",
            "IX_refresh_tokens_identity_session_id"
        })
        {
            Assert.Contains(name, indexes);
        }

        if (provider == "SQLite")
        {
            Assert.Empty(await fixture.RowsAsync("PRAGMA foreign_key_check"));
        }

        // The child references to the rebuilt session table still restrict.
        await using (var db = fixture.Context())
        {
            await Assert.ThrowsAnyAsync<DbException>(() => db.Database.ExecuteSqlInterpolatedAsync(
                $"DELETE FROM identity_sessions WHERE id = {seed.ReferencedSessionId}", Ct));
        }

        // The existing Password session is still readable, slidable, and revocable through the
        // current store; the revoked one keeps its first revocation fact.
        await using (var db = fixture.Context())
        {
            var store = new IdentitySessionStore(new IdentitySessionRepository(db), new EfCoreUnitOfWork(db));
            var now = seed.SessionAuthTime.AddMinutes(5);
            var lookup = await store.GetAsync(seed.ReferencedSessionId, now, Ct);
            Assert.Equal(IdentitySessionState.Active, lookup.State);
            Assert.Equal(seed.CredentialId, lookup.Session!.PasswordCredentialId);
            Assert.Null(lookup.Session.SmsUserLoginId);
            Assert.Equal(IdentitySessionActivityResult.Touched, await store.TouchActivityAsync(seed.ReferencedSessionId, now, Ct));
            Assert.Equal(
                IdentitySessionRevocationResult.Revoked,
                await store.RevokeAsync(seed.ReferencedSessionId, IdentitySessionRevocationReason.Logout, now, Ct));
            Assert.Equal(
                IdentitySessionRevocationResult.AlreadyRevoked,
                await store.RevokeAsync(seed.RevokedSessionId, IdentitySessionRevocationReason.Logout, now, Ct));
            Assert.Equal(IdentitySessionState.Revoked, (await store.GetAsync(seed.RevokedSessionId, now, Ct)).State);
        }
    }

    // ---- The fail-closed Down gate and the round trip ----

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Down_IsGatedBySmsSessionsAndSmsCodeBuckets_AndRoundTripsToThePreviousSchema(string provider)
    {
        await using var fixture = await Harness.CreateAsync(provider);
        var (target, previous) = await fixture.MigrationPairAsync();
        await using (var db = fixture.Context())
        {
            await db.GetService<IMigrator>().MigrateAsync(previous, Ct);
        }

        var previousSchema = await fixture.SchemaAsync();
        var seed = await fixture.SeedLegacyGraphAsync();
        await using (var db = fixture.Context())
        {
            await db.GetService<IMigrator>().MigrateAsync(target, Ct);
        }

        var identities = await fixture.SeedIdentitiesAsync("sms-down");
        Guid smsSessionId;
        await using (var db = fixture.Context())
        {
            // A counted continuation does not block Down: the count column rolls back freely.
            Assert.Equal(1, await db.Database.ExecuteSqlRawAsync(
                "UPDATE authorization_requests SET sms_code_send_count = 3", Ct));
            var store = new IdentitySessionStore(new IdentitySessionRepository(db), new EfCoreUnitOfWork(db));
            smsSessionId = (await store.CreateSmsAsync(identities.AccountId, identities.SmsLoginId, Instant, Ct)).Id;
        }

        // Gate state 1: an Sms session exists — Down fails and changes nothing.
        var schemaAtTarget = await fixture.SchemaAsync();
        var dataAtTarget = await fixture.CurrentDataAsync();
        await AssertDownBlockedAsync(fixture, previous, target, schemaAtTarget, dataAtTarget, smsSessionId);

        // Gate state 2: no Sms session, but an oidc-sms-code bucket — Down still fails.
        await using (var db = fixture.Context())
        {
            Assert.Equal(1, await db.Database.ExecuteSqlInterpolatedAsync(
                $"DELETE FROM identity_sessions WHERE id = {smsSessionId}", Ct));
            db.OidcRateLimitBuckets.Add(Bucket("oidc-sms-code"));
            await db.SaveChangesAsync(Ct);
        }

        dataAtTarget = await fixture.CurrentDataAsync();
        await AssertDownBlockedAsync(fixture, previous, target, schemaAtTarget, dataAtTarget, smsSessionId);

        // Gate cleared: Down restores exactly the previous schema — nullability, no column
        // default, no zero-GUID backfill, and the six-policy check — and keeps every legacy row.
        await using (var db = fixture.Context())
        {
            await db.Database.ExecuteSqlRawAsync("DELETE FROM oidc_rate_limit_buckets WHERE policy = 'oidc-sms-code'", Ct);
        }

        var legacyData = await fixture.LegacyDataAsync();
        await using (var db = fixture.Context())
        {
            await db.GetService<IMigrator>().MigrateAsync(previous, Ct);
            Assert.DoesNotContain(target, await db.Database.GetAppliedMigrationsAsync(Ct));
        }

        Assert.Equal(previousSchema, await fixture.SchemaAsync());
        Assert.Equal(legacyData, await fixture.LegacyDataAsync());
        Assert.Equal(0, await fixture.CountAsync("identity_sessions", "password_credential_id = " + fixture.GuidLiteral(Guid.Empty)));
        if (provider == "SQLite")
        {
            Assert.Empty(await fixture.RowsAsync("PRAGMA foreign_key_check"));
        }

        // The previous schema is the previous contract again: a Password row without a
        // credential and an oidc-sms-code bucket are both rejected.
        await using (var db = fixture.Context())
        {
            var digest = new string('e', 64);
            await Assert.ThrowsAnyAsync<DbException>(() => provider == "SQLite"
                ? db.Database.ExecuteSqlInterpolatedAsync($"""
                    INSERT INTO oidc_rate_limit_buckets (policy, partition_digest, window_expires_at, permit_count)
                    VALUES ('oidc-sms-code', {digest}, {BrowserSmsStorageTestSupport.ToMicroseconds(Instant)}, 1)
                    """, Ct)
                : db.Database.ExecuteSqlInterpolatedAsync($"""
                    INSERT INTO oidc_rate_limit_buckets (policy, partition_digest, window_expires_at, permit_count)
                    VALUES ('oidc-sms-code', {digest}, {Instant}, 1)
                    """, Ct));
        }

        // Up again succeeds, and the legacy rows carry the new defaults once more.
        await using (var db = fixture.Context())
        {
            await db.GetService<IMigrator>().MigrateAsync(target, Ct);
            Assert.Contains(target, await db.Database.GetAppliedMigrationsAsync(Ct));
        }

        Assert.Equal(schemaAtTarget, await fixture.SchemaAsync());
        Assert.Equal(legacyData, await fixture.LegacyDataAsync());
        Assert.Equal(1, await fixture.CountAsync("authorization_requests", "sms_code_send_count = 0"));
        Assert.Equal(1, await fixture.CountAsync("identity_sessions", $"id = {fixture.GuidLiteral(seed.ReferencedSessionId)} AND sms_user_login_id IS NULL"));
    }

    // ---- PostgreSQL: the upgrade is one transaction under failure and cancellation ----

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PostgreSqlUpgrade_FailureOrCancellationRollsBackAsOneTransaction(bool cancel)
    {
        await using var fixture = await Harness.CreateAsync("PostgreSQL");
        var (target, previous) = await fixture.MigrationPairAsync();
        await using (var db = fixture.Context())
        {
            await db.GetService<IMigrator>().MigrateAsync(previous, Ct);
        }

        await fixture.SeedLegacyGraphAsync();
        var schemaBefore = await fixture.SchemaAsync();
        var dataBefore = await fixture.LegacyDataAsync();

        using var caller = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var fault = new AfterCheckFault(cancel ? caller : null);
        await using (var db = fixture.Context(fault))
        {
            var upgrade = db.GetService<IMigrator>().MigrateAsync(target, caller.Token);
            if (cancel)
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => upgrade);
            }
            else
            {
                await Assert.ThrowsAsync<InvalidOperationException>(() => upgrade);
            }

            Assert.True(fault.Observed);
        }

        // The ALTERs before the fault were part of the same transaction: nothing survives.
        await using (var db = fixture.Context())
        {
            Assert.DoesNotContain(target, await db.Database.GetAppliedMigrationsAsync(Ct));
        }

        Assert.Equal(schemaBefore, await fixture.SchemaAsync());
        Assert.Equal(dataBefore, await fixture.LegacyDataAsync());

        await using (var db = fixture.Context())
        {
            await db.GetService<IMigrator>().MigrateAsync(target, Ct);
            Assert.Contains(target, await db.Database.GetAppliedMigrationsAsync(Ct));
        }

        Assert.Equal(dataBefore, await fixture.LegacyDataAsync());
    }

    private static async Task AssertDownBlockedAsync(
        Harness fixture,
        string previous,
        string target,
        string schemaAtTarget,
        string dataAtTarget,
        Guid smsSessionId)
    {
        await using (var db = fixture.Context())
        {
            var blocked = await Record.ExceptionAsync(() => db.GetService<IMigrator>().MigrateAsync(previous, Ct));
            Assert.NotNull(blocked);
            Assert.DoesNotContain(smsSessionId.ToString("D"), blocked.ToString(), StringComparison.OrdinalIgnoreCase);
        }

        await using (var db = fixture.Context())
        {
            Assert.Contains(target, await db.Database.GetAppliedMigrationsAsync(Ct));
        }

        Assert.Equal(schemaAtTarget, await fixture.SchemaAsync());
        Assert.Equal(dataAtTarget, await fixture.CurrentDataAsync());
    }

    private static IdentitySessionEntity Session(Guid accountId, string authMethod, Guid? credentialId, Guid? smsLoginId) => new()
    {
        Id = Guid.NewGuid(),
        AccountId = accountId,
        PasswordCredentialId = credentialId,
        SmsUserLoginId = smsLoginId,
        AuthMethod = authMethod,
        AuthTime = Instant,
        LastSeenAt = Instant,
        IdleExpiresAt = Instant.AddMinutes(IdentityConstants.IdentitySessionIdleTimeoutMinutes),
        AbsoluteExpiresAt = Instant.AddSeconds(IdentityConstants.MaxIdentitySessionAgeSeconds)
    };

    private static AuthorizationRequestEntity Continuation(Guid appRegistrationId, string handle) => new()
    {
        Id = Guid.NewGuid(),
        HandleDigest = LoginHandleDigest.Compute(handle),
        AppRegistrationId = appRegistrationId,
        RedirectUri = "https://client.example.test/callback",
        Scope = "openid",
        State = "sms-storage-state",
        Nonce = "sms-storage-nonce",
        CodeChallenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        CreatedAt = Instant,
        ExpiresAt = Instant.AddMinutes(IdentityConstants.LoginHandleLifetimeMinutes)
    };

    private static OidcRateLimitBucketEntity Bucket(string policy) => new()
    {
        Policy = policy,
        PartitionDigest = new string('a', 64),
        PermitCount = 1,
        WindowExpiresAt = Instant.AddMinutes(1)
    };

    /// <summary>Fails (or cancels) the upgrade right after its auth-method check was added.</summary>
    private sealed class AfterCheckFault(CancellationTokenSource? caller) : DbCommandInterceptor
    {
        public bool Observed { get; private set; }

        public override ValueTask<int> NonQueryExecutedAsync(
            DbCommand command,
            CommandExecutedEventData eventData,
            int result,
            CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("CK_identity_sessions_auth_method_reference", StringComparison.Ordinal))
            {
                Observed = true;
                if (caller is not null)
                {
                    caller.Cancel();
                    throw new OperationCanceledException(caller.Token);
                }

                throw new InvalidOperationException("Injected failure after schema command execution.");
            }

            return ValueTask.FromResult(result);
        }
    }

    private sealed record Identities(
        Guid AccountId,
        Guid CredentialId,
        Guid SmsLoginId,
        Guid OtherSmsLoginId,
        Guid WechatLoginId,
        Guid AppRegistrationId);

    private sealed record LegacyGraph(
        Guid CredentialId,
        Guid ReferencedSessionId,
        Guid RevokedSessionId,
        DateTimeOffset SessionAuthTime);

    private sealed class Harness(string provider, DatabaseOptions database, string? path, PostgreSqlContainer? container) : IAsyncDisposable
    {
        private bool Sqlite => provider == "SQLite";

        public static async Task<Harness> CreateAsync(string provider)
        {
            PostgreSqlContainer? container = null;
            string? path = null;
            try
            {
                string connection;
                if (provider == "PostgreSQL")
                {
                    Assert.SkipUnless(
                        Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true",
                        "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL browser SMS storage contract.");
                    container = new PostgreSqlBuilder(
                        Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") ?? "postgres:15-alpine").Build();
                    await container.StartAsync(Ct);
                    connection = container.GetConnectionString();
                }
                else
                {
                    path = Path.Combine(Path.GetTempPath(), $"sms-storage-{Guid.NewGuid():N}.db");
                    connection = $"Data Source={path};Pooling=false";
                }

                return new Harness(
                    provider,
                    new DatabaseOptions
                    {
                        Provider = provider,
                        ServerVersion = provider == "PostgreSQL" ? "15" : null,
                        ConnectionString = connection
                    },
                    path,
                    container);
            }
            catch
            {
                if (container is not null)
                {
                    await container.DisposeAsync();
                }

                throw;
            }
        }

        public IdentityDbContext Context(IInterceptor? interceptor = null)
        {
            var builder = new DbContextOptionsBuilder<IdentityDbContext>();
            builder.UseIdentityDatabase(database, enableRetryOnFailure: false).UseLoggerFactory(NullLoggerFactory.Instance);
            if (interceptor is not null)
            {
                builder.AddInterceptors(interceptor);
            }

            return new IdentityDbContext(builder.Options);
        }

        public async Task<(string Target, string Previous)> MigrationPairAsync()
        {
            await using var db = Context();
            var migrations = db.Database.GetMigrations().ToArray();
            var target = migrations.Single(id => id.EndsWith(MigrationSuffix, StringComparison.Ordinal));
            return (target, migrations[Array.IndexOf(migrations, target) - 1]);
        }

        /// <summary>A literal for a GUID in the provider's own storage representation.</summary>
        public string GuidLiteral(Guid value) =>
            Sqlite ? $"'{value.ToString("D").ToUpperInvariant()}'" : $"'{value:D}'::uuid";

        /// <summary>Account, credential, SMS and WeChat identities, and an application on the current model.</summary>
        public async Task<Identities> SeedIdentitiesAsync(string prefix = "sms-fresh")
        {
            await using var db = Context();
            var accountId = Guid.NewGuid();
            var otherAccountId = Guid.NewGuid();
            var credentialId = Guid.NewGuid();
            var smsLoginId = Guid.NewGuid();
            var otherSmsLoginId = Guid.NewGuid();
            var wechatLoginId = Guid.NewGuid();
            var appRegistrationId = Guid.NewGuid();
            db.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = Instant });
            db.Accounts.Add(new AccountEntity { Id = otherAccountId, IsActive = true, CreatedAt = Instant });
            db.PasswordCredentials.Add(new PasswordCredentialEntity
            {
                Id = credentialId, AccountId = accountId, Username = prefix + "-user",
                PasswordHash = "synthetic-hash", CreatedAt = Instant
            });
            db.UserLogins.Add(new UserLoginEntity
            {
                Id = smsLoginId, AccountId = accountId,
                ProviderName = IdentityConstants.AuthMethodSms, ProviderUserId = "+8613800000001"
            });
            db.UserLogins.Add(new UserLoginEntity
            {
                Id = otherSmsLoginId, AccountId = otherAccountId,
                ProviderName = IdentityConstants.AuthMethodSms, ProviderUserId = "+8613800000002"
            });
            db.UserLogins.Add(new UserLoginEntity
            {
                Id = wechatLoginId, AccountId = accountId,
                ProviderName = IdentityConstants.AuthMethodWechat, ProviderUserId = prefix + "-open-id"
            });
            db.AppRegistrations.Add(new AppRegistrationEntity
            {
                Id = appRegistrationId, AppId = prefix + "-app", AppName = "SMS storage",
                AppSecretHash = "synthetic-hash", IsActive = true, CreatedAt = Instant
            });
            await db.SaveChangesAsync(Ct);
            return new Identities(accountId, credentialId, smsLoginId, otherSmsLoginId, wechatLoginId, appRegistrationId);
        }

        /// <summary>
        /// The pre-#443 graph, seeded with only the columns every earlier version has: a live
        /// Password session referenced by a consumed code and by an interactive refresh family,
        /// a revoked Password session, one continuation, and one bucket of an existing policy.
        /// </summary>
        public async Task<LegacyGraph> SeedLegacyGraphAsync()
        {
            await using var db = Context();
            var accountId = Guid.NewGuid();
            var credentialId = Guid.NewGuid();
            var appRegistrationId = Guid.NewGuid();
            var referencedSessionId = Guid.NewGuid();
            var revokedSessionId = Guid.NewGuid();
            var rootId = Guid.NewGuid();
            var authTime = new DateTimeOffset(DateTimeOffset.UtcNow.UtcTicks / 10 * 10, TimeSpan.Zero).AddMinutes(-5);
            db.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = Instant });
            db.PasswordCredentials.Add(new PasswordCredentialEntity
            {
                Id = credentialId, AccountId = accountId, Username = "sms-legacy-user",
                PasswordHash = "synthetic-hash", CreatedAt = Instant
            });
            db.AppRegistrations.Add(new AppRegistrationEntity
            {
                Id = appRegistrationId, AppId = AppId, AppName = "SMS legacy",
                AppSecretHash = "synthetic-hash", IsActive = true, CreatedAt = Instant
            });
            db.OidcRateLimitBuckets.Add(Bucket("oidc-login"));
            await db.SaveChangesAsync(Ct);

            await BrowserSmsStorageTestSupport.InsertLegacySessionAsync(
                db, referencedSessionId, accountId, credentialId, authTime);
            await BrowserSmsStorageTestSupport.InsertLegacySessionAsync(
                db, revokedSessionId, accountId, credentialId, authTime,
                revokedAt: authTime.AddMinutes(1), revocationReason: "logout");
            await BrowserSmsStorageTestSupport.InsertLegacyAuthorizationRequestAsync(
                db, Guid.NewGuid(), LoginHandleDigest.Compute("sms-legacy-handle-0123456789abcdefghijklm"),
                appRegistrationId, authTime);
            if (Sqlite)
            {
                await RefreshTokenFamilyTestSupport.InsertInteractiveMemberSqliteAsync(
                    db, rootId, accountId, AppId, rootId, parentId: null, referencedSessionId,
                    "openid", authTime, authTime, authTime.AddHours(1));
            }
            else
            {
                await RefreshTokenFamilyTestSupport.InsertInteractiveMemberPostgreSqlAsync(
                    db, rootId, accountId, AppId, rootId, parentId: null, referencedSessionId,
                    "openid", authTime, authTime, authTime.AddHours(1));
            }

            db.AuthorizationCodes.Add(new AuthorizationCodeEntity
            {
                Id = Guid.NewGuid(),
                CodeDigest = AuthorizationCodeDigest.Compute("sms-legacy-code-0123456789abcdefghijk"),
                AppRegistrationId = appRegistrationId,
                AccountId = accountId,
                IdentitySessionId = referencedSessionId,
                RedirectUri = "https://client.example.test/callback",
                Scope = "openid",
                Nonce = "sms-legacy-nonce",
                CodeChallenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                AuthTime = authTime,
                CreatedAt = authTime,
                ExpiresAt = authTime.AddSeconds(IdentityConstants.AuthorizationCodeLifetimeSeconds),
                ConsumedAt = authTime,
                RefreshFamilyId = rootId
            });
            await db.SaveChangesAsync(Ct);
            return new LegacyGraph(credentialId, referencedSessionId, revokedSessionId, authTime);
        }

        public async Task<long> CountAsync(string table, string? predicate = null)
        {
            await using var db = Context();
            return await BrowserSmsStorageTestSupport.CountAsync(db, table, predicate);
        }

        public async Task<List<string>> RowsAsync(string sql)
        {
            await using var db = Context();
            await db.Database.OpenConnectionAsync(Ct);
            await using var command = db.Database.GetDbConnection().CreateCommand();
            command.CommandText = sql;
            await using var reader = await command.ExecuteReaderAsync(Ct);
            var rows = new List<string>();
            while (await reader.ReadAsync(Ct))
            {
                rows.Add(string.Join('|', Enumerable.Range(0, reader.FieldCount).Select(ordinal =>
                    reader.IsDBNull(ordinal) ? "<null>" : Convert.ToString(reader.GetValue(ordinal), CultureInfo.InvariantCulture))));
            }

            return rows;
        }

        public async Task<HashSet<string>> IndexNamesAsync() => (await RowsAsync(Sqlite
                ? "SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%'"
                : "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()"))
            .ToHashSet(StringComparer.Ordinal);

        /// <summary>
        /// The order-independent schema of the three affected tables plus every constraint that
        /// references them: columns with types, nullability, and defaults; checks; foreign keys;
        /// and indexes. SQLite physical column order is deliberately excluded.
        /// </summary>
        public async Task<string> SchemaAsync()
        {
            var tables = string.Join(", ", AffectedTables.Select(table => $"'{table}'"));
            var rows = new List<string>();
            if (Sqlite)
            {
                foreach (var ddl in await RowsAsync(
                    $"SELECT name || '|' || sql FROM sqlite_master WHERE type = 'table' AND name IN ({tables})"))
                {
                    var name = ddl[..ddl.IndexOf('|')];
                    rows.AddRange(ddl[(ddl.IndexOf('|') + 1)..]
                        .Split('\n')
                        .Select(line => line.Trim().TrimEnd(','))
                        .Where(line => line.Length > 0 && line != ")" && !line.StartsWith("CREATE TABLE", StringComparison.Ordinal))
                        .Select(line => name + ": " + line));
                }

                rows.AddRange(await RowsAsync(
                    $"SELECT tbl_name, name, sql FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL AND tbl_name IN ({tables})"));
                foreach (var child in new[] { "authorization_codes", "refresh_tokens" })
                {
                    rows.AddRange((await RowsAsync($"PRAGMA foreign_key_list({child})")).Select(row => child + ": " + row));
                }
            }
            else
            {
                rows.AddRange(await RowsAsync($"""
                    SELECT table_name, column_name, data_type, is_nullable, character_maximum_length, column_default
                    FROM information_schema.columns
                    WHERE table_schema = current_schema() AND table_name IN ({tables})
                    """));
                rows.AddRange(await RowsAsync($"""
                    SELECT conrelid::regclass::text, conname, contype, pg_get_constraintdef(oid)
                    FROM pg_constraint
                    WHERE conrelid::regclass::text IN ({tables}) OR confrelid::regclass::text IN ({tables})
                    """));
                rows.AddRange(await RowsAsync($"""
                    SELECT tablename, indexname, indexdef FROM pg_indexes
                    WHERE schemaname = current_schema() AND tablename IN ({tables})
                    """));
            }

            rows.Sort(StringComparer.Ordinal);
            return string.Join('\n', rows);
        }

        /// <summary>Every legacy column of the affected and referencing tables, valid on both schema versions.</summary>
        public async Task<string> LegacyDataAsync() => string.Join('\n',
            (await RowsAsync("""
                SELECT id, account_id, password_credential_id, auth_method, auth_time, last_seen_at,
                       idle_expires_at, absolute_expires_at, revoked_at, revocation_reason
                FROM identity_sessions ORDER BY id
                """))
            .Concat(await RowsAsync("""
                SELECT id, handle_digest, app_registration_id, redirect_uri, scope, state, nonce,
                       code_challenge, created_at, expires_at, consumed_at
                FROM authorization_requests ORDER BY id
                """))
            .Concat(await RowsAsync("SELECT policy, partition_digest, window_expires_at, permit_count FROM oidc_rate_limit_buckets ORDER BY policy, partition_digest"))
            .Concat(await RowsAsync("SELECT id, identity_session_id, refresh_family_id, consumed_at FROM authorization_codes ORDER BY id"))
            .Concat(await RowsAsync("SELECT id, family_id, identity_session_id, is_revoked, consumed_at FROM refresh_tokens ORDER BY id")));

        /// <summary>The legacy data plus the #443 columns, valid only on the target schema.</summary>
        public async Task<string> CurrentDataAsync() => await LegacyDataAsync() + "\n" + string.Join('\n',
            (await RowsAsync("SELECT id, sms_user_login_id FROM identity_sessions ORDER BY id"))
            .Concat(await RowsAsync("SELECT id, sms_code_send_count FROM authorization_requests ORDER BY id")));

        public async ValueTask DisposeAsync()
        {
            if (container is not null)
            {
                await container.DisposeAsync();
            }

            if (path is not null)
            {
                TestSqlitePools.ClearAll();
                foreach (var file in new[] { path, path + "-wal", path + "-shm" })
                {
                    File.Delete(file);
                }
            }
        }
    }
}
