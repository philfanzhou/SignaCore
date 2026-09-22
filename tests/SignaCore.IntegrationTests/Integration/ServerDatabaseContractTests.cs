using DotNet.Testcontainers.Containers;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Models;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

public sealed class ServerDatabaseContractTests
{
    private const string PreOidcMigration = "20260820091041_PersistDataProtectionKeys";

    /// <summary>
    /// The PostgreSQL image the container matrix runs against. CI overrides it with a mirror of the
    /// same official image, because Docker Hub meters anonymous pulls per client address and hosted
    /// runners share their egress addresses. A local run with the variable unset keeps the plain
    /// Docker Hub name.
    /// </summary>
    private static readonly string PostgreSqlImage =
        Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") is { Length: > 0 } image
            ? image
            : "postgres:15-alpine";

    [Theory]
    [InlineData("PostgreSQL")]
    public async Task ProviderContract_MigrationCrudNormalizationAndConcurrency(
        string provider)
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            $"Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the {provider} container matrix.");

        var container = CreateContainer(provider);
        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                provider,
                GetConnectionString(container));
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);

            await WaitUntilConnectableAsync(optionsBuilder.Options);
            await RunContractAsync(optionsBuilder.Options);
        }
    }

    [Fact]
    public async Task PostgreSqlLegacyHistory_UpgradesInPlace()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL legacy upgrade.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);

            await using var context = new IdentityDbContext(optionsBuilder.Options);
            var migrator = context.GetService<IMigrator>();
            await migrator.MigrateAsync(
                "20260504150448_AddAppIdToRefreshToken",
                TestContext.Current.CancellationToken);

            var accountId = Guid.NewGuid();
            var credentialId = Guid.NewGuid();
            await context.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO accounts (id, is_active, created_at, total_login_count)
                VALUES ({accountId}, TRUE, {DateTimeOffset.UtcNow}, 0);

                INSERT INTO password_credentials
                    (id, account_id, username, password_hash, created_at)
                VALUES
                    ({credentialId}, {accountId}, {"LegacyUser"}, {"hash"}, {DateTimeOffset.UtcNow});
                """, cancellationToken: TestContext.Current.CancellationToken);

            await new SignaCore.Host.Migration.SignaCoreMigrationExecutor(
                context,
                databaseOptions).ExecuteAsync(TestContext.Current.CancellationToken);

            var credential = await context.PasswordCredentials
                .AsNoTracking()
                .SingleAsync(item => item.Id == credentialId, cancellationToken: TestContext.Current.CancellationToken);
            Assert.Equal("LEGACYUSER", credential.UsernameNormalized);

            var appliedMigrations = (await context.Database
                    .GetAppliedMigrationsAsync(cancellationToken: TestContext.Current.CancellationToken))
                .ToHashSet(StringComparer.Ordinal);
            Assert.Contains(
                "20260502023354_InitialCreate",
                appliedMigrations);
            Assert.Contains(
                "20260504150448_AddAppIdToRefreshToken",
                appliedMigrations);
            Assert.Contains(
                "20260730134156_EnforceNormalizedIdentityValues",
                appliedMigrations);

            // The downgrade walk from the current version now ends at the retirement boundary:
            // RetireSystemSettings refuses its Down with the fixed NotSupportedException instead
            // of recreating an empty legacy table, so the schema stays at the current version.
            var refusal = await Assert.ThrowsAsync<NotSupportedException>(
                () => migrator.MigrateAsync(
                    PreOidcMigration,
                    TestContext.Current.CancellationToken));
            Assert.Contains("irreversible", refusal.Message, StringComparison.Ordinal);
            Assert.True(await PostgreSqlTableExistsAsync(context, "app_registrations"));
            var columns = await GetPostgreSqlColumnsAsync(context, "app_registrations");
            Assert.Contains("allow_authorization_code", columns);
            Assert.Contains("client_type", columns);

            // The legacy-application upgrade coverage keeps its pre-OIDC staging on a fresh
            // database: the original down-and-reseed path is no longer reachable across the
            // retirement boundary.
            await using (var legacy = new PostgreSqlBuilder(PostgreSqlImage)
                .WithDatabase("identity")
                .WithUsername("postgres")
                .WithPassword("postgres")
                .Build())
            {
                await legacy.StartAsync(TestContext.Current.CancellationToken);
                var legacyOptions = CreateDatabaseOptions("PostgreSQL", legacy.GetConnectionString());
                var legacyBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
                legacyBuilder.UseIdentityDatabase(legacyOptions);
                await using var legacyContext = new IdentityDbContext(legacyBuilder.Options);
                var legacyMigrator = legacyContext.GetService<IMigrator>();
                await legacyMigrator.MigrateAsync(
                    PreOidcMigration,
                    TestContext.Current.CancellationToken);
                var legacyAppId = Guid.NewGuid();
                const string callbackUrl = "https://claims.example.com/callback?tenant=legacy";
                await InsertLegacyApplicationAsync(legacyContext, legacyAppId, callbackUrl);
                await legacyMigrator.MigrateAsync(
                    cancellationToken: TestContext.Current.CancellationToken);

            var upgradedApplication = await legacyContext.AppRegistrations
                .AsNoTracking()
                .SingleAsync(
                    app => app.Id == legacyAppId,
                    TestContext.Current.CancellationToken);
            Assert.Equal(callbackUrl, upgradedApplication.CallbackUrl);
            Assert.Equal(LdapLoginMode.ManualApproval, upgradedApplication.LdapLoginMode);
            Assert.Equal(SmsLoginMode.AutoProvision, upgradedApplication.SmsLoginMode);
            Assert.Equal("legacy-profile", upgradedApplication.SmsProfileKey);
            Assert.Equal(WechatLoginMode.BindRequired, upgradedApplication.WechatLoginMode);
            Assert.Equal(AudienceMode.Shared, upgradedApplication.AudienceMode);
            Assert.Equal(OidcClientType.Confidential, upgradedApplication.ClientType);
            Assert.False(upgradedApplication.AllowAuthorizationCode);
            Assert.Equal("openid", upgradedApplication.AllowedScopes);
            Assert.False(upgradedApplication.AllowRefreshToken);
            Assert.Null(upgradedApplication.IdentitySessionMaxAgeSeconds);
            Assert.Empty(await legacyContext.AppRedirectUris.AsNoTracking().ToListAsync(
                TestContext.Current.CancellationToken));
            }
        }
    }

    /// <summary>
    /// <c>PS-03</c>/<c>PS-23</c> on the real PostgreSQL matrix: the exact fresh schema shape, the
    /// additive upgrade from <c>DropLegacyDataProtectionKeys</c> with a symmetric <c>Down</c>, the
    /// restrictive non-cascading client reference, and the atomic one-time consumption across two
    /// independent connections (<c>EV-01</c> primitive, <c>AC-02</c> storage half).
    /// </summary>
    [Fact]
    public async Task PostgreSqlAuthorizationRequests_SchemaUpgradeDownAndConcurrentConsumption()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL continuation contract.");

        const string preContinuationMigration = "20260914171835_DropLegacyDataProtectionKeys";
        // The migration under test, pinned: later migrations in the chain legitimately change
        // refresh_tokens (the family columns), which is not this migration's contract.
        const string continuationMigration = "20260916073310_AddAuthorizationRequests";
        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            var accountId = Guid.NewGuid();
            var appId = Guid.NewGuid();
            var tokenId = Guid.NewGuid();
            var createdAt = DateTimeOffset.UtcNow;
            var expiresAt = createdAt.AddHours(1);
            var tokenDigest = RefreshTokenDigest.Compute("continuation-upgrade-token");

            // ---- Additive upgrade from the immediately preceding migration, symmetric Down ----
            await using (var context = new IdentityDbContext(options))
            {
                var cancellationToken = TestContext.Current.CancellationToken;
                var migrator = context.GetService<IMigrator>();
                await migrator.MigrateAsync(preContinuationMigration, cancellationToken);

                context.Accounts.Add(new AccountEntity
                {
                    Id = accountId,
                    IsActive = true,
                    CreatedAt = createdAt
                });
                context.AppRegistrations.Add(new AppRegistrationEntity
                {
                    Id = appId,
                    AppId = "continuation-upgrade-app",
                    AppSecretHash = "hash",
                    AppName = "Continuation Upgrade",
                    IsActive = true,
                    CreatedAt = createdAt
                });
                await context.SaveChangesAsync(cancellationToken);

                // The legacy token row is seeded with raw SQL: the migration version under test
                // predates the family columns a current-EF-model INSERT would name.
                await RefreshTokenFamilyTestSupport.InsertLegacyRefreshTokenPostgreSqlAsync(
                    context, tokenId, accountId, tokenDigest, createdAt, expiresAt,
                    "continuation-upgrade-app");

                var refreshColumnsBefore = await GetPostgreSqlColumnsAsync(context, "refresh_tokens");
                var appColumnsBefore = await GetPostgreSqlColumnsAsync(context, "app_registrations");
                Assert.False(await PostgreSqlTableExistsAsync(context, "authorization_requests"));

                await migrator.MigrateAsync(continuationMigration, cancellationToken);

                Assert.True(await PostgreSqlTableExistsAsync(context, "authorization_requests"));
                Assert.Empty(await context.AuthorizationRequests
                    .AsNoTracking()
                    .ToListAsync(cancellationToken));
                Assert.True(refreshColumnsBefore.SetEquals(
                    await GetPostgreSqlColumnsAsync(context, "refresh_tokens")));
                Assert.True(appColumnsBefore.SetEquals(
                    await GetPostgreSqlColumnsAsync(context, "app_registrations")));
                await AssertSeedUnchangedAsync(
                    context, accountId, appId, tokenId, createdAt, expiresAt, tokenDigest);

                context.ChangeTracker.Clear();
                await migrator.MigrateAsync(preContinuationMigration, cancellationToken);
                Assert.False(await PostgreSqlTableExistsAsync(context, "authorization_requests"));
                Assert.True(refreshColumnsBefore.SetEquals(
                    await GetPostgreSqlColumnsAsync(context, "refresh_tokens")));
                Assert.True(appColumnsBefore.SetEquals(
                    await GetPostgreSqlColumnsAsync(context, "app_registrations")));
                await AssertSeedUnchangedAsync(
                    context, accountId, appId, tokenId, createdAt, expiresAt, tokenDigest);

                await migrator.MigrateAsync(continuationMigration, cancellationToken);
            }

            // ---- Exact fresh schema shape ----
            await using (var context = new IdentityDbContext(options))
            {
                var columnDetails = await GetPostgreSqlColumnDetailsAsync(
                    context, "authorization_requests");
                Assert.Equal(
                    new Dictionary<string, (string IsNullable, int? MaxLength)>(StringComparer.Ordinal)
                    {
                        ["id"] = ("NO", null),
                        ["handle_digest"] = ("NO", 71),
                        ["app_registration_id"] = ("NO", null),
                        ["redirect_uri"] = ("NO", 501),
                        ["scope"] = ("NO", 32),
                        ["state"] = ("NO", 128),
                        ["nonce"] = ("NO", 128),
                        ["code_challenge"] = ("NO", 43),
                        ["created_at"] = ("NO", null),
                        ["expires_at"] = ("NO", null),
                        ["consumed_at"] = ("YES", null)
                    },
                    columnDetails);

                var indexDefinitions = await GetPostgreSqlIndexDefinitionsAsync(
                    context, "authorization_requests");
                Assert.Contains(indexDefinitions, definition =>
                    definition.Contains("UNIQUE", StringComparison.Ordinal)
                    && definition.Contains("handle_digest", StringComparison.Ordinal));

                var foreignKeys = await GetPostgreSqlForeignKeysAsync(
                    context, "authorization_requests");
                var reference = Assert.Single(foreignKeys);
                Assert.Equal("app_registrations", reference.ReferencedTable);
                // 'r' = RESTRICT in pg_constraint.confdeltype; never 'c' (cascade).
                Assert.Equal('r', reference.DeleteAction);

                // The restrictive reference is enforced: an orphan row fails.
                context.AuthorizationRequests.Add(new AuthorizationRequestEntity
                {
                    Id = Guid.NewGuid(),
                    HandleDigest = LoginHandleDigest.Compute(
                        "orphan-handle-0123456789abcdefghijklmnopqrstu"),
                    AppRegistrationId = Guid.NewGuid(),
                    RedirectUri = "https://client.example.com/callback",
                    Scope = "openid",
                    State = "server-contract-state-value",
                    Nonce = "server-contract-nonce-value",
                    CodeChallenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                    CreatedAt = DateTimeOffset.UtcNow,
                    ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(
                        IdentityConstants.LoginHandleLifetimeMinutes)
                });
                await Assert.ThrowsAsync<DbUpdateException>(() =>
                    context.SaveChangesAsync(TestContext.Current.CancellationToken));
                context.ChangeTracker.Clear();
            }

            // ---- Two independent connections consume concurrently: exactly one commits ----
            string handle;
            await using (var creationContext = new IdentityDbContext(options))
            {
                var store = new AuthorizationRequestStore(
                    new AuthorizationRequestRepository(creationContext),
                    new EfCoreUnitOfWork(creationContext));
                var creation = await store.CreateAsync(
                    new OidcAuthorizationValidationResult.Accepted(
                        "continuation-upgrade-app",
                        appId,
                        "https://client.example.com/callback?tenant=one",
                        "openid profile",
                        "ServerCanaryState_0123456789abcdef",
                        "ServerCanaryNonce_0123456789abcdef",
                        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
                    DateTimeOffset.UtcNow,
                    TestContext.Current.CancellationToken);
                handle = creation.LoginHandle;
            }

            var consumeResults = await Task.WhenAll(
                ConsumeContinuationAsync(options, handle),
                ConsumeContinuationAsync(options, handle));
            Assert.Equal(1, consumeResults.Count(result => result));

            await using (var assertionContext = new IdentityDbContext(options))
            {
                var rows = await assertionContext.AuthorizationRequests
                    .AsNoTracking()
                    .Where(row => row.HandleDigest == LoginHandleDigest.Compute(handle))
                    .ToListAsync(TestContext.Current.CancellationToken);
                var row = Assert.Single(rows);
                Assert.NotNull(row.ConsumedAt);

                var store = new AuthorizationRequestStore(
                    new AuthorizationRequestRepository(assertionContext),
                    new EfCoreUnitOfWork(assertionContext));
                Assert.False(await store.TryConsumeAsync(
                    handle, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken));

                // Deleting the application while a continuation row exists fails; no cascade.
                var application = await assertionContext.AppRegistrations
                    .SingleAsync(app => app.Id == appId, TestContext.Current.CancellationToken);
                assertionContext.AppRegistrations.Remove(application);
                await Assert.ThrowsAsync<DbUpdateException>(() =>
                    assertionContext.SaveChangesAsync(TestContext.Current.CancellationToken));
            }
        }
    }

    /// <summary>
    /// <c>PS-04</c>/<c>PS-23</c> on the real PostgreSQL matrix: the exact fresh schema shape
    /// (columns, lengths, indexes, restrictive references, the revocation-pair check), the
    /// additive upgrade from <c>AddAuthorizationRequests</c> with a symmetric <c>Down</c>, and the
    /// database-enforced references in both directions.
    /// </summary>
    [Fact]
    public async Task PostgreSqlIdentitySessions_SchemaUpgradeDownAndRestrictiveReferences()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL identity session contract.");

        const string preSessionMigration = "20260916073310_AddAuthorizationRequests";
        // The migration under test, pinned: later migrations in the chain legitimately change
        // refresh_tokens (the family columns), which is not this migration's contract.
        const string sessionMigration = "20260916103405_AddIdentitySessions";
        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            var accountId = Guid.NewGuid();
            var credentialId = Guid.NewGuid();
            var appId = Guid.NewGuid();
            var tokenId = Guid.NewGuid();
            var createdAt = DateTimeOffset.UtcNow;
            var expiresAt = createdAt.AddHours(1);
            var tokenDigest = RefreshTokenDigest.Compute("session-upgrade-token");
            var handle = "session-upgrade-handle-0123456789abcdefghijk";

            // ---- Additive upgrade from the immediately preceding migration, symmetric Down ----
            await using (var context = new IdentityDbContext(options))
            {
                var cancellationToken = TestContext.Current.CancellationToken;
                var migrator = context.GetService<IMigrator>();
                await migrator.MigrateAsync(preSessionMigration, cancellationToken);

                context.Accounts.Add(new AccountEntity
                {
                    Id = accountId, IsActive = true, CreatedAt = createdAt
                });
                context.PasswordCredentials.Add(new PasswordCredentialEntity
                {
                    Id = credentialId, AccountId = accountId, Username = "session-upgrade-user",
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
                    State = "session-upgrade-state",
                    Nonce = "session-upgrade-nonce",
                    CodeChallenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                    CreatedAt = createdAt,
                    ExpiresAt = createdAt.AddMinutes(IdentityConstants.LoginHandleLifetimeMinutes)
                });
                await context.SaveChangesAsync(cancellationToken);

                // The legacy token row is seeded with raw SQL: the migration version under test
                // predates the family columns a current-EF-model INSERT would name.
                await RefreshTokenFamilyTestSupport.InsertLegacyRefreshTokenPostgreSqlAsync(
                    context, tokenId, accountId, tokenDigest, createdAt, expiresAt,
                    "session-upgrade-app");

                var accountsBefore = await GetPostgreSqlColumnsAsync(context, "accounts");
                var credentialsBefore = await GetPostgreSqlColumnsAsync(context, "password_credentials");
                var appsBefore = await GetPostgreSqlColumnsAsync(context, "app_registrations");
                var tokensBefore = await GetPostgreSqlColumnsAsync(context, "refresh_tokens");
                var continuationsBefore = await GetPostgreSqlColumnsAsync(context, "authorization_requests");
                Assert.False(await PostgreSqlTableExistsAsync(context, "identity_sessions"));

                await migrator.MigrateAsync(sessionMigration, cancellationToken);

                Assert.True(await PostgreSqlTableExistsAsync(context, "identity_sessions"));
                Assert.Empty(await context.IdentitySessions.AsNoTracking().ToListAsync(cancellationToken));
                Assert.True(accountsBefore.SetEquals(await GetPostgreSqlColumnsAsync(context, "accounts")));
                Assert.True(credentialsBefore.SetEquals(await GetPostgreSqlColumnsAsync(context, "password_credentials")));
                Assert.True(appsBefore.SetEquals(await GetPostgreSqlColumnsAsync(context, "app_registrations")));
                Assert.True(tokensBefore.SetEquals(await GetPostgreSqlColumnsAsync(context, "refresh_tokens")));
                Assert.True(continuationsBefore.SetEquals(await GetPostgreSqlColumnsAsync(context, "authorization_requests")));
                await AssertSeedUnchangedAsync(context);

                context.ChangeTracker.Clear();
                await migrator.MigrateAsync(preSessionMigration, cancellationToken);
                Assert.False(await PostgreSqlTableExistsAsync(context, "identity_sessions"));
                Assert.True(accountsBefore.SetEquals(await GetPostgreSqlColumnsAsync(context, "accounts")));
                Assert.True(credentialsBefore.SetEquals(await GetPostgreSqlColumnsAsync(context, "password_credentials")));
                Assert.True(appsBefore.SetEquals(await GetPostgreSqlColumnsAsync(context, "app_registrations")));
                Assert.True(tokensBefore.SetEquals(await GetPostgreSqlColumnsAsync(context, "refresh_tokens")));
                Assert.True(continuationsBefore.SetEquals(await GetPostgreSqlColumnsAsync(context, "authorization_requests")));
                await AssertSeedUnchangedAsync(context);

                await migrator.MigrateAsync(sessionMigration, cancellationToken);
                Assert.True(await PostgreSqlTableExistsAsync(context, "identity_sessions"));

                async Task AssertSeedUnchangedAsync(IdentityDbContext assertionContext)
                {
                    var account = await assertionContext.Accounts.AsNoTracking()
                        .SingleAsync(row => row.Id == accountId, cancellationToken);
                    Assert.True(account.IsActive);
                    Assert.Equal(createdAt.UtcTicks / 10, account.CreatedAt.UtcTicks / 10);

                    var credential = await assertionContext.PasswordCredentials.AsNoTracking()
                        .SingleAsync(row => row.Id == credentialId, cancellationToken);
                    Assert.Equal("session-upgrade-user", credential.Username);
                    Assert.Equal("hash", credential.PasswordHash);
                    Assert.Equal(createdAt.UtcTicks / 10, credential.CreatedAt.UtcTicks / 10);

                    var application = await assertionContext.AppRegistrations.AsNoTracking()
                        .SingleAsync(row => row.Id == appId, cancellationToken);
                    Assert.Equal("session-upgrade-app", application.AppId);
                    Assert.Equal("hash", application.AppSecretHash);
                    Assert.True(application.IsActive);
                    Assert.Equal(createdAt.UtcTicks / 10, application.CreatedAt.UtcTicks / 10);

                    // The Down state predates the family columns, so the token row is read
                    // with raw SQL instead of the current EF model.
                    var token = await RefreshTokenFamilyTestSupport
                        .ReadRefreshTokenRowPostgreSqlAsync(assertionContext, tokenId);
                    Assert.Equal(tokenDigest, token.TokenValue);
                    Assert.False(token.IsRevoked);
                    Assert.Equal(createdAt.UtcTicks / 10, token.CreatedAt.UtcTicks / 10);
                    Assert.Equal(expiresAt.UtcTicks / 10, token.ExpiresAt.UtcTicks / 10);

                    var continuation = await assertionContext.AuthorizationRequests.AsNoTracking()
                        .SingleAsync(
                            row => row.HandleDigest == LoginHandleDigest.Compute(handle),
                            cancellationToken);
                    Assert.Equal(appId, continuation.AppRegistrationId);
                    Assert.Null(continuation.ConsumedAt);
                    Assert.Equal(createdAt.UtcTicks / 10, continuation.CreatedAt.UtcTicks / 10);
                }
            }

            // ---- Exact fresh schema shape ----
            await using (var context = new IdentityDbContext(options))
            {
                var columnDetails = await GetPostgreSqlColumnDetailsAsync(context, "identity_sessions");
                Assert.Equal(
                    new Dictionary<string, (string IsNullable, int? MaxLength)>(StringComparer.Ordinal)
                    {
                        ["id"] = ("NO", null),
                        ["account_id"] = ("NO", null),
                        ["password_credential_id"] = ("NO", null),
                        ["auth_method"] = ("NO", 50),
                        ["auth_time"] = ("NO", null),
                        ["last_seen_at"] = ("NO", null),
                        ["idle_expires_at"] = ("NO", null),
                        ["absolute_expires_at"] = ("NO", null),
                        ["revoked_at"] = ("YES", null),
                        ["revocation_reason"] = ("YES", 32)
                    },
                    columnDetails);

                var indexDefinitions = await GetPostgreSqlIndexDefinitionsAsync(
                    context, "identity_sessions");
                Assert.Contains(indexDefinitions, definition =>
                    definition.Contains("account_id", StringComparison.Ordinal));
                Assert.Contains(indexDefinitions, definition =>
                    definition.Contains("password_credential_id", StringComparison.Ordinal));

                var foreignKeys = await GetPostgreSqlForeignKeysAsync(context, "identity_sessions");
                Assert.Equal(2, foreignKeys.Count);
                Assert.Contains(foreignKeys, key =>
                    key.ReferencedTable == "accounts" && key.DeleteAction == 'r');
                Assert.Contains(foreignKeys, key =>
                    key.ReferencedTable == "password_credentials" && key.DeleteAction == 'r');

                Assert.Contains(
                    "CK_identity_sessions_revocation_pair",
                    await GetPostgreSqlCheckConstraintsAsync(context, "identity_sessions"));
            }

            // ---- The references and the revocation pairing are enforced by the database ----
            await using (var context = new IdentityDbContext(options))
            {
                var cancellationToken = TestContext.Current.CancellationToken;
                var refAccountId = Guid.NewGuid();
                var refCredentialId = Guid.NewGuid();
                context.Accounts.Add(new AccountEntity
                {
                    Id = refAccountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow
                });
                context.PasswordCredentials.Add(new PasswordCredentialEntity
                {
                    Id = refCredentialId, AccountId = refAccountId, Username = "session-contract-user",
                    PasswordHash = "hash", CreatedAt = DateTimeOffset.UtcNow
                });
                await context.SaveChangesAsync(cancellationToken);

                // Half of the revocation pair fails the check constraint.
                context.IdentitySessions.Add(CreateIdentitySession(refAccountId, refCredentialId, session =>
                    session.RevokedAt = DateTimeOffset.UtcNow));
                await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync(cancellationToken));
                context.ChangeTracker.Clear();

                context.IdentitySessions.Add(CreateIdentitySession(refAccountId, refCredentialId, session =>
                    session.RevocationReason = "logout"));
                await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync(cancellationToken));
                context.ChangeTracker.Clear();

                // Orphan references fail in both directions.
                context.IdentitySessions.Add(CreateIdentitySession(Guid.NewGuid(), refCredentialId));
                await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync(cancellationToken));
                context.ChangeTracker.Clear();

                context.IdentitySessions.Add(CreateIdentitySession(refAccountId, Guid.NewGuid()));
                await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync(cancellationToken));
                context.ChangeTracker.Clear();

                // A valid session; deleting either referenced row now fails without cascading.
                context.IdentitySessions.Add(CreateIdentitySession(refAccountId, refCredentialId));
                await context.SaveChangesAsync(cancellationToken);

                context.ChangeTracker.Clear();
                var account = await context.Accounts
                    .SingleAsync(row => row.Id == refAccountId, cancellationToken);
                context.Accounts.Remove(account);
                await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync(cancellationToken));
                context.ChangeTracker.Clear();

                var credential = await context.PasswordCredentials
                    .SingleAsync(row => row.Id == refCredentialId, cancellationToken);
                context.PasswordCredentials.Remove(credential);
                await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync(cancellationToken));
                context.ChangeTracker.Clear();

                Assert.Single(await context.IdentitySessions
                    .AsNoTracking()
                    .ToListAsync(cancellationToken));
            }
        }
    }

    /// <summary>
    /// The real two-instance concurrency matrix of <c>PS-04</c>: exactly one concurrent activity
    /// slide wins inside one minute window, exactly one concurrent revocation wins and its facts
    /// persist, a held row lock blocks a second locker and an activity update until its
    /// transaction ends, and a capped slide can never invert the idle &lt;= absolute invariant.
    /// </summary>
    [Fact]
    public async Task PostgreSqlIdentitySessions_ConcurrentActivityRevocationAndLocking()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL identity session concurrency matrix.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            await using (var migration = new IdentityDbContext(options))
            {
                await migration.Database.MigrateAsync(TestContext.Current.CancellationToken);
            }

            var (accountId, credentialId) = await SeedSessionAccountAsync(options);
            var cancellationToken = TestContext.Current.CancellationToken;
            var authTime = DateTimeOffset.UtcNow.AddMinutes(-5);

            // (a) Two activity updates race on one stale session: exactly one Touched, one
            // NotStale, and the stored last_seen_at is the winner's instant.
            var staleId = await CreateSessionAsync(options, accountId, credentialId, authTime);
            var firstNow = DateTimeOffset.UtcNow;
            var secondNow = firstNow.AddMilliseconds(50);
            var touchResults = await Task.WhenAll(
                TouchSessionAsync(options, staleId, firstNow),
                TouchSessionAsync(options, staleId, secondNow));
            Assert.Equal(
                1,
                touchResults.Count(result => result == IdentitySessionActivityResult.Touched));
            Assert.Equal(
                1,
                touchResults.Count(result => result == IdentitySessionActivityResult.NotStale));
            var touchedRow = await GetSessionRowAsync(options, staleId);
            var winningTouch = touchResults[0] == IdentitySessionActivityResult.Touched
                ? firstNow
                : secondNow;
            Assert.Equal(
                winningTouch.UtcTicks / 10,
                touchedRow.LastSeenAt.UtcTicks / 10);

            // (b) Two revocations with different reasons race: exactly one Revoked, and the
            // stored time and reason are the winner's.
            var revokeId = await CreateSessionAsync(options, accountId, credentialId, authTime);
            var revokeResults = await Task.WhenAll(
                RevokeSessionAsync(
                    options, revokeId, IdentitySessionRevocationReason.Logout, firstNow),
                RevokeSessionAsync(
                    options, revokeId, IdentitySessionRevocationReason.CodeReplay, secondNow));
            Assert.Equal(
                1,
                revokeResults.Count(result => result == IdentitySessionRevocationResult.Revoked));
            Assert.Equal(
                1,
                revokeResults.Count(result => result == IdentitySessionRevocationResult.AlreadyRevoked));
            var revokedRow = await GetSessionRowAsync(options, revokeId);
            var winningRevocation = revokeResults[0] == IdentitySessionRevocationResult.Revoked
                ? (firstNow, "logout")
                : (secondNow, "code_replay");
            Assert.Equal(
                winningRevocation.Item1.UtcTicks / 10,
                revokedRow.RevokedAt!.Value.UtcTicks / 10);
            Assert.Equal(winningRevocation.Item2, revokedRow.RevocationReason);

            // (c) Transaction A locks the row and revokes inside its transaction without
            // committing: B's activity update and B's lock both block until A ends.
            var lockedId = await CreateSessionAsync(options, accountId, credentialId, authTime);
            var rowBeforeLock = await GetSessionRowAsync(options, lockedId);
            var revokeInstant = DateTimeOffset.UtcNow;
            var holderReady = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var releaseHolder = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var holderTask = Task.Run(async () =>
            {
                await using var holderContext = new IdentityDbContext(options);
                var holderStore = new IdentitySessionStore(
                    new IdentitySessionRepository(holderContext),
                    new EfCoreUnitOfWork(holderContext));
                var strategy = holderContext.Database.CreateExecutionStrategy();
                await strategy.ExecuteAsync(async operationToken =>
                {
                    await using var transaction = await holderContext.Database
                        .BeginTransactionAsync(operationToken);
                    var locked = await holderStore.LockAsync(lockedId, operationToken);
                    Assert.NotNull(locked);
                    Assert.Equal(
                        IdentitySessionRevocationResult.Revoked,
                        await holderStore.RevokeAsync(
                            lockedId,
                            IdentitySessionRevocationReason.Logout,
                            revokeInstant,
                            operationToken));
                    holderReady.SetResult();
                    await releaseHolder.Task.WaitAsync(TimeSpan.FromSeconds(60), operationToken);
                    await transaction.CommitAsync(operationToken);
                }, cancellationToken);
            }, CancellationToken.None);

            await holderReady.Task.WaitAsync(TimeSpan.FromSeconds(60), cancellationToken);

            var blockedTouch = TouchSessionAsync(
                options, lockedId, DateTimeOffset.UtcNow.AddMilliseconds(1));
            var blockedLock = LockSessionInTransactionAsync(options, lockedId);
            await Assert.ThrowsAsync<TimeoutException>(() =>
                blockedTouch.WaitAsync(TimeSpan.FromMilliseconds(500)));
            await Assert.ThrowsAsync<TimeoutException>(() =>
                blockedLock.WaitAsync(TimeSpan.FromMilliseconds(500)));

            releaseHolder.SetResult();
            await holderTask.WaitAsync(TimeSpan.FromSeconds(60), cancellationToken);

            // After A committed, B's update sees the revocation without writing, and B's lock
            // returns the revoked row.
            Assert.Equal(
                IdentitySessionActivityResult.Unavailable,
                await blockedTouch.WaitAsync(TimeSpan.FromSeconds(60), cancellationToken));
            var afterBlockedTouch = await GetSessionRowAsync(options, lockedId);
            Assert.Equal(
                rowBeforeLock.IdleExpiresAt.UtcTicks / 10,
                afterBlockedTouch.IdleExpiresAt.UtcTicks / 10);
            Assert.Equal(
                revokeInstant.UtcTicks / 10,
                afterBlockedTouch.RevokedAt!.Value.UtcTicks / 10);
            var lockResult = await blockedLock.WaitAsync(TimeSpan.FromSeconds(60), cancellationToken);
            Assert.NotNull(lockResult);
            Assert.Equal(
                revokeInstant.UtcTicks / 10,
                lockResult!.RevokedAt!.Value.UtcTicks / 10);

            // (d) Two slides race near the absolute deadline: the cap holds whichever wins.
            var nearAbsoluteId = await InsertSessionAsync(
                options, accountId, credentialId, session =>
                {
                    var baseline = DateTimeOffset.UtcNow;
                    session.AuthTime = baseline.AddMinutes(-2);
                    session.LastSeenAt = baseline.AddMinutes(-2);
                    session.IdleExpiresAt = baseline.AddMinutes(5);
                    session.AbsoluteExpiresAt = baseline.AddMinutes(10);
                });
            var nearFirst = DateTimeOffset.UtcNow;
            var nearSecond = nearFirst.AddMilliseconds(50);
            await Task.WhenAll(
                TouchSessionAsync(options, nearAbsoluteId, nearFirst),
                TouchSessionAsync(options, nearAbsoluteId, nearSecond));
            var cappedRow = await GetSessionRowAsync(options, nearAbsoluteId);
            Assert.True(cappedRow.IdleExpiresAt <= cappedRow.AbsoluteExpiresAt);
            Assert.Equal(
                cappedRow.AbsoluteExpiresAt.UtcTicks / 10,
                cappedRow.IdleExpiresAt.UtcTicks / 10);
        }
    }

    /// <summary>
    /// One injected PostgreSQL serialization failure inside the revocation unit is replayed as a
    /// whole by the retrying execution strategy: the outcome stays a single <c>Revoked</c> with
    /// exactly one stored fact.
    /// </summary>
    [Fact]
    public async Task PostgreSqlIdentitySessions_TransientSerializationFailureReplaysTheRevocationOnce()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL identity session replay matrix.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            await using (var migration = new IdentityDbContext(options))
            {
                await migration.Database.MigrateAsync(TestContext.Current.CancellationToken);
            }

            var (accountId, credentialId) = await SeedSessionAccountAsync(options);
            var sessionId = await CreateSessionAsync(
                options, accountId, credentialId, DateTimeOffset.UtcNow.AddMinutes(-5));

            var interceptor = new TransientSessionUpdateFailureInterceptor();
            var interceptedBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            interceptedBuilder.UseIdentityDatabase(databaseOptions);
            interceptedBuilder.AddInterceptors(interceptor);
            await using var context = new IdentityDbContext(interceptedBuilder.Options);
            var store = new IdentitySessionStore(
                new IdentitySessionRepository(context),
                new EfCoreUnitOfWork(context));

            var revokeInstant = DateTimeOffset.UtcNow;
            Assert.Equal(
                IdentitySessionRevocationResult.Revoked,
                await store.RevokeAsync(
                    sessionId,
                    IdentitySessionRevocationReason.Logout,
                    revokeInstant,
                    TestContext.Current.CancellationToken));

            Assert.True(interceptor.ThrewOnce);
            var row = await GetSessionRowAsync(options, sessionId);
            Assert.Equal(revokeInstant.UtcTicks / 10, row.RevokedAt!.Value.UtcTicks / 10);
            Assert.Equal("logout", row.RevocationReason);

            Assert.Equal(
                IdentitySessionRevocationResult.AlreadyRevoked,
                await store.RevokeAsync(
                    sessionId,
                    IdentitySessionRevocationReason.CodeReplay,
                    DateTimeOffset.UtcNow,
                    TestContext.Current.CancellationToken));
        }
    }

    /// <summary>
    /// <c>PS-05</c>/<c>PS-23</c> on the real PostgreSQL matrix: the exact fresh schema shape
    /// (columns, lengths, the unique digest index, the session index, the three restrictive
    /// references, the family/consumption check), the additive upgrade from
    /// <c>AddIdentitySessions</c> with a symmetric <c>Down</c>, and the database-enforced
    /// references in both directions.
    /// </summary>
    [Fact]
    public async Task PostgreSqlAuthorizationCodes_SchemaUpgradeDownAndRestrictiveReferences()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL authorization code contract.");

        const string preCodeMigration = "20260916103405_AddIdentitySessions";
        // The migration under test, pinned: later migrations in the chain legitimately change
        // refresh_tokens (the family columns), which is not this migration's contract.
        const string codeMigration = "20260916160627_AddAuthorizationCodes";
        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            var accountId = Guid.NewGuid();
            var credentialId = Guid.NewGuid();
            var appId = Guid.NewGuid();
            var tokenId = Guid.NewGuid();
            var sessionId = Guid.NewGuid();
            var createdAt = DateTimeOffset.UtcNow;
            var expiresAt = createdAt.AddHours(1);
            var tokenDigest = RefreshTokenDigest.Compute("code-upgrade-token");
            var handle = "code-upgrade-handle-0123456789abcdefghij";

            // ---- Additive upgrade from the immediately preceding migration, symmetric Down ----
            await using (var context = new IdentityDbContext(options))
            {
                var cancellationToken = TestContext.Current.CancellationToken;
                var migrator = context.GetService<IMigrator>();
                await migrator.MigrateAsync(preCodeMigration, cancellationToken);

                context.Accounts.Add(new AccountEntity
                {
                    Id = accountId, IsActive = true, CreatedAt = createdAt
                });
                context.PasswordCredentials.Add(new PasswordCredentialEntity
                {
                    Id = credentialId, AccountId = accountId, Username = "code-contract-user",
                    PasswordHash = "hash", CreatedAt = createdAt
                });
                context.AppRegistrations.Add(new AppRegistrationEntity
                {
                    Id = appId, AppId = "code-contract-app", AppSecretHash = "hash",
                    AppName = "Code Contract", IsActive = true, CreatedAt = createdAt
                });
                context.AuthorizationRequests.Add(new AuthorizationRequestEntity
                {
                    Id = Guid.NewGuid(),
                    HandleDigest = LoginHandleDigest.Compute(handle),
                    AppRegistrationId = appId,
                    RedirectUri = "https://client.example.com/callback",
                    Scope = "openid",
                    State = "server-contract-state-value",
                    Nonce = "server-contract-nonce-value",
                    CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    CreatedAt = createdAt,
                    ExpiresAt = createdAt.AddMinutes(IdentityConstants.LoginHandleLifetimeMinutes)
                });
                context.IdentitySessions.Add(new IdentitySessionEntity
                {
                    Id = sessionId,
                    AccountId = accountId,
                    PasswordCredentialId = credentialId,
                    AuthMethod = IdentityConstants.AuthMethodPassword,
                    AuthTime = createdAt,
                    LastSeenAt = createdAt,
                    IdleExpiresAt = createdAt.AddMinutes(30),
                    AbsoluteExpiresAt = createdAt.AddHours(12)
                });
                await context.SaveChangesAsync(cancellationToken);

                // The legacy token row is seeded with raw SQL: the migration version under test
                // predates the family columns a current-EF-model INSERT would name.
                await RefreshTokenFamilyTestSupport.InsertLegacyRefreshTokenPostgreSqlAsync(
                    context, tokenId, accountId, tokenDigest, createdAt, expiresAt,
                    "code-contract-app");

                var accountsBefore = await GetPostgreSqlColumnsAsync(context, "accounts");
                var sessionsBefore = await GetPostgreSqlColumnsAsync(context, "identity_sessions");
                var continuationsBefore = await GetPostgreSqlColumnsAsync(
                    context, "authorization_requests");
                Assert.False(await PostgreSqlTableExistsAsync(context, "authorization_codes"));

                await migrator.MigrateAsync(codeMigration, cancellationToken);

                Assert.True(await PostgreSqlTableExistsAsync(context, "authorization_codes"));
                Assert.Empty(await context.AuthorizationCodes
                    .AsNoTracking()
                    .ToListAsync(cancellationToken));
                Assert.True(accountsBefore.SetEquals(
                    await GetPostgreSqlColumnsAsync(context, "accounts")));
                Assert.True(sessionsBefore.SetEquals(
                    await GetPostgreSqlColumnsAsync(context, "identity_sessions")));
                Assert.True(continuationsBefore.SetEquals(
                    await GetPostgreSqlColumnsAsync(context, "authorization_requests")));

                context.ChangeTracker.Clear();
                await migrator.MigrateAsync(preCodeMigration, cancellationToken);
                Assert.False(await PostgreSqlTableExistsAsync(context, "authorization_codes"));
                Assert.True(sessionsBefore.SetEquals(
                    await GetPostgreSqlColumnsAsync(context, "identity_sessions")));

                await migrator.MigrateAsync(codeMigration, cancellationToken);
            }

            // ---- Exact fresh schema shape ----
            await using (var context = new IdentityDbContext(options))
            {
                var cancellationToken = TestContext.Current.CancellationToken;
                var columnDetails = await GetPostgreSqlColumnDetailsAsync(
                    context, "authorization_codes");
                Assert.Equal(
                    new Dictionary<string, (string IsNullable, int? MaxLength)>(StringComparer.Ordinal)
                    {
                        ["id"] = ("NO", null),
                        ["code_digest"] = ("NO", 71),
                        ["app_registration_id"] = ("NO", null),
                        ["account_id"] = ("NO", null),
                        ["identity_session_id"] = ("NO", null),
                        ["redirect_uri"] = ("NO", 501),
                        ["scope"] = ("NO", 32),
                        ["nonce"] = ("NO", 128),
                        ["code_challenge"] = ("NO", 43),
                        ["auth_time"] = ("NO", null),
                        ["created_at"] = ("NO", null),
                        ["expires_at"] = ("NO", null),
                        ["consumed_at"] = ("YES", null),
                        ["refresh_family_id"] = ("YES", null)
                    },
                    columnDetails);

                var indexDefinitions = await GetPostgreSqlIndexDefinitionsAsync(
                    context, "authorization_codes");
                Assert.Contains(indexDefinitions, definition =>
                    definition.Contains("UNIQUE", StringComparison.Ordinal)
                    && definition.Contains("code_digest", StringComparison.Ordinal));
                Assert.Contains(indexDefinitions, definition =>
                    definition.Contains("identity_session_id", StringComparison.Ordinal));

                var foreignKeys = await GetPostgreSqlForeignKeysAsync(
                    context, "authorization_codes");
                Assert.Equal(3, foreignKeys.Count);
                Assert.Contains(foreignKeys, key =>
                    key.ReferencedTable == "app_registrations" && key.DeleteAction == 'r');
                Assert.Contains(foreignKeys, key =>
                    key.ReferencedTable == "accounts" && key.DeleteAction == 'r');
                Assert.Contains(foreignKeys, key =>
                    key.ReferencedTable == "identity_sessions" && key.DeleteAction == 'r');

                var checkConstraints = await GetPostgreSqlCheckConstraintsAsync(
                    context, "authorization_codes");
                Assert.Contains(
                    "CK_authorization_codes_family_requires_consumption", checkConstraints);

                // The family check is enforced: a link without consumption fails.
                context.AuthorizationCodes.Add(new AuthorizationCodeEntity
                {
                    Id = Guid.NewGuid(),
                    CodeDigest = AuthorizationCodeDigest.Compute(
                        "family-orphan-0123456789abcdefghijklmnopqrs"),
                    AppRegistrationId = appId,
                    AccountId = accountId,
                    IdentitySessionId = sessionId,
                    RedirectUri = "https://client.example.com/callback",
                    Scope = "openid",
                    Nonce = "server-contract-nonce-value",
                    CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    AuthTime = createdAt,
                    CreatedAt = DateTimeOffset.UtcNow,
                    ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(
                        IdentityConstants.AuthorizationCodeLifetimeSeconds),
                    RefreshFamilyId = Guid.NewGuid()
                });
                await Assert.ThrowsAsync<DbUpdateException>(() =>
                    context.SaveChangesAsync(cancellationToken));
                context.ChangeTracker.Clear();

                // The restrictive references are enforced: an orphan session fails.
                context.AuthorizationCodes.Add(new AuthorizationCodeEntity
                {
                    Id = Guid.NewGuid(),
                    CodeDigest = AuthorizationCodeDigest.Compute(
                        "session-orphan-0123456789abcdefghijklmnopqrstu"),
                    AppRegistrationId = appId,
                    AccountId = accountId,
                    IdentitySessionId = Guid.NewGuid(),
                    RedirectUri = "https://client.example.com/callback",
                    Scope = "openid",
                    Nonce = "server-contract-nonce-value",
                    CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    AuthTime = createdAt,
                    CreatedAt = DateTimeOffset.UtcNow,
                    ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(
                        IdentityConstants.AuthorizationCodeLifetimeSeconds)
                });
                await Assert.ThrowsAsync<DbUpdateException>(() =>
                    context.SaveChangesAsync(cancellationToken));
                context.ChangeTracker.Clear();

                // The valid shape — a consumed row may carry the family link — persists.
                var valid = new AuthorizationCodeEntity
                {
                    Id = Guid.NewGuid(),
                    CodeDigest = AuthorizationCodeDigest.Compute(
                        "valid-shape-0123456789abcdefghijklmnopqrstuv"),
                    AppRegistrationId = appId,
                    AccountId = accountId,
                    IdentitySessionId = sessionId,
                    RedirectUri = "https://client.example.com/callback",
                    Scope = "openid",
                    Nonce = "server-contract-nonce-value",
                    CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    AuthTime = createdAt,
                    CreatedAt = DateTimeOffset.UtcNow,
                    ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(
                        IdentityConstants.AuthorizationCodeLifetimeSeconds),
                    ConsumedAt = DateTimeOffset.UtcNow,
                    RefreshFamilyId = Guid.NewGuid()
                };
                context.AuthorizationCodes.Add(valid);
                await context.SaveChangesAsync(cancellationToken);
                context.ChangeTracker.Clear();

                // Deleting the referenced session fails; no cascade.
                var session = await context.IdentitySessions
                    .SingleAsync(row => row.Id == sessionId, cancellationToken);
                context.IdentitySessions.Remove(session);
                await Assert.ThrowsAsync<DbUpdateException>(() =>
                    context.SaveChangesAsync(cancellationToken));
                context.ChangeTracker.Clear();

                var store = new AuthorizationCodeStore(
                    new AuthorizationCodeRepository(context),
                    new EfCoreUnitOfWork(context));
                Assert.Equal(
                    1,
                    await store.CleanupExpiredAsync(
                        DateTimeOffset.UtcNow.AddHours(IdentityConstants.AuthorizationCodeRetentionHours + 1),
                        cancellationToken));

                // With the code gone the session deletion succeeds.
                context.IdentitySessions.Remove(
                    await context.IdentitySessions.SingleAsync(row => row.Id == sessionId, cancellationToken));
                await context.SaveChangesAsync(cancellationToken);
            }
        }
    }

    /// <summary>
    /// The real <c>PS-05</c> concurrency matrix on PostgreSQL: two independent connections
    /// redeeming one code under the session→code lock order (exactly one commits, the loser
    /// blocks and then reads <c>Consumed</c>), two lock-free conditional consumptions (exactly
    /// one <c>true</c>), and the logout-vs-redemption race (<c>EV-28</c>/<c>SC-05</c>/<c>SC-06</c>
    /// storage shapes: the code stays unconsumed when the session revocation commits first).
    /// </summary>
    [Fact]
    public async Task PostgreSqlAuthorizationCodes_ConcurrentRedemptionLockOrderAndSingleConsumption()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL authorization code concurrency matrix.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            await using (var migration = new IdentityDbContext(options))
            {
                await migration.Database.MigrateAsync(TestContext.Current.CancellationToken);
            }

            var (accountId, credentialId, appId) = await SeedAuthorizationCodePrerequisitesAsync(options);
            var cancellationToken = TestContext.Current.CancellationToken;
            var authTime = DateTimeOffset.UtcNow.AddMinutes(-5);

            // (a) A locks session then code and consumes without committing; B blocks on the same
            // lock order; after A commits B reads Consumed and its conditional update hits zero.
            var codeA = await CreateAuthorizationCodeAsync(
                options, accountId, credentialId, appId, authTime);
            var consumeInstant = DateTimeOffset.UtcNow;
            var holderReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var releaseHolder = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var holderTask = Task.Run(async () =>
            {
                await using var holderContext = new IdentityDbContext(options);
                var sessionStore = new IdentitySessionStore(
                    new IdentitySessionRepository(holderContext),
                    new EfCoreUnitOfWork(holderContext));
                var codeStore = new AuthorizationCodeStore(
                    new AuthorizationCodeRepository(holderContext),
                    new EfCoreUnitOfWork(holderContext));
                var strategy = holderContext.Database.CreateExecutionStrategy();
                await strategy.ExecuteAsync(async operationToken =>
                {
                    await using var transaction = await holderContext.Database
                        .BeginTransactionAsync(operationToken);
                    var lockedSession = await sessionStore.LockAsync(
                        codeA.SessionId, operationToken);
                    Assert.NotNull(lockedSession);
                    var lockedCode = await codeStore.LockAsync(codeA.Id, operationToken);
                    Assert.NotNull(lockedCode);
                    Assert.Null(lockedCode!.ConsumedAt);
                    Assert.True(await codeStore.TryConsumeAsync(codeA.Id, consumeInstant, operationToken));
                    holderReady.SetResult();
                    await releaseHolder.Task.WaitAsync(TimeSpan.FromSeconds(60), operationToken);
                    await transaction.CommitAsync(operationToken);
                }, CancellationToken.None);
            }, CancellationToken.None);

            await holderReady.Task.WaitAsync(TimeSpan.FromSeconds(60), cancellationToken);

            var blockedRedemption = RedeemAuthorizationCodeAsync(
                options, codeA.SessionId, codeA.Id, consumeInstant.AddMilliseconds(1));
            await Assert.ThrowsAsync<TimeoutException>(() =>
                blockedRedemption.WaitAsync(TimeSpan.FromMilliseconds(500)));

            releaseHolder.SetResult();
            await holderTask.WaitAsync(TimeSpan.FromSeconds(60), cancellationToken);

            var loserOutcome = await blockedRedemption.WaitAsync(TimeSpan.FromSeconds(60), cancellationToken);
            Assert.False(loserOutcome.ConsumedThisCall);
            Assert.Equal(AuthorizationCodeState.Consumed, loserOutcome.Classification);
            Assert.Equal(
                consumeInstant.UtcTicks / 10,
                (await GetAuthorizationCodeRowAsync(options, codeA.Id)).ConsumedAt!.Value.UtcTicks / 10);

            // (b) Two lock-free conditional consumptions race: exactly one true.
            var codeB = await CreateAuthorizationCodeAsync(
                options, accountId, credentialId, appId, authTime);
            var raceResults = await Task.WhenAll(
                ConsumeAuthorizationCodeAsync(options, codeB.Id),
                ConsumeAuthorizationCodeAsync(options, codeB.Id));
            Assert.Equal(1, raceResults.Count(result => result));

            // (c) EV-28/SC-05: the logout side locks the session first, revokes, commits; the
            // redemption side then locks the session, sees the revocation, and never consumes.
            var codeC = await CreateAuthorizationCodeAsync(
                options, accountId, credentialId, appId, authTime);
            var revokeInstant = DateTimeOffset.UtcNow;
            await using (var logoutContext = new IdentityDbContext(options))
            {
                var sessionStore = new IdentitySessionStore(
                    new IdentitySessionRepository(logoutContext),
                    new EfCoreUnitOfWork(logoutContext));
                var strategy = logoutContext.Database.CreateExecutionStrategy();
                await strategy.ExecuteAsync(async operationToken =>
                {
                    await using var transaction = await logoutContext.Database
                        .BeginTransactionAsync(operationToken);
                    await sessionStore.LockAsync(codeC.SessionId, operationToken);
                    Assert.Equal(
                        IdentitySessionRevocationResult.Revoked,
                        await sessionStore.RevokeAsync(
                            codeC.SessionId, IdentitySessionRevocationReason.Logout,
                            revokeInstant, operationToken));
                    await transaction.CommitAsync(operationToken);
                }, cancellationToken);
            }

            var postLogout = await RedeemAuthorizationCodeAsync(
                options, codeC.SessionId, codeC.Id, DateTimeOffset.UtcNow);
            Assert.NotNull(postLogout.Session);
            Assert.NotNull(postLogout.Session!.RevokedAt);
            Assert.Equal(
                revokeInstant.UtcTicks / 10,
                postLogout.Session.RevokedAt!.Value.UtcTicks / 10);
            Assert.Null((await GetAuthorizationCodeRowAsync(options, codeC.Id)).ConsumedAt);
        }
    }

    /// <summary>
    /// One injected PostgreSQL serialization failure inside the consumption unit is replayed as a
    /// whole by the retrying execution strategy: the outcome stays a single committed consumption.
    /// </summary>
    [Fact]
    public async Task PostgreSqlAuthorizationCodes_TransientSerializationFailureReplaysTheConsumptionOnce()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL authorization code replay matrix.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            await using (var migration = new IdentityDbContext(options))
            {
                await migration.Database.MigrateAsync(TestContext.Current.CancellationToken);
            }

            var (accountId, credentialId, appId) = await SeedAuthorizationCodePrerequisitesAsync(options);
            var code = await CreateAuthorizationCodeAsync(
                options, accountId, credentialId, appId, DateTimeOffset.UtcNow.AddMinutes(-5));

            var interceptor = new TransientAuthorizationCodeUpdateFailureInterceptor();
            var interceptedBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            interceptedBuilder.UseIdentityDatabase(databaseOptions);
            interceptedBuilder.AddInterceptors(interceptor);
            await using var context = new IdentityDbContext(interceptedBuilder.Options);
            var store = new AuthorizationCodeStore(
                new AuthorizationCodeRepository(context),
                new EfCoreUnitOfWork(context));

            var consumeInstant = DateTimeOffset.UtcNow;
            Assert.True(await store.TryConsumeAsync(
                code.Id, consumeInstant, TestContext.Current.CancellationToken));

            Assert.True(interceptor.ThrewOnce);
            var row = await GetAuthorizationCodeRowAsync(options, code.Id);
            Assert.Equal(consumeInstant.UtcTicks / 10, row.ConsumedAt!.Value.UtcTicks / 10);

            Assert.False(await store.TryConsumeAsync(
                code.Id, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken));
        }
    }

    /// <summary>
    /// <c>AC-09</c> on the real PostgreSQL matrix: one instance's session is reused by another
    /// instance through the shared database only; two concurrent authorize reuses of the same
    /// session produce two distinct codes with the bounded slide written at most once
    /// (<c>SC-07</c>); and the forced serial outcomes of revocation-versus-reuse hold —
    /// revocation first makes the reuse answer <c>null</c> with zero writes, reuse first still
    /// allows the later revocation.
    /// </summary>
    [Fact]
    public async Task PostgreSqlAuthorizationSessionReuse_CrossInstanceConcurrencyAndSerialOutcomes()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL authorize session reuse matrix.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            await using (var migration = new IdentityDbContext(options))
            {
                await migration.Database.MigrateAsync(TestContext.Current.CancellationToken);
            }

            var (accountId, credentialId, appId) = await SeedAuthorizationCodePrerequisitesAsync(options);
            var accepted = new OidcAuthorizationValidationResult.Accepted(
                "code-contract-app",
                appId,
                "https://client.example.com/callback",
                "openid profile",
                "ServerReuseState_0123456789abcdef",
                "ServerReuseNonce_0123456789abcdef",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");

            // ---- SC-07: two concurrent reuses, two codes, at most one slide write ----
            // The session's activity starts two minutes in the past, so exactly the first
            // committed reuse slides it and the second observes the fresh activity.
            var now = DateTimeOffset.UtcNow;
            var racedSessionId = await CreateReuseSessionAsync(
                options, accountId, credentialId, now.AddMinutes(-2));
            var racedCodes = await Task.WhenAll(
                TryReuseAsync(options, accepted, racedSessionId, now),
                TryReuseAsync(options, accepted, racedSessionId, now));
            Assert.All(racedCodes, code => Assert.False(string.IsNullOrEmpty(code)));
            Assert.NotEqual(racedCodes[0], racedCodes[1]);

            await using (var assertion = new IdentityDbContext(options))
            {
                var cancellationToken = TestContext.Current.CancellationToken;
                var session = await assertion.IdentitySessions.AsNoTracking()
                    .SingleAsync(row => row.Id == racedSessionId, cancellationToken);
                Assert.Null(session.RevokedAt);
                Assert.Equal(now.UtcTicks / 10, session.LastSeenAt.UtcTicks / 10);
                Assert.Equal(
                    now.AddMinutes(IdentityConstants.IdentitySessionIdleTimeoutMinutes).UtcTicks / 10,
                    session.IdleExpiresAt.UtcTicks / 10);
                Assert.Equal(2, await assertion.AuthorizationCodes
                    .CountAsync(row => row.IdentitySessionId == racedSessionId, cancellationToken));
                Assert.Equal(2, await assertion.AuditLogs
                    .CountAsync(row => row.Action == "oidc.authorize.validated", cancellationToken));
            }

            // ---- Revocation commits first: the other instance's reuse answers null, no writes ----
            var revokedSessionId = await CreateReuseSessionAsync(options, accountId, credentialId);
            await RevokeRedemptionSessionAsync(options, revokedSessionId);
            Assert.Null(await TryReuseAsync(options, accepted, revokedSessionId, DateTimeOffset.UtcNow));

            await using (var assertion = new IdentityDbContext(options))
            {
                var cancellationToken = TestContext.Current.CancellationToken;
                Assert.Empty(await assertion.AuthorizationCodes.AsNoTracking()
                    .Where(row => row.IdentitySessionId == revokedSessionId)
                    .ToListAsync(cancellationToken));
            }

            // ---- Reuse commits first: the later revocation still succeeds ----
            var reusedSessionId = await CreateReuseSessionAsync(options, accountId, credentialId);
            Assert.False(string.IsNullOrEmpty(await TryReuseAsync(
                options, accepted, reusedSessionId, DateTimeOffset.UtcNow)));
            await RevokeRedemptionSessionAsync(options, reusedSessionId);

            await using (var assertion = new IdentityDbContext(options))
            {
                var session = await assertion.IdentitySessions.AsNoTracking()
                    .SingleAsync(
                        row => row.Id == reusedSessionId, TestContext.Current.CancellationToken);
                Assert.NotNull(session.RevokedAt);
                Assert.True(await assertion.AuthorizationCodes.AsNoTracking()
                    .AnyAsync(
                        row => row.IdentitySessionId == reusedSessionId,
                        TestContext.Current.CancellationToken));
            }
        }
    }

    /// <summary>Creates one session over the shared database — the "instance A" half of the reuse.</summary>
    private static async Task<Guid> CreateReuseSessionAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid accountId,
        Guid credentialId,
        DateTimeOffset? authTime = null)
    {
        await using var context = new IdentityDbContext(options);
        var sessions = new IdentitySessionStore(
            new IdentitySessionRepository(context), new EfCoreUnitOfWork(context));
        var session = await sessions.CreateAsync(
            accountId, credentialId, authTime ?? DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
        return session.Id;
    }

    /// <summary>
    /// One "instance" of the reuse service on its own connection and unit of work — the same
    /// composition the host registers per request scope.
    /// </summary>
    private static async Task<string?> TryReuseAsync(
        DbContextOptions<IdentityDbContext> options,
        OidcAuthorizationValidationResult.Accepted accepted,
        Guid sessionId,
        DateTimeOffset now)
    {
        await using var context = new IdentityDbContext(options);
        var unitOfWork = new EfCoreUnitOfWork(context);
        var service = new SignaCore.Host.Services.OidcAuthorizationSessionReuseService(
            new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork),
            new AuthorizationCodeStore(new AuthorizationCodeRepository(context), unitOfWork),
            new AccountRepository(context),
            new AuditService(new LoginHistoryRepository(context), new AuditLogRepository(context)),
            unitOfWork,
            context);
        return await service.TryIssueAsync(
            accepted,
            sessionId,
            now,
            null,
            "reuse-contract-correlation",
            TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// <c>AC-06</c>/<c>EV-20</c>/<c>EV-24</c>/<c>EV-25</c> on the real PostgreSQL matrix: two
    /// independent service providers redeem the same code concurrently — exactly one commits the
    /// consumption and its audit, the loser observes the committed consumption under the locks and
    /// commits the replay disposal; the forced serial outcomes of <c>SC-05</c>/<c>SC-06</c> hold
    /// their write shapes; and one synthetic SQLSTATE 40001 on the consumption update replays the
    /// whole unit exactly once under <c>EnableRetryOnFailure</c>.
    /// </summary>
    [Fact]
    public async Task PostgreSqlAuthorizationCodeRedemption_ConcurrencySerialOutcomesAndRetry()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL authorization code redemption matrix.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            await using (var migration = new IdentityDbContext(options))
            {
                await migration.Database.MigrateAsync(TestContext.Current.CancellationToken);
            }

            var (accountId, credentialId, appId) = await SeedRedemptionPrerequisitesAsync(options);

            // ---- EV-25/SC-13: two instances race over one code; exactly one winner ----
            var raced = await CreateRedemptionCodeAsync(options, accountId, credentialId, appId);
            var outcomes = await Task.WhenAll(
                RedeemAuthorizationCodeAsync(options, raced.Code),
                RedeemAuthorizationCodeAsync(options, raced.Code));
            Assert.Equal(1, outcomes.Count(outcome => outcome.IsSuccess));
            var loser = Assert.Single(outcomes, outcome => !outcome.IsSuccess);
            Assert.Equal(400, loser.Status);
            Assert.Equal("replay", loser.FailureReason);

            await using (var assertion = new IdentityDbContext(options))
            {
                var cancellationToken = TestContext.Current.CancellationToken;
                var codeRow = await assertion.AuthorizationCodes.AsNoTracking()
                    .SingleAsync(row => row.Id == raced.CodeId, cancellationToken);
                Assert.NotNull(codeRow.ConsumedAt);
                var session = await assertion.IdentitySessions.AsNoTracking()
                    .SingleAsync(row => row.Id == raced.SessionId, cancellationToken);
                Assert.NotNull(session.RevokedAt);
                Assert.Equal("code_replay", session.RevocationReason);
                // The audit ids are random Guids and the two instances commit independently,
                // so the row order carries no meaning: the shape is the one-of-each set.
                var audits = await assertion.AuditLogs.AsNoTracking()
                    .Where(row => row.TargetId == raced.CodeId.ToString("D"))
                    .ToListAsync(cancellationToken);
                Assert.Equal(2, audits.Count);
                Assert.Equal(
                    new HashSet<string>(StringComparer.Ordinal) { "oidc.code.redeemed", "oidc.code.replayed" },
                    audits.Select(row => row.Action).ToHashSet(StringComparer.Ordinal));
                Assert.Contains(
                    "family:none",
                    Assert.Single(audits, row => row.Action == "oidc.code.replayed").Description,
                    StringComparison.Ordinal);
            }

            // ---- SC-05: the revocation commits first; the redemption rejects without consuming ----
            var revokedFirst = await CreateRedemptionCodeAsync(options, accountId, credentialId, appId);
            await RevokeRedemptionSessionAsync(options, revokedFirst.SessionId);
            var afterRevoke = await RedeemAuthorizationCodeAsync(options, revokedFirst.Code);
            Assert.False(afterRevoke.IsSuccess);
            Assert.Equal("invalid_grant", afterRevoke.FailureReason);

            await using (var assertion = new IdentityDbContext(options))
            {
                var cancellationToken = TestContext.Current.CancellationToken;
                var codeRow = await assertion.AuthorizationCodes.AsNoTracking()
                    .SingleAsync(row => row.Id == revokedFirst.CodeId, cancellationToken);
                Assert.Null(codeRow.ConsumedAt);
                Assert.Empty(await assertion.AuditLogs.AsNoTracking()
                    .Where(row => row.TargetId == revokedFirst.CodeId.ToString("D"))
                    .ToListAsync(cancellationToken));
                var session = await assertion.IdentitySessions.AsNoTracking()
                    .SingleAsync(row => row.Id == revokedFirst.SessionId, cancellationToken);
                Assert.Equal("administrative", session.RevocationReason);
            }

            // ---- SC-06: the redemption commits first; the later revocation still succeeds ----
            var redeemedFirst = await CreateRedemptionCodeAsync(options, accountId, credentialId, appId);
            var winnerOutcome = await RedeemAuthorizationCodeAsync(options, redeemedFirst.Code);
            Assert.True(winnerOutcome.IsSuccess);
            await RevokeRedemptionSessionAsync(options, redeemedFirst.SessionId);

            await using (var assertion = new IdentityDbContext(options))
            {
                var cancellationToken = TestContext.Current.CancellationToken;
                var codeRow = await assertion.AuthorizationCodes.AsNoTracking()
                    .SingleAsync(row => row.Id == redeemedFirst.CodeId, cancellationToken);
                Assert.NotNull(codeRow.ConsumedAt);
                var session = await assertion.IdentitySessions.AsNoTracking()
                    .SingleAsync(row => row.Id == redeemedFirst.SessionId, cancellationToken);
                Assert.Equal("administrative", session.RevocationReason);
            }

            // ---- 40001: one transient serialization failure replays the unit exactly once ----
            var retried = await CreateRedemptionCodeAsync(options, accountId, credentialId, appId);
            var interceptor = new TransientAuthorizationCodeUpdateFailureInterceptor();
            var interceptedBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            interceptedBuilder.UseIdentityDatabase(databaseOptions);
            interceptedBuilder.AddInterceptors(interceptor);
            var retriedOutcome = await RedeemAuthorizationCodeAsync(
                interceptedBuilder.Options, retried.Code);
            Assert.True(retriedOutcome.IsSuccess);
            Assert.True(interceptor.ThrewOnce);

            await using (var assertion = new IdentityDbContext(options))
            {
                var cancellationToken = TestContext.Current.CancellationToken;
                var audits = await assertion.AuditLogs.AsNoTracking()
                    .Where(row => row.TargetId == retried.CodeId.ToString("D"))
                    .ToListAsync(cancellationToken);
                var redeemed = Assert.Single(audits);
                Assert.Equal("oidc.code.redeemed", redeemed.Action);
            }
        }
    }

    private static async Task<(Guid AccountId, Guid CredentialId, Guid AppId)>
        SeedRedemptionPrerequisitesAsync(DbContextOptions<IdentityDbContext> options)
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
            Id = credentialId, AccountId = accountId, Username = "redemption-contract-user",
            PasswordHash = "hash", CreatedAt = DateTimeOffset.UtcNow
        });
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = appId, AppId = "redemption-contract-app", AppSecretHash = "hash",
            AppName = "Redemption Contract", IsActive = true, CreatedAt = DateTimeOffset.UtcNow,
            AudienceMode = AudienceMode.PerApplication,
            ClientType = OidcClientType.Confidential,
            AllowAuthorizationCode = true,
            AllowedScopes = "openid profile",
            AllowRefreshToken = false
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        return (accountId, credentialId, appId);
    }

    private static async Task<(string Code, Guid CodeId, Guid SessionId)> CreateRedemptionCodeAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid accountId,
        Guid credentialId,
        Guid appId)
    {
        await using var context = new IdentityDbContext(options);
        var unitOfWork = new EfCoreUnitOfWork(context);
        var sessions = new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork);
        var codes = new AuthorizationCodeStore(new AuthorizationCodeRepository(context), unitOfWork);
        var session = await sessions.CreateAsync(
            accountId, credentialId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
        var creation = await codes.CreateAsync(
            session,
            new AuthorizationCodeBinding(
                appId,
                "https://client.example.com/callback",
                "openid profile",
                "RedemptionCanaryNonce_0123456789abcdef",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
            DateTimeOffset.UtcNow,
            TestContext.Current.CancellationToken);
        return (creation.Code, creation.Id, session.Id);
    }

    /// <summary>
    /// One "instance" of the redemption service on its own connection and unit of work — the same
    /// composition the host registers per request scope, with the signing key held in memory.
    /// </summary>
    private static async Task<SignaCore.Host.Services.AuthorizationCodeRedemptionOutcome>
        RedeemAuthorizationCodeAsync(
            DbContextOptions<IdentityDbContext> options,
            string code)
    {
        await using var context = new IdentityDbContext(options);
        var application = await context.AppRegistrations
            .AsNoTracking()
            .SingleAsync(
                app => app.AppId == "redemption-contract-app",
                TestContext.Current.CancellationToken);
        var unitOfWork = new EfCoreUnitOfWork(context);
        var accountRepository = new AccountRepository(context);
        var meterFactory = new Mock<System.Diagnostics.Metrics.IMeterFactory>();
        meterFactory
            .Setup(factory => factory.Create(It.IsAny<System.Diagnostics.Metrics.MeterOptions>()))
            .Returns(new System.Diagnostics.Metrics.Meter("SignaCore"));
        var service = new SignaCore.Host.Services.AuthorizationCodeRedemptionService(
            new AuthorizationCodeStore(new AuthorizationCodeRepository(context), unitOfWork),
            new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork),
            accountRepository,
            new PasswordCredentialRepository(context),
            new InteractiveAccessTokenFactory(
                new JwtOptions { Issuer = "https://redemption-contract.test" },
                NullLogger<InteractiveAccessTokenFactory>.Instance),
            new InteractiveIdTokenFactory(new JwtOptions { Issuer = "https://redemption-contract.test" }),
            new RefreshTokenFamilyStore(
                new RefreshTokenRepository(context),
                unitOfWork,
                NullLogger<RefreshTokenFamilyStore>.Instance),
            callbackService: null,
            new StaticRedemptionKeyManager(),
            new AuditService(new LoginHistoryRepository(context), new AuditLogRepository(context)),
            new AuthMetrics(meterFactory.Object),
            unitOfWork,
            context,
            new AdminIdentityOptions(),
            NullLogger<SignaCore.Host.Services.AuthorizationCodeRedemptionService>.Instance);
        return await service.RedeemAsync(
            application,
            new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
            {
                ["grant_type"] = SignaCore.Host.Services.AuthorizationCodeRedemptionService.GrantType,
                ["code"] = code,
                ["redirect_uri"] = "https://client.example.com/callback",
                ["code_verifier"] = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
            }),
            null,
            "redemption-contract-correlation",
            TestContext.Current.CancellationToken);
    }

    /// <summary>The forced-serial revocation of <c>SC-05</c>/<c>SC-06</c>: lock, revoke, commit.</summary>
    private static async Task RevokeRedemptionSessionAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid sessionId)
    {
        await using var context = new IdentityDbContext(options);
        var sessions = new IdentitySessionStore(
            new IdentitySessionRepository(context), new EfCoreUnitOfWork(context));
        var strategy = context.Database.CreateExecutionStrategy();
        await strategy.ExecuteAsync(async operationToken =>
        {
            await using var transaction = await context.Database
                .BeginTransactionAsync(operationToken);
            await sessions.LockAsync(sessionId, operationToken);
            await sessions.RevokeAsync(
                sessionId, IdentitySessionRevocationReason.Administrative,
                DateTimeOffset.UtcNow, operationToken);
            await transaction.CommitAsync(operationToken);
        }, TestContext.Current.CancellationToken);
    }

    /// <summary>A synchronous, in-memory key manager for the contract composition.</summary>
    private sealed class StaticRedemptionKeyManager : SignaCore.Domain.Keys.IKeyManager
    {
        private readonly Microsoft.IdentityModel.Tokens.RsaSecurityKey _key;

        public StaticRedemptionKeyManager()
        {
            var rsa = System.Security.Cryptography.RSA.Create(2048);
            _key = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsa)
            {
                KeyId = Guid.NewGuid().ToString()
            };
        }

        public Microsoft.IdentityModel.Tokens.RsaSecurityKey GetCurrentKey() => _key;

        public IReadOnlyList<Microsoft.IdentityModel.Tokens.SecurityKey> GetValidationKeys() => [_key];

        public Task RefreshKeysAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<IReadOnlyList<Microsoft.IdentityModel.Tokens.RsaSecurityKey>> GetValidKeysAsync(
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<Microsoft.IdentityModel.Tokens.RsaSecurityKey>>([_key]);

        public Task<bool> NeedsKeyRotationAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(false);

        public Task RotateKeyAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task InitializationCompleted => Task.CompletedTask;
    }

    /// <c>EV-01</c> on the real PostgreSQL matrix: two independent service providers run the
    /// success transaction over the same handle concurrently — exactly one commits its session,
    /// code, and audit, the loser observes the committed consumption and rolls back with zero
    /// writes — and a continuation created by one instance's service completes on another
    /// instance's service, because the whole flow rides the shared database only.
    /// </summary>
    [Fact]
    public async Task PostgreSqlLoginCompletion_ConcurrentCompletionOnce_AndCrossInstanceCompletion()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL login completion matrix.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            await using (var migration = new IdentityDbContext(options))
            {
                await migration.Database.MigrateAsync(TestContext.Current.CancellationToken);
            }

            var (accountId, credentialId, appId) =
                await SeedAuthorizationCodePrerequisitesAsync(options);

            // ---- Two independent service providers complete the same handle: one winner ----
            var (handle, accepted) = await CreateLoginContinuationAsync(
                options, appId, "ServerCompletionState_0123456789ab");
            var completions = await Task.WhenAll(
                CompleteLoginAsync(options, handle, accepted, accountId, credentialId),
                CompleteLoginAsync(options, handle, accepted, accountId, credentialId));
            var winner = Assert.Single(completions, completion => completion is not null)!;

            await using (var assertion = new IdentityDbContext(options))
            {
                var cancellationToken = TestContext.Current.CancellationToken;
                var session = Assert.Single(await assertion.IdentitySessions.AsNoTracking()
                    .Where(row => row.AccountId == accountId).ToListAsync(cancellationToken));
                Assert.Equal(winner.SessionId, session.Id);
                Assert.Equal(credentialId, session.PasswordCredentialId);
                var code = Assert.Single(await assertion.AuthorizationCodes.AsNoTracking()
                    .Where(row => row.AccountId == accountId).ToListAsync(cancellationToken));
                Assert.Equal(session.Id, code.IdentitySessionId);
                Assert.Equal(appId, code.AppRegistrationId);
                var continuation = await assertion.AuthorizationRequests.AsNoTracking()
                    .SingleAsync(
                        row => row.HandleDigest == LoginHandleDigest.Compute(handle),
                        cancellationToken);
                Assert.NotNull(continuation.ConsumedAt);
                var history = Assert.Single(await assertion.LoginHistories.AsNoTracking()
                    .Where(row => row.AccountId == accountId).ToListAsync(cancellationToken));
                Assert.Equal("login_success", history.EventType);
                var account = await assertion.Accounts.AsNoTracking()
                    .SingleAsync(row => row.Id == accountId, cancellationToken);
                Assert.Equal(1, account.TotalLoginCount);
            }

            // ---- Instance A's service creates the continuation, instance B's completes it ----
            var (secondHandle, secondAccepted) = await CreateLoginContinuationAsync(
                options, appId, "ServerCompletionState_9876543210ab");
            var second = await CompleteLoginAsync(
                options, secondHandle, secondAccepted, accountId, credentialId);
            Assert.NotNull(second);

            await using (var assertion = new IdentityDbContext(options))
            {
                var cancellationToken = TestContext.Current.CancellationToken;
                var sessions = await assertion.IdentitySessions.AsNoTracking()
                    .Where(row => row.AccountId == accountId).ToListAsync(cancellationToken);
                Assert.Equal(2, sessions.Count);
                Assert.Contains(sessions, session => session.Id == second!.SessionId);
                var secondCode = Assert.Single(await assertion.AuthorizationCodes.AsNoTracking()
                    .Where(row => row.IdentitySessionId == second.SessionId)
                    .ToListAsync(cancellationToken));
                Assert.Equal(appId, secondCode.AppRegistrationId);
                Assert.NotNull(secondCode.RedirectUri);
                var secondContinuation = await assertion.AuthorizationRequests.AsNoTracking()
                    .SingleAsync(
                        row => row.HandleDigest == LoginHandleDigest.Compute(secondHandle),
                        cancellationToken);
                Assert.NotNull(secondContinuation.ConsumedAt);
                var account = await assertion.Accounts.AsNoTracking()
                    .SingleAsync(row => row.Id == accountId, cancellationToken);
                Assert.Equal(2, account.TotalLoginCount);
            }
        }
    }

    private static async Task<(string Handle, OidcAuthorizationValidationResult.Accepted Accepted)>
        CreateLoginContinuationAsync(
            DbContextOptions<IdentityDbContext> options,
            Guid appId,
            string state)
    {
        var accepted = new OidcAuthorizationValidationResult.Accepted(
            "code-contract-app",
            appId,
            "https://client.example.com/callback",
            "openid profile",
            state,
            "ServerCanaryNonce_0123456789abcdef",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        await using var context = new IdentityDbContext(options);
        var store = new AuthorizationRequestStore(
            new AuthorizationRequestRepository(context),
            new EfCoreUnitOfWork(context));
        var creation = await store.CreateAsync(
            accepted, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
        return (creation.LoginHandle, accepted);
    }

    /// <summary>
    /// One "instance" of the completion service on its own connection and unit of work — the same
    /// composition the host registers per request scope.
    /// </summary>
    private static async Task<SignaCore.Host.Services.OidcLoginCompletion?> CompleteLoginAsync(
        DbContextOptions<IdentityDbContext> options,
        string handle,
        OidcAuthorizationValidationResult.Accepted accepted,
        Guid accountId,
        Guid credentialId)
    {
        await using var context = new IdentityDbContext(options);
        var unitOfWork = new EfCoreUnitOfWork(context);
        var accountRepository = new AccountRepository(context);
        var service = new SignaCore.Host.Services.OidcLoginCompletionService(
            new AuthorizationRequestStore(new AuthorizationRequestRepository(context), unitOfWork),
            accountRepository,
            new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork),
            new AuthorizationCodeStore(new AuthorizationCodeRepository(context), unitOfWork),
            new LoginAttemptRepository(context),
            new AccountLoginInfoService(accountRepository),
            new AuditService(new LoginHistoryRepository(context), new AuditLogRepository(context)),
            unitOfWork,
            context);
        return await service.CompleteAsync(
            handle,
            accepted,
            ValidationResult.Success(
                new AccountEntity { Id = accountId, IsActive = true },
                IdentityConstants.AuthMethodPassword,
                "server-completion-user",
                passwordCredentialId: credentialId),
            accepted.ClientId,
            null,
            null,
            "server-completion-correlation",
            DateTimeOffset.UtcNow,
            TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// <c>AC-11</c> on the real PostgreSQL matrix: the exact fresh family shape, the backfill
    /// upgrade from <c>AddAuthorizationCodes</c> that preserves every legacy value byte for byte,
    /// the corrupt-write matrix rejected fail-closed, the restrictive references, legacy cleanup
    /// and rotation staying away from interactive rows, and the downgrade gate with its round
    /// trip. The SQLite half lives in <see cref="RefreshTokenFamilyDatabaseContractTests"/>.
    /// </summary>
    [Fact]
    public async Task PostgreSqlRefreshTokenFamilies_BackfillConstraintsCleanupAndDownGate()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL refresh family contract.");

        const string codeMigration = "20260916160627_AddAuthorizationCodes";
        const string appId = "family-contract-app";
        const string canonicalScope = "openid profile";
        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            // ---- The backfill upgrade from AddAuthorizationCodes ----
            var accountId = Guid.NewGuid();
            var credentialId = Guid.NewGuid();
            var appRegistrationId = Guid.NewGuid();
            var liveId = Guid.NewGuid();
            const string livePlaintext = "family-upgrade-live-token";
            const string plaintextTokenValue = "legacy-plaintext-token-value";
            var createdAt = DateTimeOffset.UtcNow.AddHours(-2);
            Guid sessionId;

            await using (var context = new IdentityDbContext(options))
            {
                var cancellationToken = TestContext.Current.CancellationToken;
                var migrator = context.GetService<IMigrator>();
                await migrator.MigrateAsync(codeMigration, cancellationToken);

                context.Accounts.Add(new AccountEntity
                {
                    Id = accountId, IsActive = true, CreatedAt = createdAt
                });
                context.PasswordCredentials.Add(new PasswordCredentialEntity
                {
                    Id = credentialId, AccountId = accountId, Username = "family-contract-user",
                    PasswordHash = "hash", CreatedAt = createdAt
                });
                context.AppRegistrations.Add(new AppRegistrationEntity
                {
                    Id = appRegistrationId, AppId = appId, AppSecretHash = "hash",
                    AppName = "Family Contract", IsActive = true, CreatedAt = createdAt
                });
                var session = CreateIdentitySession(accountId, credentialId);
                context.IdentitySessions.Add(session);
                await context.SaveChangesAsync(cancellationToken);
                sessionId = session.Id;

                // Five legacy shapes on the pre-family schema, seeded with raw SQL: live,
                // expired, revoked, plaintext (never rewritten; the startup conversion was
                // removed), and a cross-application mint. Plus one consumed code, family null.
                await RefreshTokenFamilyTestSupport.InsertLegacyRefreshTokenPostgreSqlAsync(
                    context, liveId, accountId, RefreshTokenDigest.Compute(livePlaintext),
                    createdAt, DateTimeOffset.UtcNow.AddHours(1), appId);
                await RefreshTokenFamilyTestSupport.InsertLegacyRefreshTokenPostgreSqlAsync(
                    context, Guid.NewGuid(), accountId, RefreshTokenDigest.Compute("family-upgrade-expired"),
                    createdAt, createdAt.AddHours(1), appId);
                await RefreshTokenFamilyTestSupport.InsertLegacyRefreshTokenPostgreSqlAsync(
                    context, Guid.NewGuid(), accountId, RefreshTokenDigest.Compute("family-upgrade-revoked"),
                    createdAt, DateTimeOffset.UtcNow.AddHours(1), appId, isRevoked: true);
                await RefreshTokenFamilyTestSupport.InsertLegacyRefreshTokenPostgreSqlAsync(
                    context, Guid.NewGuid(), accountId, plaintextTokenValue,
                    createdAt, DateTimeOffset.UtcNow.AddHours(1), appId);
                await RefreshTokenFamilyTestSupport.InsertLegacyRefreshTokenPostgreSqlAsync(
                    context, Guid.NewGuid(), accountId, RefreshTokenDigest.Compute("family-upgrade-exchange"),
                    createdAt, DateTimeOffset.UtcNow.AddHours(1), appId,
                    sourceAppId: "family-contract-source-app");
                context.AuthorizationCodes.Add(new AuthorizationCodeEntity
                {
                    Id = Guid.NewGuid(),
                    CodeDigest = AuthorizationCodeDigest.Compute(
                        "family-upgrade-code-0123456789abcdefgh"),
                    AppRegistrationId = appRegistrationId,
                    AccountId = accountId,
                    IdentitySessionId = sessionId,
                    RedirectUri = "https://client.example.test/callback",
                    Scope = "openid",
                    Nonce = "family-upgrade-nonce",
                    CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    AuthTime = createdAt,
                    CreatedAt = createdAt,
                    ExpiresAt = createdAt.AddSeconds(
                        IdentityConstants.AuthorizationCodeLifetimeSeconds),
                    ConsumedAt = createdAt.AddSeconds(1)
                });
                await context.SaveChangesAsync(cancellationToken);

                var tokensBefore = await DumpPostgreSqlAsync(context, FamilyLegacyTokenDumpSql);
                var codesBefore = await DumpPostgreSqlAsync(context, FamilyCodeDumpSql);

                await migrator.MigrateAsync(cancellationToken: cancellationToken);

                Assert.Equal(tokensBefore, await DumpPostgreSqlAsync(context, FamilyLegacyTokenDumpSql));
                Assert.Equal(codesBefore, await DumpPostgreSqlAsync(context, FamilyCodeDumpSql));

                // family_id = id on every row, the other five family columns null.
                var familyDump = await DumpPostgreSqlAsync(context, """
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

                // The live legacy token still rotates; the replacement is a fresh singleton root.
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
                        AppId = appId
                    },
                    cancellationToken));
                await context.SaveChangesAsync(cancellationToken);
                var replacement = await context.RefreshTokens.AsNoTracking()
                    .SingleAsync(row => row.Id == replacementId, cancellationToken);
                Assert.Equal(replacementId, replacement.FamilyId);
                Assert.Null(replacement.ParentId);
                Assert.Null(replacement.IdentitySessionId);
            }

            // ---- Exact fresh family shape ----
            await using (var context = new IdentityDbContext(options))
            {
                var columnDetails = await GetPostgreSqlColumnDetailsAsync(context, "refresh_tokens");
                Assert.Equal("NO", columnDetails["family_id"].IsNullable);
                Assert.Equal("YES", columnDetails["parent_id"].IsNullable);
                Assert.Equal("YES", columnDetails["identity_session_id"].IsNullable);
                Assert.Equal("YES", columnDetails["scope"].IsNullable);
                Assert.Equal(
                    (int?)IdentityConstants.MaxOidcAllowedScopesLength,
                    columnDetails["scope"].MaxLength);
                Assert.Equal("YES", columnDetails["auth_time"].IsNullable);
                Assert.Equal("YES", columnDetails["consumed_at"].IsNullable);

                var checkConstraints = await GetPostgreSqlCheckConstraintsAsync(context, "refresh_tokens");
                Assert.Contains("CK_refresh_tokens_app_id_not_empty", checkConstraints);
                Assert.Contains("CK_refresh_tokens_family_marker", checkConstraints);
                Assert.Contains("CK_refresh_tokens_family_shape", checkConstraints);

                var foreignKeys = await GetPostgreSqlForeignKeysAsync(context, "refresh_tokens");
                Assert.Equal(3, foreignKeys.Count);
                Assert.Contains(foreignKeys, key =>
                    key.ReferencedTable == "identity_sessions" && key.DeleteAction == 'r');
                Assert.Equal(
                    2,
                    foreignKeys.Count(key =>
                        key.ReferencedTable == "refresh_tokens" && key.DeleteAction == 'r'));

                var indexDefinitions = await GetPostgreSqlIndexDefinitionsAsync(context, "refresh_tokens");
                Assert.Contains(indexDefinitions, definition =>
                    definition.Contains("UNIQUE", StringComparison.Ordinal)
                    && definition.Contains("parent_id", StringComparison.Ordinal));
                Assert.Contains(indexDefinitions, definition =>
                    definition.Contains("family_id", StringComparison.Ordinal));
                Assert.Contains(indexDefinitions, definition =>
                    definition.Contains("identity_session_id", StringComparison.Ordinal));

                var codeForeignKeys = await GetPostgreSqlForeignKeysAsync(context, "authorization_codes");
                Assert.Contains(codeForeignKeys, key =>
                    key.ReferencedTable == "refresh_tokens" && key.DeleteAction == 'r');
                var codeIndexes = await GetPostgreSqlIndexDefinitionsAsync(
                    context, "authorization_codes");
                Assert.Contains(codeIndexes, definition =>
                    definition.Contains("refresh_family_id", StringComparison.Ordinal));
            }

            // ---- Corrupt writes, restrictive deletes, cleanup, rotation isolation, Down gate ----
            await using (var context = new IdentityDbContext(options))
            {
                var cancellationToken = TestContext.Current.CancellationToken;
                var migrator = context.GetService<IMigrator>();
                var now = DateTimeOffset.UtcNow;
                var authTime = now.AddMinutes(-5);

                var rootId = Guid.NewGuid();
                var childId = Guid.NewGuid();
                await RefreshTokenFamilyTestSupport.InsertInteractiveMemberPostgreSqlAsync(
                    context, rootId, accountId, appId, rootId, parentId: null, sessionId,
                    canonicalScope, authTime, now, now.AddHours(1), consumedAt: now);
                await RefreshTokenFamilyTestSupport.InsertInteractiveMemberPostgreSqlAsync(
                    context, childId, accountId, appId, rootId, parentId: rootId, sessionId,
                    canonicalScope, authTime, now, now.AddHours(1));

                var missingRowId = Guid.NewGuid();
                var corruptInserts = new (string Label, Func<Task<int>> Insert)[]
                {
                    ("partial-marker", () =>
                    {
                        var markerId = Guid.NewGuid();
                        return InsertFamilyRowPostgreSqlAsync(
                            context, markerId, accountId, appId,
                            familyId: markerId, parentId: null, sessionId, canonicalScope,
                            authTime: null, consumedAt: null);
                    }),
                    ("legacy-with-parent", () => InsertFamilyRowPostgreSqlAsync(
                        context, Guid.NewGuid(), accountId, appId,
                        familyId: childId, parentId: childId, sessionId: null, scope: null,
                        authTime: null, consumedAt: null)),
                    ("legacy-with-consumed", () =>
                    {
                        var consumedId = Guid.NewGuid();
                        return InsertFamilyRowPostgreSqlAsync(
                            context, consumedId, accountId, appId,
                            familyId: consumedId, parentId: null, sessionId: null, scope: null,
                            authTime: null, consumedAt: now);
                    }),
                    ("root-with-parent", () =>
                    {
                        var selfRootId = Guid.NewGuid();
                        return InsertFamilyRowPostgreSqlAsync(
                            context, selfRootId, accountId, appId,
                            familyId: selfRootId, parentId: childId, sessionId: null, scope: null,
                            authTime: null, consumedAt: null);
                    }),
                    ("self-parent", () =>
                    {
                        var selfId = Guid.NewGuid();
                        return InsertFamilyRowPostgreSqlAsync(
                            context, selfId, accountId, appId,
                            familyId: rootId, parentId: selfId, sessionId: null, scope: null,
                            authTime: null, consumedAt: null);
                    }),
                    ("family-missing", () => InsertFamilyRowPostgreSqlAsync(
                        context, Guid.NewGuid(), accountId, appId,
                        familyId: missingRowId, parentId: missingRowId, sessionId, canonicalScope,
                        authTime, consumedAt: null)),
                    ("parent-missing", () => InsertFamilyRowPostgreSqlAsync(
                        context, Guid.NewGuid(), accountId, appId,
                        familyId: rootId, parentId: missingRowId, sessionId, canonicalScope,
                        authTime, consumedAt: null)),
                    ("session-missing", () =>
                    {
                        var sessionRowId = Guid.NewGuid();
                        return InsertFamilyRowPostgreSqlAsync(
                            context, sessionRowId, accountId, appId,
                            familyId: sessionRowId, parentId: null, Guid.NewGuid(), canonicalScope,
                            authTime, consumedAt: null);
                    }),
                    ("second-child", () => InsertFamilyRowPostgreSqlAsync(
                        context, Guid.NewGuid(), accountId, appId,
                        familyId: rootId, parentId: rootId, sessionId, canonicalScope,
                        authTime, consumedAt: null)),
                };
                var tokenCountBefore = await context.RefreshTokens.AsNoTracking()
                    .CountAsync(cancellationToken);
                foreach (var (_, insert) in corruptInserts)
                {
                    var exception = await Record.ExceptionAsync(insert);
                    Assert.NotNull(exception);
                    Assert.IsType<Npgsql.PostgresException>(exception);
                }

                context.AuthorizationCodes.Add(new AuthorizationCodeEntity
                {
                    Id = Guid.NewGuid(),
                    CodeDigest = AuthorizationCodeDigest.Compute(
                        "family-orphan-code-0123456789abcdefghijk"),
                    AppRegistrationId = appRegistrationId,
                    AccountId = accountId,
                    IdentitySessionId = sessionId,
                    RedirectUri = "https://client.example.test/callback",
                    Scope = canonicalScope,
                    Nonce = "family-orphan-nonce",
                    CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    AuthTime = authTime,
                    CreatedAt = now,
                    ExpiresAt = now.AddSeconds(IdentityConstants.AuthorizationCodeLifetimeSeconds),
                    ConsumedAt = now,
                    RefreshFamilyId = missingRowId
                });
                await Assert.ThrowsAsync<DbUpdateException>(() =>
                    context.SaveChangesAsync(cancellationToken));
                context.ChangeTracker.Clear();
                Assert.Equal(
                    tokenCountBefore,
                    await context.RefreshTokens.AsNoTracking().CountAsync(cancellationToken));

                // Restrictive deletes: the root of a child, the session of an interactive row,
                // and a root a code links all refuse; a legacy singleton deletes fine.
                var linkedRootId = Guid.NewGuid();
                await InsertLegacyRootPostgreSqlAsync(context, linkedRootId, accountId, appId, now);
                context.AuthorizationCodes.Add(new AuthorizationCodeEntity
                {
                    Id = Guid.NewGuid(),
                    CodeDigest = AuthorizationCodeDigest.Compute(
                        "family-linked-code-0123456789abcdefgh"),
                    AppRegistrationId = appRegistrationId,
                    AccountId = accountId,
                    IdentitySessionId = sessionId,
                    RedirectUri = "https://client.example.test/callback",
                    Scope = canonicalScope,
                    Nonce = "family-linked-nonce",
                    CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    AuthTime = authTime,
                    CreatedAt = now,
                    ExpiresAt = now.AddSeconds(IdentityConstants.AuthorizationCodeLifetimeSeconds),
                    ConsumedAt = now,
                    RefreshFamilyId = linkedRootId
                });
                await context.SaveChangesAsync(cancellationToken);
                context.ChangeTracker.Clear();

                await AssertDeleteRejectedPostgreSqlAsync(context, "refresh_tokens", rootId);
                await AssertDeleteRejectedPostgreSqlAsync(context, "identity_sessions", sessionId);
                await AssertDeleteRejectedPostgreSqlAsync(context, "refresh_tokens", linkedRootId);

                var deletableId = Guid.NewGuid();
                await InsertLegacyRootPostgreSqlAsync(
                    context, deletableId, accountId, appId, now, expiresAt: now.AddHours(-1));
                await context.Database.ExecuteSqlInterpolatedAsync(
                    $"DELETE FROM refresh_tokens WHERE id = {deletableId}", cancellationToken);
                Assert.False(await context.RefreshTokens.AsNoTracking()
                    .AnyAsync(row => row.Id == deletableId, cancellationToken));

                // Legacy cleanup beside a revoked-and-expired interactive family: only the
                // legacy rows go, the family stays for #98's child-first cleanup.
                var interactiveRootId2 = Guid.NewGuid();
                await RefreshTokenFamilyTestSupport.InsertInteractiveMemberPostgreSqlAsync(
                    context, interactiveRootId2, accountId, appId, interactiveRootId2,
                    parentId: null, sessionId, canonicalScope, authTime,
                    now.AddHours(-2), now.AddHours(-1), isRevoked: true, consumedAt: now.AddHours(-1));
                var expiredLegacyId = Guid.NewGuid();
                var revokedLegacyId = Guid.NewGuid();
                await InsertLegacyRootPostgreSqlAsync(
                    context, expiredLegacyId, accountId, appId, now, expiresAt: now.AddHours(-1));
                await InsertLegacyRootPostgreSqlAsync(
                    context, revokedLegacyId, accountId, appId, now, isRevoked: true);
                var deleted = await new RefreshTokenRepository(context)
                    .RemoveExpiredAndRevokedAsync(cancellationToken);
                // The upgraded expired, revoked, and rotated-source legacy rows plus the two
                // fresh ones; every interactive member and every live legacy row stays.
                Assert.Equal(5, deleted);
                Assert.True(await context.RefreshTokens.AsNoTracking()
                    .AnyAsync(row => row.Id == interactiveRootId2, cancellationToken));
                Assert.True(await context.RefreshTokens.AsNoTracking()
                    .AnyAsync(row => row.Id == rootId, cancellationToken));
                Assert.False(await context.RefreshTokens.AsNoTracking()
                    .AnyAsync(row => row.Id == expiredLegacyId, cancellationToken));
                Assert.False(await context.RefreshTokens.AsNoTracking()
                    .AnyAsync(row => row.Id == revokedLegacyId, cancellationToken));

                // Legacy rotation of an interactive member's digest refuses without any write.
                var interactivePlaintext = "family-contract-token-" + rootId.ToString("N");
                Assert.False(await new RefreshTokenRepository(context).TryRotateAsync(
                    interactivePlaintext,
                    new RefreshTokenEntity
                    {
                        Id = Guid.NewGuid(),
                        AccountId = accountId,
                        TokenValue = RefreshTokenDigest.Compute("family-rotation-replacement"),
                        CreatedAt = now,
                        ExpiresAt = now.AddHours(1),
                        AppId = appId
                    },
                    cancellationToken));
                await context.SaveChangesAsync(cancellationToken);
                var rootRow = await context.RefreshTokens.AsNoTracking()
                    .SingleAsync(row => row.Id == rootId, cancellationToken);
                Assert.False(rootRow.IsRevoked);
                Assert.Equal(
                    now.UtcTicks / 10,
                    rootRow.ConsumedAt!.Value.UtcTicks / 10);

                // The down gate and the round trip now live behind the retirement boundary: a
                // downgrade walk from the current version is refused by RetireSystemSettings —
                // the newest migration — before the family gate can fire, so they are exercised
                // on a fresh database staged at the family migration, inside the pre-retirement
                // window where they are reachable.
                await using (var gate = new PostgreSqlBuilder(PostgreSqlImage)
                    .WithDatabase("identity")
                    .WithUsername("postgres")
                    .WithPassword("postgres")
                    .Build())
                {
                    await gate.StartAsync(TestContext.Current.CancellationToken);
                    var gateOptions = CreateDatabaseOptions(
                        "PostgreSQL",
                        gate.GetConnectionString());
                    var gateBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
                    gateBuilder.UseIdentityDatabase(gateOptions);
                    var gateContextOptions = gateBuilder.Options;
                    await WaitUntilConnectableAsync(gateContextOptions);
                    await using var gateContext = new IdentityDbContext(gateContextOptions);
                    var gateMigrator = gateContext.GetService<IMigrator>();
                    await gateMigrator.MigrateAsync(
                        "20260917030605_AddRefreshTokenFamilies",
                        cancellationToken);

                    var gateAccountId = Guid.NewGuid();
                    var gateCredentialId = Guid.NewGuid();
                    var gateAppRegistrationId = Guid.NewGuid();
                    var gateCreatedAt = DateTimeOffset.UtcNow.AddHours(-2);
                    gateContext.Accounts.Add(new AccountEntity
                    {
                        Id = gateAccountId, IsActive = true, CreatedAt = gateCreatedAt
                    });
                    gateContext.PasswordCredentials.Add(new PasswordCredentialEntity
                    {
                        Id = gateCredentialId,
                        AccountId = gateAccountId,
                        Username = "family_gate_admin",
                        PasswordHash = "hash",
                        CreatedAt = gateCreatedAt
                    });
                    gateContext.AppRegistrations.Add(new AppRegistrationEntity
                    {
                        Id = gateAppRegistrationId,
                        AppId = appId,
                        AppSecretHash = "hash",
                        AppName = "Family Gate",
                        IsActive = true,
                        CreatedAt = gateCreatedAt
                    });
                    var gateSession = CreateIdentitySession(gateAccountId, gateCredentialId);
                    gateContext.IdentitySessions.Add(gateSession);
                    await gateContext.SaveChangesAsync(cancellationToken);

                    var gateRootId = Guid.NewGuid();
                    var gateNow = DateTimeOffset.UtcNow;
                    await RefreshTokenFamilyTestSupport.InsertInteractiveMemberPostgreSqlAsync(
                        gateContext, gateRootId, gateAccountId, appId, gateRootId, parentId: null,
                        gateSession.Id, canonicalScope, gateNow.AddMinutes(-5), gateNow,
                        gateNow.AddHours(1), consumedAt: gateNow);
                    // The legacy-root row is inserted in its family-era shape directly: at this
                    // staging point family_id is already NOT NULL, and the row the backfill
                    // would have produced is exactly this singleton root.
                    var gateLegacyId = Guid.NewGuid();
                    await gateContext.Database.ExecuteSqlInterpolatedAsync($"""
                        INSERT INTO refresh_tokens
                            (id, account_id, token_value, created_at, expires_at, is_revoked, app_id,
                             family_id, parent_id, identity_session_id, scope, auth_time, consumed_at)
                        VALUES
                            ({gateLegacyId}, {gateAccountId},
                             {RefreshTokenDigest.Compute("family-gate-legacy")},
                             {gateCreatedAt}, {gateNow.AddHours(1)}, FALSE, {appId},
                             {gateLegacyId}, NULL, NULL, NULL, NULL, NULL);
                        """, cancellationToken);
                    gateContext.ChangeTracker.Clear();
                    var gateColumnsWithFamily = await GetPostgreSqlColumnsAsync(
                        gateContext, "refresh_tokens");

                    // Gate state 1: interactive rows exist — the family gate refuses, value-free.
                    var blocked = await Record.ExceptionAsync(() =>
                        gateMigrator.MigrateAsync(codeMigration, cancellationToken));
                    Assert.NotNull(blocked);
                    var blockedText = blocked!.ToString();
                    Assert.Contains(
                        "refresh family downgrade blocked", blockedText, StringComparison.Ordinal);
                    Assert.DoesNotContain(
                        RefreshTokenFamilyTestSupport.DigestFor(gateRootId),
                        blockedText,
                        StringComparison.Ordinal);
                    Assert.True(gateColumnsWithFamily.SetEquals(
                        await GetPostgreSqlColumnsAsync(gateContext, "refresh_tokens")));

                    // Gate state 2: no interactive rows, but a consumed code still links a root.
                    await gateContext.Database.ExecuteSqlInterpolatedAsync(
                        $"DELETE FROM refresh_tokens WHERE identity_session_id = {gateSession.Id}",
                        cancellationToken);
                    gateContext.AuthorizationCodes.Add(new AuthorizationCodeEntity
                    {
                        Id = Guid.NewGuid(),
                        CodeDigest = AuthorizationCodeDigest.Compute("family-gate-code-0123456789abcdefghijk"),
                        AppRegistrationId = gateAppRegistrationId,
                        AccountId = gateAccountId,
                        IdentitySessionId = gateSession.Id,
                        RedirectUri = "https://client.example.test/callback",
                        Scope = canonicalScope,
                        Nonce = "family-gate-nonce",
                        CodeChallenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                        AuthTime = gateNow.AddMinutes(-5),
                        CreatedAt = gateNow,
                        ExpiresAt = gateNow.AddSeconds(IdentityConstants.AuthorizationCodeLifetimeSeconds),
                        ConsumedAt = gateNow,
                        RefreshFamilyId = gateLegacyId
                    });
                    await gateContext.SaveChangesAsync(cancellationToken);
                    gateContext.ChangeTracker.Clear();
                    Assert.NotNull(await Record.ExceptionAsync(() =>
                        gateMigrator.MigrateAsync(codeMigration, cancellationToken)));
                    Assert.True(gateColumnsWithFamily.SetEquals(
                        await GetPostgreSqlColumnsAsync(gateContext, "refresh_tokens")));

                    // Gate cleared: Down succeeds inside the pre-retirement window, the shape
                    // returns to AddAuthorizationCodes, and the surviving legacy rows are
                    // untouched; Up restores the singleton roots.
                    await gateContext.Database.ExecuteSqlRawAsync(
                        "DELETE FROM authorization_codes WHERE refresh_family_id IS NOT NULL",
                        cancellationToken);
                    var gateLegacyBefore = await DumpPostgreSqlAsync(
                        gateContext, FamilyLegacyTokenDumpSql);
                    await gateMigrator.MigrateAsync(codeMigration, cancellationToken);
                    var gateColumnsAfterDown = await GetPostgreSqlColumnsAsync(
                        gateContext, "refresh_tokens");
                    Assert.DoesNotContain("family_id", gateColumnsAfterDown);
                    Assert.DoesNotContain("parent_id", gateColumnsAfterDown);
                    Assert.DoesNotContain("identity_session_id", gateColumnsAfterDown);
                    Assert.DoesNotContain("scope", gateColumnsAfterDown);
                    Assert.DoesNotContain("auth_time", gateColumnsAfterDown);
                    Assert.DoesNotContain("consumed_at", gateColumnsAfterDown);
                    var gateForeignKeysAfterDown = await GetPostgreSqlForeignKeysAsync(
                        gateContext, "authorization_codes");
                    Assert.Equal(3, gateForeignKeysAfterDown.Count);
                    Assert.Equal(
                        gateLegacyBefore,
                        await DumpPostgreSqlAsync(gateContext, FamilyLegacyTokenDumpSql));

                    await gateMigrator.MigrateAsync(cancellationToken: cancellationToken);
                    Assert.Equal(
                        gateLegacyBefore,
                        await DumpPostgreSqlAsync(gateContext, FamilyLegacyTokenDumpSql));
                    var familyAfterRoundTrip = await DumpPostgreSqlAsync(gateContext, """
                        SELECT id, family_id, parent_id, identity_session_id, scope, auth_time, consumed_at
                        FROM refresh_tokens ORDER BY id
                        """);
                    foreach (var line in familyAfterRoundTrip.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.TrimEnd('\r')))
                    {
                        var fields = line.Split('|');
                        Assert.Equal(fields[0], fields[1]);
                        Assert.Equal("NULL", fields[2]);
                        Assert.Equal("NULL", fields[3]);
                    }
                }
            }
        }
    }

    /// <summary>
    /// The comparable projection of every legacy refresh-token column, ordered so the upgrade,
    /// the downgrade gate, and the round trip can compare dumps byte for byte.
    /// </summary>
    private const string FamilyLegacyTokenDumpSql = """
        SELECT id, account_id, token_value, created_at, expires_at, is_revoked, app_id,
               coalesce(ldap_credential_id::text, ''), coalesce(sms_user_login_id::text, ''),
               coalesce(wechat_user_login_id::text, ''), coalesce(source_app_id, '')
        FROM refresh_tokens
        ORDER BY id
        """;

    private const string FamilyCodeDumpSql = """
        SELECT id, code_digest, app_registration_id, account_id, identity_session_id,
               redirect_uri, scope, nonce, code_challenge, auth_time, created_at, expires_at,
               consumed_at
        FROM authorization_codes
        ORDER BY id
        """;

    private static async Task<string> DumpPostgreSqlAsync(IdentityDbContext context, string sql)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = sql;
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        var dump = new System.Text.StringBuilder();
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

    private static Task<int> InsertFamilyRowPostgreSqlAsync(
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
        return context.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO refresh_tokens
                (id, account_id, token_value, created_at, expires_at, is_revoked, app_id,
                 family_id, parent_id, identity_session_id, scope, auth_time, consumed_at)
            VALUES
                ({id}, {accountId}, {tokenDigest}, {created}, {expires}, FALSE, {appId},
                 {familyId}, {parentId}, {sessionId}, {scope}, {authTime}, {consumedAt});
            """, TestContext.Current.CancellationToken);
    }

    private static Task InsertLegacyRootPostgreSqlAsync(
        IdentityDbContext context,
        Guid tokenId,
        Guid accountId,
        string appId,
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
            AppId = appId
        });
        return context.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    private static async Task AssertDeleteRejectedPostgreSqlAsync(
        IdentityDbContext context, string table, Guid id)
    {
        var exception = await Record.ExceptionAsync(() =>
            table == "identity_sessions"
                ? context.Database.ExecuteSqlInterpolatedAsync(
                    $"DELETE FROM identity_sessions WHERE id = {id}",
                    TestContext.Current.CancellationToken)
                : context.Database.ExecuteSqlInterpolatedAsync(
                    $"DELETE FROM refresh_tokens WHERE id = {id}",
                    TestContext.Current.CancellationToken));
        Assert.IsType<Npgsql.PostgresException>(exception);
    }

    private static async Task<(Guid AccountId, Guid CredentialId, Guid AppId)>
        SeedAuthorizationCodePrerequisitesAsync(DbContextOptions<IdentityDbContext> options)
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
            Id = credentialId, AccountId = accountId, Username = "code-contract-user",
            PasswordHash = "hash", CreatedAt = DateTimeOffset.UtcNow
        });
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = appId, AppId = "code-contract-app", AppSecretHash = "hash",
            AppName = "Code Contract", IsActive = true, CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        return (accountId, credentialId, appId);
    }

    private static async Task<(Guid Id, Guid SessionId)> CreateAuthorizationCodeAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid accountId,
        Guid credentialId,
        Guid appId,
        DateTimeOffset authTime)
    {
        await using var context = new IdentityDbContext(options);
        var sessionStore = new IdentitySessionStore(
            new IdentitySessionRepository(context),
            new EfCoreUnitOfWork(context));
        var codeStore = new AuthorizationCodeStore(
            new AuthorizationCodeRepository(context),
            new EfCoreUnitOfWork(context));
        var session = await sessionStore.CreateAsync(
            accountId, credentialId, authTime, TestContext.Current.CancellationToken);
        // The code is created at the current instant: the 60-second lifetime must still cover the
        // redemption that follows immediately.
        var creation = await codeStore.CreateAsync(
            session,
            new AuthorizationCodeBinding(
                appId,
                "https://client.example.com/callback",
                "openid profile",
                "ServerCanaryNonce_0123456789abcdef",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
            DateTimeOffset.UtcNow,
            TestContext.Current.CancellationToken);
        return (creation.Id, session.Id);
    }

    private static async Task<AuthorizationCodeEntity> GetAuthorizationCodeRowAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid codeId)
    {
        await using var context = new IdentityDbContext(options);
        return await context.AuthorizationCodes.AsNoTracking()
            .SingleAsync(code => code.Id == codeId, TestContext.Current.CancellationToken);
    }

    private static async Task<bool> ConsumeAuthorizationCodeAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid codeId)
    {
        await using var context = new IdentityDbContext(options);
        var store = new AuthorizationCodeStore(
            new AuthorizationCodeRepository(context),
            new EfCoreUnitOfWork(context));
        return await store.TryConsumeAsync(
            codeId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
    }

    private sealed record AuthorizationCodeRedemptionOutcome(
        bool ConsumedThisCall,
        AuthorizationCodeState Classification,
        IdentitySessionEntity? Session);

    /// <summary>
    /// Runs the canonical redemption shape on its own connection: lock the session, lock the
    /// code, classify the locked snapshot, and only consume when it is still unconsumed — the
    /// <c>EV-20</c>/<c>EV-21</c> order the token endpoint will use.
    /// </summary>
    private static async Task<AuthorizationCodeRedemptionOutcome> RedeemAuthorizationCodeAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid sessionId,
        Guid codeId,
        DateTimeOffset now)
    {
        await using var context = new IdentityDbContext(options);
        var sessionStore = new IdentitySessionStore(
            new IdentitySessionRepository(context),
            new EfCoreUnitOfWork(context));
        var codeStore = new AuthorizationCodeStore(
            new AuthorizationCodeRepository(context),
            new EfCoreUnitOfWork(context));
        var strategy = context.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async operationToken =>
        {
            await using var transaction = await context.Database
                .BeginTransactionAsync(operationToken);
            var session = await sessionStore.LockAsync(sessionId, operationToken);
            var code = await codeStore.LockAsync(codeId, operationToken);
            var classification = code is null
                ? AuthorizationCodeState.Missing
                : code.ConsumedAt is not null
                    ? AuthorizationCodeState.Consumed
                    : now >= code.ExpiresAt
                        ? AuthorizationCodeState.Expired
                        : AuthorizationCodeState.Unconsumed;
            // The store deliberately never decides session liveness; the redemption caller does
            // (EV-28): a revoked session aborts before the consumption, leaving the code
            // unconsumed.
            var sessionUsable = session is not null && session.RevokedAt is null;
            var consumed = classification == AuthorizationCodeState.Unconsumed
                && sessionUsable
                && await codeStore.TryConsumeAsync(codeId, now, operationToken);
            await transaction.CommitAsync(operationToken);
            return new AuthorizationCodeRedemptionOutcome(consumed, classification, session);
        }, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Throws one PostgreSQL serialization failure (SQLSTATE 40001, transient under the default
    /// <c>EnableRetryOnFailure</c> configuration) on the first authorization-code UPDATE so the
    /// retrying execution strategy replays the whole consumption unit.
    /// </summary>
    private sealed class TransientAuthorizationCodeUpdateFailureInterceptor : DbCommandInterceptor
    {
        private bool _thrown;

        public bool ThrewOnce => _thrown;

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            System.Data.Common.DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfArmed(command);
            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }

        public override ValueTask<InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
            System.Data.Common.DbCommand command,
            CommandEventData eventData,
            InterceptionResult<System.Data.Common.DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfArmed(command);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }

        private void ThrowIfArmed(System.Data.Common.DbCommand command)
        {
            if (_thrown
                || !command.CommandText.StartsWith("UPDATE", StringComparison.OrdinalIgnoreCase)
                || !command.CommandText.Contains(
                    "authorization_codes", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            _thrown = true;
            throw new Npgsql.PostgresException(
                "synthetic serialization failure",
                "ERROR",
                "ERROR",
                "40001");
        }
    }

    /// <summary>
    /// <c>EV-34</c> on the real PostgreSQL matrix: the restrictive <c>authorization_requests</c>
    /// reference makes a referenced application's delete fail as a recognizable foreign-key
    /// violation, and the concurrent insert/delete window resolves by the commit order — the
    /// deleter blocks behind the uncommitted continuation and reports the violation after the
    /// insert commits, while an insert racing an already committed delete fails on its own side.
    /// </summary>
    [Fact]
    public async Task PostgreSqlAppDeletion_RestrictiveReferenceAndTheConcurrentWindow()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL application deletion contract.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            await using (var migration = new IdentityDbContext(options))
            {
                await migration.Database.MigrateAsync(TestContext.Current.CancellationToken);
            }

            var cancellationToken = TestContext.Current.CancellationToken;

            // ---- Scenario 2: a referenced application cannot be deleted; the violation is
            // recognizable and nothing disappears.
            var referencedAppId = Guid.NewGuid();
            await SeedDeletionApplicationAsync(options, referencedAppId);
            await InsertDeletionContinuationAsync(options, referencedAppId, 0);
            var referencedException = await Assert.ThrowsAsync<DbUpdateException>(() =>
                DeleteDeletionApplicationAsync(options, referencedAppId));
            Assert.True(DatabaseConstraintViolation.IsForeignKeyViolation(referencedException));
            await using (var verify = new IdentityDbContext(options))
            {
                Assert.True(await verify.AppRegistrations.AsNoTracking()
                    .AnyAsync(app => app.Id == referencedAppId, cancellationToken));
                Assert.True(await verify.AppRedirectUris.AsNoTracking()
                    .AnyAsync(uri => uri.AppRegistrationId == referencedAppId, cancellationToken));
                Assert.Equal(1, await verify.AuthorizationRequests.AsNoTracking()
                    .CountAsync(row => row.AppRegistrationId == referencedAppId, cancellationToken));
            }

            // ---- Scenario 5a: the continuation insert commits first; the concurrent delete
            // blocks behind it and then reports the foreign-key violation.
            var racingAppId = Guid.NewGuid();
            await SeedDeletionApplicationAsync(options, racingAppId);
            var insertReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var releaseInsert = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var insertTask = Task.Run(async () =>
            {
                await using var context = new IdentityDbContext(options);
                var strategy = context.Database.CreateExecutionStrategy();
                await strategy.ExecuteAsync(async () =>
                {
                    await using var transaction = await context.Database
                        .BeginTransactionAsync(CancellationToken.None);
                    context.AuthorizationRequests.Add(CreateDeletionContinuation(racingAppId, 100));
                    await context.SaveChangesAsync(CancellationToken.None);
                    insertReady.SetResult();
                    await releaseInsert.Task.WaitAsync(TimeSpan.FromSeconds(60), CancellationToken.None);
                    await transaction.CommitAsync(CancellationToken.None);
                });
            }, CancellationToken.None);

            await insertReady.Task.WaitAsync(TimeSpan.FromSeconds(60), cancellationToken);

            var blockedDelete = DeleteDeletionApplicationAsync(options, racingAppId);
            await Assert.ThrowsAsync<TimeoutException>(() =>
                blockedDelete.WaitAsync(TimeSpan.FromMilliseconds(500)));

            releaseInsert.SetResult();
            await insertTask.WaitAsync(TimeSpan.FromSeconds(60), cancellationToken);
            var blockedException = await Assert.ThrowsAsync<DbUpdateException>(() =>
                blockedDelete.WaitAsync(TimeSpan.FromSeconds(60), cancellationToken));
            Assert.True(DatabaseConstraintViolation.IsForeignKeyViolation(blockedException));
            await using (var verify = new IdentityDbContext(options))
            {
                Assert.True(await verify.AppRegistrations.AsNoTracking()
                    .AnyAsync(app => app.Id == racingAppId, cancellationToken));
                Assert.Equal(1, await verify.AuthorizationRequests.AsNoTracking()
                    .CountAsync(row => row.AppRegistrationId == racingAppId, cancellationToken));
            }

            // ---- Scenario 5b: the delete commits first; the racing insert fails on its own side.
            var deletedAppId = Guid.NewGuid();
            await SeedDeletionApplicationAsync(options, deletedAppId);
            await DeleteDeletionApplicationAsync(options, deletedAppId);
            await using (var insertContext = new IdentityDbContext(options))
            {
                insertContext.AuthorizationRequests.Add(CreateDeletionContinuation(deletedAppId, 200));
                var insertException = await Assert.ThrowsAsync<DbUpdateException>(() =>
                    insertContext.SaveChangesAsync(cancellationToken));
                Assert.True(DatabaseConstraintViolation.IsForeignKeyViolation(insertException));
            }
        }
    }

    private static async Task SeedDeletionApplicationAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid appId)
    {
        await using var context = new IdentityDbContext(options);
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = appId,
            AppId = $"deletion-app-{appId:N}",
            AppSecretHash = "hash",
            AppName = "Deletion Contract App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow,
            RedirectUris =
            [
                new AppRedirectUriEntity
                {
                    Id = Guid.NewGuid(),
                    AppRegistrationId = appId,
                    Kind = RedirectUriKind.Redirect,
                    CanonicalUri = "https://bff.deletion.test/callback"
                }
            ]
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    private static AuthorizationRequestEntity CreateDeletionContinuation(Guid appId, int sequence) =>
        new()
        {
            Id = Guid.NewGuid(),
            HandleDigest = LoginHandleDigest.Compute(
                $"deletion-pg-handle-{sequence}-0123456789abcdefgh"),
            AppRegistrationId = appId,
            RedirectUri = "https://bff.deletion.test/callback",
            Scope = "openid",
            State = "deletion-state",
            Nonce = "deletion-nonce",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(
                IdentityConstants.LoginHandleLifetimeMinutes)
        };

    private static async Task InsertDeletionContinuationAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid appId,
        int sequence)
    {
        await using var context = new IdentityDbContext(options);
        context.AuthorizationRequests.Add(CreateDeletionContinuation(appId, sequence));
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    private static async Task DeleteDeletionApplicationAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid appId)
    {
        await using var context = new IdentityDbContext(options);
        var app = await context.AppRegistrations
            .SingleAsync(app => app.Id == appId, TestContext.Current.CancellationToken);
        context.AppRegistrations.Remove(app);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// The #269 column-type contract: after migrating to the latest version, every mapped column's
    /// physical <c>format_type</c> equals the model's <c>GetColumnType</c> (with
    /// <c>timestamptz</c>/<c>timestamp with time zone</c> normalized), no real column is missing,
    /// and the mapped set is non-empty — so the snapshot and the physical schema can no longer
    /// disagree.
    /// </summary>
    [Fact]
    public async Task PostgreSqlModelColumnTypes_MatchThePhysicalSchema()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL column type contract.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            await using (var migration = new IdentityDbContext(options))
            {
                await migration.Database.MigrateAsync(TestContext.Current.CancellationToken);
            }

            await using var context = new IdentityDbContext(options);
            await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
            await using var command = context.Database.GetDbConnection().CreateCommand();
            command.CommandText = """
                SELECT table_name, column_name, format_type(atttypid, atttypmod)
                FROM information_schema.columns
                JOIN pg_attribute ON attrelid = to_regclass('public.' || table_name)
                    AND attname = column_name
                WHERE table_schema = 'public'
                ORDER BY table_name, column_name
                """;
            var physical = new Dictionary<string, string>(StringComparer.Ordinal);
            await using (var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken))
            {
                while (await reader.ReadAsync(TestContext.Current.CancellationToken))
                {
                    physical[$"{reader.GetString(0)}.{reader.GetString(1)}"] = reader.GetString(2);
                }
            }

            var mismatches = new List<string>();
            var mapped = 0;
            foreach (var entityType in context.Model.GetEntityTypes())
            {
                var tableName = entityType.GetTableName()!;
                foreach (var property in entityType.GetProperties())
                {
                    var columnName = property.GetColumnName(
                        StoreObjectIdentifier.Table(tableName, entityType.GetSchema()));
                    if (columnName is null)
                    {
                        continue;
                    }

                    mapped++;
                    var key = $"{tableName}.{columnName}";
                    if (!physical.TryGetValue(key, out var physicalType))
                    {
                        mismatches.Add($"{key}: missing in the database");
                        continue;
                    }

                    var modelType = property.GetColumnType()!;
                    if (Normalize(modelType) != Normalize(physicalType))
                    {
                        mismatches.Add($"{key}: model={modelType}, database={physicalType}");
                    }
                }
            }

            Assert.True(mapped > 0, "The comparison must cover a non-empty mapped column set.");
            Assert.Empty(mismatches);

            static string Normalize(string columnType) => columnType switch
            {
                "timestamp with time zone" => "timestamptz",
                _ => columnType
            };
        }
    }

    /// <summary>
    /// The #269 in-place upgrade: from the pre-alignment history with overlong rows already
    /// stored, the alignment migration succeeds, changes no byte, and the empty <c>Down</c> runs
    /// cleanly and also changes neither bytes nor the physical <c>text</c> type.
    /// </summary>
    [Fact]
    public async Task PostgreSqlLegacyTextAlignment_UpgradesInPlaceWithOverlongData()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL text alignment upgrade.");

        const string preAlignmentMigration = "20260916103405_AddIdentitySessions";
        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            await using (var context = new IdentityDbContext(options))
            {
                var migrator = context.GetService<IMigrator>();
                await migrator.MigrateAsync(preAlignmentMigration, TestContext.Current.CancellationToken);

                var userAgent = new string('U', 600) + "-upgrade-tail";
                var description = new string('D', 1500) + "-upgrade-tail";
                var remark = new string('R', 800) + "-upgrade-tail";
                var accountId = Guid.NewGuid();
                await context.Database.ExecuteSqlInterpolatedAsync($"""
                    INSERT INTO accounts (id, is_active, created_at, total_login_count, remark)
                    VALUES ({accountId}, TRUE, {DateTimeOffset.UtcNow}, 0, {remark});

                    INSERT INTO login_histories
                        (id, username, auth_method, event_type, failure_reason, user_agent,
                         app_id, created_at)
                    VALUES
                        ({Guid.NewGuid()}, {"overlong-upgrade-user"}, {"oidc_login"}, {"login_failure"},
                         {"Wrong username or password"}, {userAgent}, {"upgrade-app"},
                         {DateTimeOffset.UtcNow});

                    INSERT INTO audit_logs
                        (id, action, target_type, target_id, description, created_at)
                    VALUES
                        ({Guid.NewGuid()}, {"login.failed"}, {"LoginHistory"}, {"overlong-upgrade-target"},
                         {description}, {DateTimeOffset.UtcNow});
                    """, cancellationToken: TestContext.Current.CancellationToken);

                await migrator.MigrateAsync(cancellationToken: TestContext.Current.CancellationToken);

                var accountRemark = await context.Database.SqlQuery<string>(
                    $"SELECT remark AS \"Value\" FROM accounts WHERE id = {accountId}")
                    .SingleAsync(TestContext.Current.CancellationToken);
                var historyAgent = await context.Database.SqlQuery<string>(
                    $"SELECT user_agent AS \"Value\" FROM login_histories WHERE username = {"overlong-upgrade-user"}")
                    .SingleAsync(TestContext.Current.CancellationToken);
                var auditDescription = await context.Database.SqlQuery<string>(
                    $"SELECT description AS \"Value\" FROM audit_logs WHERE action = {"login.failed"}")
                    .SingleAsync(TestContext.Current.CancellationToken);
                Assert.Equal(remark, accountRemark);
                Assert.Equal(userAgent, historyAgent);
                Assert.Equal(description, auditDescription);

                // The column is physically text before and after: the alignment is a metadata
                // statement about the model, not a schema change.
                await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
                await using (var typeCommand = context.Database.GetDbConnection().CreateCommand())
                {
                    typeCommand.CommandText =
                        "SELECT format_type(atttypid, atttypmod) FROM pg_attribute "
                        + "WHERE attrelid = 'public.accounts'::regclass AND attname = 'remark'";
                    Assert.Equal(
                        "text",
                        (string)(await typeCommand.ExecuteScalarAsync(TestContext.Current.CancellationToken))!);
                }

                // The alignment's empty Down keeps its coverage inside the pre-retirement
                // window: a downgrade walk from the current version is refused by
                // RetireSystemSettings before it could ever reach this migration, so the round
                // trip runs on a fresh database staged at the alignment migration.
                var refusal = await Assert.ThrowsAsync<NotSupportedException>(
                    () => migrator.MigrateAsync(
                        preAlignmentMigration,
                        TestContext.Current.CancellationToken));
                Assert.Contains("irreversible", refusal.Message, StringComparison.Ordinal);
                Assert.Equal(
                    remark,
                    await context.Database.SqlQuery<string>(
                        $"SELECT remark AS \"Value\" FROM accounts WHERE id = {accountId}")
                        .SingleAsync(TestContext.Current.CancellationToken));

                await using (var alignment = new PostgreSqlBuilder(PostgreSqlImage)
                    .WithDatabase("identity")
                    .WithUsername("postgres")
                    .WithPassword("postgres")
                    .Build())
                {
                    await alignment.StartAsync(TestContext.Current.CancellationToken);
                    var alignmentOptions = CreateDatabaseOptions(
                        "PostgreSQL",
                        alignment.GetConnectionString());
                    var alignmentBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
                    alignmentBuilder.UseIdentityDatabase(alignmentOptions);
                    var alignmentContextOptions = alignmentBuilder.Options;
                    await WaitUntilConnectableAsync(alignmentContextOptions);
                    await using var alignmentContext = new IdentityDbContext(alignmentContextOptions);
                    var alignmentMigrator = alignmentContext.GetService<IMigrator>();
                    await alignmentMigrator.MigrateAsync(
                        "20260917154330_AlignPostgreSqlLegacyTextColumns",
                        TestContext.Current.CancellationToken);
                    var alignmentRemark = new string('A', 900) + "-alignment-tail";
                    var alignmentAccountId = Guid.NewGuid();
                    await alignmentContext.Database.ExecuteSqlInterpolatedAsync($"""
                        INSERT INTO accounts (id, is_active, created_at, total_login_count, remark)
                        VALUES ({alignmentAccountId}, TRUE, {DateTimeOffset.UtcNow}, 0, {alignmentRemark});
                        """, TestContext.Current.CancellationToken);

                    // The empty Down runs cleanly and changes neither bytes nor types.
                    await alignmentMigrator.MigrateAsync(
                        preAlignmentMigration, TestContext.Current.CancellationToken);
                    await alignmentMigrator.MigrateAsync(
                        cancellationToken: TestContext.Current.CancellationToken);
                    Assert.Equal(
                        alignmentRemark,
                        await alignmentContext.Database.SqlQuery<string>(
                                $"SELECT remark AS \"Value\" FROM accounts WHERE id = {alignmentAccountId}")
                            .SingleAsync(TestContext.Current.CancellationToken));
                }
            }
        }
    }

    /// <summary>
    /// The PostgreSQL half of the #269 overlong-input regression: six failed logins carrying a
    /// 600-character User-Agent commit their shared failure unit — the counter climbs to its
    /// threshold with the lockout written, and every history row keeps the complete value.
    /// </summary>
    [Fact]
    public async Task PostgreSqlLoginFailureUnit_WithAnOverlongUserAgent_CommitsFully()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL overlong user-agent regression.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .Build();

        await using (container)
        {
            await container.StartAsync(TestContext.Current.CancellationToken);
            var databaseOptions = CreateDatabaseOptions(
                "PostgreSQL",
                container.GetConnectionString());
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);
            var options = optionsBuilder.Options;
            await WaitUntilConnectableAsync(options);

            await using (var migration = new IdentityDbContext(options))
            {
                await migration.Database.MigrateAsync(TestContext.Current.CancellationToken);
            }

            await using var context = new IdentityDbContext(options);
            var recorder = new SignaCore.Host.Services.OidcLoginFailureRecorder(
                new LoginAttemptRepository(context),
                new AuditService(
                    new LoginHistoryRepository(context),
                    new AuditLogRepository(context)),
                new EfCoreUnitOfWork(context),
                context,
                NullLogger<SignaCore.Host.Services.OidcLoginFailureRecorder>.Instance);
            var userAgent = new string('U', 600) + "-pg-tail";

            for (var attempt = 0; attempt < 6; attempt++)
            {
                await recorder.RecordFailureAsync(
                    new LoginAttemptChange(LoginAttemptChangeKind.RecordFailure, "overlong-ua-pg-user"),
                    "overlong-ua-pg-user",
                    "Wrong username or password",
                    "overlong-ua-app",
                    clientIp: "203.0.113.9",
                    userAgent: userAgent,
                    correlationId: "overlong-ua-correlation",
                    cancellationToken: TestContext.Current.CancellationToken);
            }

            // The recorder path has no validator gate, so all six failures count; the lockout was
            // written when the fifth failure reached the threshold.
            var attemptRow = await context.LoginAttempts.AsNoTracking()
                .SingleAsync(
                    row => row.UsernameNormalized == "OVERLONG-UA-PG-USER",
                    TestContext.Current.CancellationToken);
            Assert.Equal(6, attemptRow.FailedAttempts);
            Assert.NotNull(attemptRow.LockoutUntil);

            var histories = await context.LoginHistories.AsNoTracking()
                .Where(row => row.Username == "overlong-ua-pg-user")
                .ToListAsync(TestContext.Current.CancellationToken);
            Assert.Equal(6, histories.Count);
            Assert.All(histories, row => Assert.Equal(userAgent, row.UserAgent));
        }
    }

    private static IdentitySessionEntity CreateIdentitySession(
        Guid accountId,
        Guid credentialId,
        Action<IdentitySessionEntity>? mutate = null)
    {
        var now = DateTimeOffset.UtcNow;
        var session = new IdentitySessionEntity
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
        mutate?.Invoke(session);
        return session;
    }

    private static async Task<(Guid AccountId, Guid CredentialId)> SeedSessionAccountAsync(
        DbContextOptions<IdentityDbContext> options)
    {
        await using var context = new IdentityDbContext(options);
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity
        {
            Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow
        });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = credentialId, AccountId = accountId, Username = "session-contract-user",
            PasswordHash = "hash", CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        return (accountId, credentialId);
    }

    private static async Task<Guid> CreateSessionAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid accountId,
        Guid credentialId,
        DateTimeOffset authTime)
    {
        await using var context = new IdentityDbContext(options);
        var store = new IdentitySessionStore(
            new IdentitySessionRepository(context),
            new EfCoreUnitOfWork(context));
        var session = await store.CreateAsync(
            accountId, credentialId, authTime, TestContext.Current.CancellationToken);
        return session.Id;
    }

    private static async Task<Guid> InsertSessionAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid accountId,
        Guid credentialId,
        Action<IdentitySessionEntity>? mutate = null)
    {
        var session = CreateIdentitySession(accountId, credentialId, mutate);
        await using var context = new IdentityDbContext(options);
        context.IdentitySessions.Add(session);
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        return session.Id;
    }

    private static async Task<IdentitySessionEntity> GetSessionRowAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid sessionId)
    {
        await using var context = new IdentityDbContext(options);
        return await context.IdentitySessions.AsNoTracking()
            .SingleAsync(row => row.Id == sessionId, TestContext.Current.CancellationToken);
    }

    private static async Task<IdentitySessionActivityResult> TouchSessionAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid sessionId,
        DateTimeOffset now)
    {
        await using var context = new IdentityDbContext(options);
        var store = new IdentitySessionStore(
            new IdentitySessionRepository(context),
            new EfCoreUnitOfWork(context));
        return await store.TouchActivityAsync(sessionId, now, TestContext.Current.CancellationToken);
    }

    private static async Task<IdentitySessionRevocationResult> RevokeSessionAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid sessionId,
        IdentitySessionRevocationReason reason,
        DateTimeOffset now)
    {
        await using var context = new IdentityDbContext(options);
        var store = new IdentitySessionStore(
            new IdentitySessionRepository(context),
            new EfCoreUnitOfWork(context));
        return await store.RevokeAsync(sessionId, reason, now, TestContext.Current.CancellationToken);
    }

    private static async Task<IdentitySessionEntity?> LockSessionInTransactionAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid sessionId)
    {
        await using var context = new IdentityDbContext(options);
        var store = new IdentitySessionStore(
            new IdentitySessionRepository(context),
            new EfCoreUnitOfWork(context));
        var strategy = context.Database.CreateExecutionStrategy();
        return await strategy.ExecuteAsync(async operationToken =>
        {
            await using var transaction = await context.Database.BeginTransactionAsync(operationToken);
            var locked = await store.LockAsync(sessionId, operationToken);
            await transaction.CommitAsync(operationToken);
            return locked;
        }, TestContext.Current.CancellationToken);
    }

    private static async Task<HashSet<string>> GetPostgreSqlCheckConstraintsAsync(
        IdentityDbContext context,
        string tableName)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT con.conname FROM pg_constraint con WHERE con.conrelid = to_regclass('public.' || @name) AND con.contype = 'c'";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "name";
        parameter.Value = tableName;
        command.Parameters.Add(parameter);
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        var names = new HashSet<string>(StringComparer.Ordinal);
        while (await reader.ReadAsync(TestContext.Current.CancellationToken))
        {
            names.Add(reader.GetString(0));
        }

        return names;
    }

    /// <summary>
    /// Throws one PostgreSQL serialization failure (SQLSTATE 40001, transient under the default
    /// <c>EnableRetryOnFailure</c> configuration) on the first identity-session UPDATE so the
    /// retrying execution strategy replays the whole revocation unit.
    /// </summary>
    private sealed class TransientSessionUpdateFailureInterceptor : DbCommandInterceptor
    {
        private bool _thrown;

        public bool ThrewOnce => _thrown;

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
            System.Data.Common.DbCommand command,
            CommandEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfArmed(command);
            return base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
        }

        public override ValueTask<InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
            System.Data.Common.DbCommand command,
            CommandEventData eventData,
            InterceptionResult<System.Data.Common.DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            ThrowIfArmed(command);
            return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
        }

        private void ThrowIfArmed(System.Data.Common.DbCommand command)
        {
            // Npgsql renders runtime DML with unquoted lowercase identifiers, so the match is on
            // the statement shape rather than on a quoted fragment.
            if (_thrown
                || !command.CommandText.StartsWith("UPDATE", StringComparison.OrdinalIgnoreCase)
                || !command.CommandText.Contains(
                    "identity_sessions", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            _thrown = true;
            throw new Npgsql.PostgresException(
                "synthetic serialization failure",
                "ERROR",
                "ERROR",
                "40001");
        }
    }

    private static async Task<bool> ConsumeContinuationAsync(
        DbContextOptions<IdentityDbContext> options,
        string handle)
    {
        await using var context = new IdentityDbContext(options);
        var store = new AuthorizationRequestStore(
            new AuthorizationRequestRepository(context),
            new EfCoreUnitOfWork(context));
        return await store.TryConsumeAsync(
            handle, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);
    }

    private static async Task AssertSeedUnchangedAsync(
        IdentityDbContext context,
        Guid accountId,
        Guid appId,
        Guid tokenId,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        string tokenDigest)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var account = await context.Accounts.AsNoTracking()
            .SingleAsync(item => item.Id == accountId, cancellationToken);
        Assert.True(account.IsActive);
        Assert.Equal(createdAt.UtcTicks / 10, account.CreatedAt.UtcTicks / 10);

        var application = await context.AppRegistrations.AsNoTracking()
            .SingleAsync(item => item.Id == appId, cancellationToken);
        Assert.Equal("continuation-upgrade-app", application.AppId);
        Assert.Equal("CONTINUATION-UPGRADE-APP", application.AppIdNormalized);
        Assert.Equal("hash", application.AppSecretHash);
        Assert.True(application.IsActive);
        Assert.Equal(createdAt.UtcTicks / 10, application.CreatedAt.UtcTicks / 10);

        // The Down state predates the family columns, so the token row is read with raw SQL
        // instead of the current EF model.
        var token = await RefreshTokenFamilyTestSupport.ReadRefreshTokenRowPostgreSqlAsync(
            context, tokenId);
        Assert.Equal(tokenDigest, token.TokenValue);
        Assert.False(token.IsRevoked);
        Assert.Equal(createdAt.UtcTicks / 10, token.CreatedAt.UtcTicks / 10);
        Assert.Equal(expiresAt.UtcTicks / 10, token.ExpiresAt.UtcTicks / 10);
        Assert.Null(token.SourceAppId);
    }

    private static IContainer CreateContainer(string provider)
    {
        return provider switch
        {
            "PostgreSQL" => new PostgreSqlBuilder(PostgreSqlImage)
                .WithDatabase("identity")
                .WithUsername("postgres")
                .WithPassword("postgres")
                .Build(),
            _ => throw new InvalidOperationException($"Unsupported provider: {provider}")
        };
    }

    /// <summary>
    /// Retry the real provider connection until it succeeds or the deadline is
    /// reached. A listening port can precede database readiness, so this closes
    /// that gap and preserves the last connection error for diagnostics.
    /// </summary>
    private async Task WaitUntilConnectableAsync(DbContextOptions<IdentityDbContext> options)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(120);
        Exception? lastError = null;

        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                await using var context = new IdentityDbContext(options);
                if (await context.Database.CanConnectAsync())
                {
                    return;
                }
            }
            catch (Exception exception)
            {
                lastError = exception;
            }

            await Task.Delay(TimeSpan.FromSeconds(1));
        }

        throw new InvalidOperationException(
            $"Database did not become connectable within 120s. Last error: {lastError?.Message ?? "CanConnectAsync kept returning false"}",
            lastError);
    }

    private static string GetConnectionString(IContainer container)
    {
        return container switch
        {
            PostgreSqlContainer postgreSql => postgreSql.GetConnectionString(),
            _ => throw new InvalidOperationException("Unsupported test container.")
        };
    }

    private static DatabaseOptions CreateDatabaseOptions(
        string provider,
        string connectionString)
    {
        return new DatabaseOptions
        {
            Provider = provider,
            ServerVersion = provider switch
            {
                "PostgreSQL" => "15",
                _ => throw new InvalidOperationException(
                    $"Unsupported provider: {provider}")
            },
            ConnectionString = connectionString
        };
    }

    private static async Task RunContractAsync(
        DbContextOptions<IdentityDbContext> options)
    {
        var accountId = Guid.NewGuid();
        var appRegistrationId = Guid.NewGuid();

        // Express one instant in UTC+8 and convert it to UTC before writing, to verify that the
        // same instant lands as the same UTC value with microsecond precision intact, whichever
        // offset it was expressed in.
        //
        // ToUniversalTime() has to be explicit here; a value with a non-zero offset must not be
        // written directly. Npgsql accepts only Offset=0 for timestamp with time zone and throws
        // ArgumentException ("only offset 0 (UTC) is supported") for anything else.
        // Product code uses DateTimeOffset.UtcNow throughout, so this matches how the product
        // writes.
        var sourceInstant = new DateTimeOffset(
            2026,
            7,
            30,
            12,
            34,
            56,
            TimeSpan.FromHours(8)).AddTicks(1234560).ToUniversalTime();
        const string token = "CaseSensitiveRefreshToken";
        const string phone = "13800138000";
        const string otpCode = "123456";

        await using (var seedContext = new IdentityDbContext(options))
        {
            await seedContext.Database.MigrateAsync();
            seedContext.AppRegistrations.Add(new AppRegistrationEntity
            {
                Id = appRegistrationId,
                AppId = "database-contract-app",
                AppSecretHash = "hash",
                AppName = "Database Contract",
                IsActive = true,
                CreatedAt = sourceInstant
            });
            seedContext.Accounts.Add(new AccountEntity
            {
                Id = accountId,
                IsActive = true,
                CreatedAt = sourceInstant
            });
            seedContext.PasswordCredentials.Add(new PasswordCredentialEntity
            {
                Id = Guid.NewGuid(),
                AccountId = accountId,
                Username = "Cafe\u0301",
                PasswordHash = "hash",
                CreatedAt = sourceInstant
            });
            var seededTokenId = Guid.NewGuid();
            seedContext.RefreshTokens.Add(new RefreshTokenEntity
            {
                Id = seededTokenId,
                // PS-07: a directly seeded legacy row is the singleton root of its own family.
                FamilyId = seededTokenId,
                AccountId = accountId,
                TokenValue = RefreshTokenDigest.Compute(token),
                CreatedAt = sourceInstant,
                ExpiresAt = sourceInstant.AddHours(1),
                AppId = "database-contract-app"
            });
            seedContext.Otps.Add(new OtpEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = appRegistrationId,
                Phone = phone,
                CodeMac = otpCode,
                Status = OtpStatus.Sent,
                Provider = "Test",
                ProfileKey = "test",
                HourWindowStartedAt = DateTimeOffset.UtcNow,
                DayWindowStartedAt = DateTimeOffset.UtcNow,
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
                LockoutUntil = DateTimeOffset.UnixEpoch
            });
            await seedContext.SaveChangesAsync();
        }

        await using (var queryContext = new IdentityDbContext(options))
        {
            var credentialRepository =
                new PasswordCredentialRepository(queryContext);
            // What was written is the decomposed form "Cafe" plus a combining acute accent; the
            // query uses the precomposed upper-case form "CAF\u00C9", verifying that
            // IdentityValueNormalizer's FormC plus ToUpperInvariant behaves the same on every
            // provider.
            //
            // The \u00C9 escape is deliberate rather than the character written literally: that
            // literal was once decoded as GBK by mistake and stored back as UTF-8, turning
            // \u00C9 (C3 89) into a CJK character (U+8121), so the query looked for a value that
            // had never been written and the test failed for a long time. Every non-ASCII literal
            // uses an escape to avoid repeating that.
            var credential =
                await credentialRepository.GetByUsernameAsync("CAF\u00C9");
            Assert.NotNull(credential);

            var account = await queryContext.Accounts
                .AsNoTracking()
                .SingleAsync(item => item.Id == accountId);
            Assert.Equal(TimeSpan.Zero, account.CreatedAt.Offset);
            Assert.Equal(sourceInstant.UtcTicks / 10, account.CreatedAt.UtcTicks / 10);
        }

        await VerifyInteractiveOidcFreshDatabaseContractAsync(options);

        await VerifyOtpAuditTransactionRollbackAsync(
            options,
            appRegistrationId,
            phone,
            otpCode);

        var rotateResults = await Task.WhenAll(
            TryRotateAsync(options, token, accountId),
            TryRotateAsync(options, token, accountId));
        Assert.Equal(1, rotateResults.Count(result => result));

        await using (var assertionContext = new IdentityDbContext(options))
        {
            Assert.Single(await assertionContext.RefreshTokens
                .Where(refreshToken => !refreshToken.IsRevoked)
                .ToListAsync());
        }

        var consumeResults = await Task.WhenAll(
            TryConsumeOtpAsync(options, appRegistrationId, phone, otpCode),
            TryConsumeOtpAsync(options, appRegistrationId, phone, otpCode));
        Assert.Equal(1, consumeResults.Count(result => result));
    }

    private static async Task<bool> TryRotateAsync(
        DbContextOptions<IdentityDbContext> options,
        string token,
        Guid accountId)
    {
        await using var context = new IdentityDbContext(options);
        var repository = new RefreshTokenRepository(context);
        return await repository.TryRotateAsync(token, new RefreshTokenEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            TokenValue = Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            AppId = "database-contract-app"
        });
    }

    private static async Task VerifyInteractiveOidcFreshDatabaseContractAsync(
        DbContextOptions<IdentityDbContext> options)
    {
        var appId = Guid.NewGuid();
        const string canonicalUri = "https://example.com/callback?tenant=one";

        await using var context = new IdentityDbContext(options);
        await InsertLegacyApplicationAsync(context, appId, callbackUrl: null);

        var application = await context.AppRegistrations
            .AsNoTracking()
            .SingleAsync(app => app.Id == appId);
        Assert.Equal(OidcClientType.Confidential, application.ClientType);
        Assert.False(application.AllowAuthorizationCode);
        Assert.Equal("openid", application.AllowedScopes);
        Assert.False(application.AllowRefreshToken);
        Assert.Null(application.IdentitySessionMaxAgeSeconds);

        context.AppRedirectUris.Add(new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = appId,
            Kind = RedirectUriKind.Redirect,
            CanonicalUri = canonicalUri
        });
        await context.SaveChangesAsync();

        context.AppRedirectUris.Add(new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = appId,
            Kind = RedirectUriKind.Redirect,
            CanonicalUri = canonicalUri
        });
        await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync());
        context.ChangeTracker.Clear();

        context.AppRedirectUris.Add(new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = appId,
            Kind = RedirectUriKind.PostLogout,
            CanonicalUri = canonicalUri
        });
        await context.SaveChangesAsync();

        var boundaryInput = "https://example.com?" + new string('a', 480);
        Assert.Equal(500, boundaryInput.Length);
        var boundaryCanonicalUri = OidcRedirectUriValidator.ValidateAndCanonicalize(
            boundaryInput,
            isDevelopment: false).Value;
        Assert.Equal(501, boundaryCanonicalUri.Length);
        context.AppRedirectUris.Add(new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = appId,
            Kind = RedirectUriKind.Redirect,
            CanonicalUri = boundaryCanonicalUri
        });
        await context.SaveChangesAsync();
        Assert.Equal(
            boundaryCanonicalUri,
            await context.AppRedirectUris
                .AsNoTracking()
                .Where(uri => uri.CanonicalUri == boundaryCanonicalUri)
                .Select(uri => uri.CanonicalUri)
                .SingleAsync());

        var repository = new AppRegistrationRepository(context);
        var withOidcConfiguration = await repository.GetByAppIdWithOidcConfigurationAsync(
            "OIDC-MIGRATION-APP",
            TestContext.Current.CancellationToken);
        Assert.NotNull(withOidcConfiguration);
        Assert.Equal(3, withOidcConfiguration.RedirectUris.Count);

        context.AppRegistrations.Remove(withOidcConfiguration);
        await context.SaveChangesAsync();
        Assert.Empty(await context.AppRedirectUris.AsNoTracking().ToListAsync());

        context.AppRedirectUris.Add(new AppRedirectUriEntity
        {
            Id = Guid.NewGuid(),
            AppRegistrationId = Guid.NewGuid(),
            Kind = RedirectUriKind.Redirect,
            CanonicalUri = "https://example.com/orphan"
        });
        await Assert.ThrowsAsync<DbUpdateException>(() => context.SaveChangesAsync());
    }

    private static Task<int> InsertLegacyApplicationAsync(
        IdentityDbContext context,
        Guid id,
        string? callbackUrl)
    {
        return context.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO app_registrations
                (id, app_id, app_id_normalized, app_secret_hash, app_name, callback_url,
                 is_active, created_at, ldap_login_mode, sms_login_mode, sms_profile_key,
                 wechat_login_mode, audience_mode)
            VALUES
                ({id}, {"oidc-migration-app"}, {"OIDC-MIGRATION-APP"}, {"hash"},
                 {"OIDC Migration"}, {callbackUrl}, {true}, {DateTimeOffset.UtcNow},
                 {(int)LdapLoginMode.ManualApproval}, {(int)SmsLoginMode.AutoProvision}, {"legacy-profile"},
                 {(int)WechatLoginMode.BindRequired}, {(int)AudienceMode.Shared});
            """, cancellationToken: TestContext.Current.CancellationToken);
    }

    private static async Task<bool> PostgreSqlTableExistsAsync(
        IdentityDbContext context,
        string tableName)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = @name";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "name";
        parameter.Value = tableName;
        command.Parameters.Add(parameter);
        return Convert.ToInt64(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken)) > 0;
    }

    private static async Task<HashSet<string>> GetPostgreSqlColumnsAsync(
        IdentityDbContext context,
        string tableName)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = @name";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "name";
        parameter.Value = tableName;
        command.Parameters.Add(parameter);
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        var columns = new HashSet<string>(StringComparer.Ordinal);
        while (await reader.ReadAsync(TestContext.Current.CancellationToken))
        {
            columns.Add(reader.GetString(0));
        }

        return columns;
    }

    private static async Task<Dictionary<string, (string IsNullable, int? MaxLength)>>
        GetPostgreSqlColumnDetailsAsync(
            IdentityDbContext context,
            string tableName)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT column_name, is_nullable, character_maximum_length FROM information_schema.columns WHERE table_schema = 'public' AND table_name = @name ORDER BY column_name";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "name";
        parameter.Value = tableName;
        command.Parameters.Add(parameter);
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        var details = new Dictionary<string, (string IsNullable, int? MaxLength)>(StringComparer.Ordinal);
        while (await reader.ReadAsync(TestContext.Current.CancellationToken))
        {
            details[reader.GetString(0)] = (
                reader.GetString(1),
                reader.IsDBNull(2) ? null : Convert.ToInt32(reader.GetValue(2)));
        }

        return details;
    }

    private static async Task<List<string>> GetPostgreSqlIndexDefinitionsAsync(
        IdentityDbContext context,
        string tableName)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND tablename = @name";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "name";
        parameter.Value = tableName;
        command.Parameters.Add(parameter);
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        var definitions = new List<string>();
        while (await reader.ReadAsync(TestContext.Current.CancellationToken))
        {
            definitions.Add(reader.GetString(0));
        }

        return definitions;
    }

    private static async Task<List<(char DeleteAction, string ReferencedTable)>>
        GetPostgreSqlForeignKeysAsync(
            IdentityDbContext context,
            string tableName)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT con.confdeltype, con.confrelid::regclass::text FROM pg_constraint con WHERE con.conrelid = to_regclass('public.' || @name) AND con.contype = 'f'";
        var parameter = command.CreateParameter();
        parameter.ParameterName = "name";
        parameter.Value = tableName;
        command.Parameters.Add(parameter);
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        var foreignKeys = new List<(char DeleteAction, string ReferencedTable)>();
        while (await reader.ReadAsync(TestContext.Current.CancellationToken))
        {
            foreignKeys.Add((
                Convert.ToChar(reader.GetValue(0)),
                reader.GetString(1)));
        }

        return foreignKeys;
    }

    private static async Task<bool> TryConsumeOtpAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid appRegistrationId,
        string phone,
        string code)
    {
        await using var context = new IdentityDbContext(options);
        var repository = new OtpRepository(context);
        return await repository.TryConsumeAsync(
            appRegistrationId,
            phone,
            code,
            DateTimeOffset.UtcNow,
            maxAttempts: 5);
    }

    private static async Task VerifyOtpAuditTransactionRollbackAsync(
        DbContextOptions<IdentityDbContext> options,
        Guid appRegistrationId,
        string phone,
        string codeMac)
    {
        var observedAt = DateTimeOffset.UtcNow;
        await using (var consumeContext = new IdentityDbContext(options))
        {
            var strategy = consumeContext.Database.CreateExecutionStrategy();
            await strategy.ExecuteAsync(async () =>
            {
                await using var transaction = await consumeContext.Database.BeginTransactionAsync(
                    TestContext.Current.CancellationToken);
                Assert.True(await new OtpRepository(consumeContext).TryConsumeAsync(
                    appRegistrationId,
                    phone,
                    codeMac,
                    observedAt,
                    maxAttempts: 5,
                    TestContext.Current.CancellationToken));
                consumeContext.LoginHistories.Add(CreateOtpLoginHistory("login_success"));
                await consumeContext.SaveChangesAsync(TestContext.Current.CancellationToken);
                await transaction.RollbackAsync(TestContext.Current.CancellationToken);
            });
        }

        await AssertOtpAndAuditStateAsync(OtpStatus.Sent, 0, DateTimeOffset.UnixEpoch);

        var lockoutUntil = observedAt.AddMinutes(5);
        await using (var failureContext = new IdentityDbContext(options))
        {
            var strategy = failureContext.Database.CreateExecutionStrategy();
            await strategy.ExecuteAsync(async () =>
            {
                await using var transaction = await failureContext.Database.BeginTransactionAsync(
                    TestContext.Current.CancellationToken);
                Assert.Equal(1, await new OtpRepository(failureContext).IncrementFailedAttemptsAsync(
                    appRegistrationId,
                    phone,
                    codeMac,
                    observedAt,
                    maxAttempts: 1,
                    lockoutUntil,
                    TestContext.Current.CancellationToken));
                failureContext.LoginHistories.Add(CreateOtpLoginHistory("login_failure"));
                await failureContext.SaveChangesAsync(TestContext.Current.CancellationToken);
                await transaction.RollbackAsync(TestContext.Current.CancellationToken);
            });
        }

        await AssertOtpAndAuditStateAsync(OtpStatus.Sent, 0, DateTimeOffset.UnixEpoch);
        return;

        LoginHistoryEntity CreateOtpLoginHistory(string eventType) => new()
        {
            Id = Guid.NewGuid(),
            Username = "database-contract-sms-user",
            AuthMethod = "sms",
            EventType = eventType,
            AppId = "database-contract-app",
            CreatedAt = DateTimeOffset.UtcNow
        };

        async Task AssertOtpAndAuditStateAsync(
            OtpStatus expectedStatus,
            int expectedAttempts,
            DateTimeOffset expectedLockout)
        {
            await using var assertionContext = new IdentityDbContext(options);
            var otp = await assertionContext.Otps.AsNoTracking()
                .SingleAsync(TestContext.Current.CancellationToken);
            Assert.Equal(expectedStatus, otp.Status);
            Assert.Equal(expectedAttempts, otp.Attempts);
            Assert.Equal(expectedLockout, otp.LockoutUntil);
            Assert.Empty(await assertionContext.LoginHistories.AsNoTracking()
                .ToListAsync(TestContext.Current.CancellationToken));
        }
    }

    private static bool ShouldRunContainerMatrix()
    {
        return string.Equals(
            Environment.GetEnvironmentVariable(
                "RUN_SIGNACORE_DATABASE_CONTRACTS"),
            "true",
            StringComparison.OrdinalIgnoreCase);
    }
}
