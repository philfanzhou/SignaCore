using DotNet.Testcontainers.Containers;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
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

            await migrator.MigrateAsync(
                PreOidcMigration,
                TestContext.Current.CancellationToken);
            Assert.False(await PostgreSqlTableExistsAsync(context, "app_redirect_uris"));
            var columns = await GetPostgreSqlColumnsAsync(context, "app_registrations");
            Assert.DoesNotContain("allow_authorization_code", columns);
            Assert.DoesNotContain("allow_refresh_token", columns);
            Assert.DoesNotContain("allowed_scopes", columns);
            Assert.DoesNotContain("client_type", columns);
            Assert.DoesNotContain("identity_session_max_age_seconds", columns);

            var legacyAppId = Guid.NewGuid();
            const string callbackUrl = "https://claims.example.com/callback?tenant=legacy";
            await InsertLegacyApplicationAsync(context, legacyAppId, callbackUrl);
            await migrator.MigrateAsync(cancellationToken: TestContext.Current.CancellationToken);

            var upgradedApplication = await context.AppRegistrations
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
            Assert.Empty(await context.AppRedirectUris.AsNoTracking().ToListAsync(
                TestContext.Current.CancellationToken));
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
                context.RefreshTokens.Add(new RefreshTokenEntity
                {
                    Id = tokenId,
                    AccountId = accountId,
                    TokenValue = tokenDigest,
                    CreatedAt = createdAt,
                    ExpiresAt = expiresAt,
                    AppId = "continuation-upgrade-app"
                });
                await context.SaveChangesAsync(cancellationToken);

                var refreshColumnsBefore = await GetPostgreSqlColumnsAsync(context, "refresh_tokens");
                var appColumnsBefore = await GetPostgreSqlColumnsAsync(context, "app_registrations");
                Assert.False(await PostgreSqlTableExistsAsync(context, "authorization_requests"));

                await migrator.MigrateAsync(cancellationToken: cancellationToken);

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

                await migrator.MigrateAsync(cancellationToken: cancellationToken);
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
                context.RefreshTokens.Add(new RefreshTokenEntity
                {
                    Id = tokenId, AccountId = accountId, TokenValue = tokenDigest,
                    CreatedAt = createdAt, ExpiresAt = expiresAt, AppId = "session-upgrade-app"
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

                var accountsBefore = await GetPostgreSqlColumnsAsync(context, "accounts");
                var credentialsBefore = await GetPostgreSqlColumnsAsync(context, "password_credentials");
                var appsBefore = await GetPostgreSqlColumnsAsync(context, "app_registrations");
                var tokensBefore = await GetPostgreSqlColumnsAsync(context, "refresh_tokens");
                var continuationsBefore = await GetPostgreSqlColumnsAsync(context, "authorization_requests");
                Assert.False(await PostgreSqlTableExistsAsync(context, "identity_sessions"));

                await migrator.MigrateAsync(cancellationToken: cancellationToken);

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

                await migrator.MigrateAsync(cancellationToken: cancellationToken);
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

                    var token = await assertionContext.RefreshTokens.AsNoTracking()
                        .SingleAsync(row => row.Id == tokenId, cancellationToken);
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
                context.RefreshTokens.Add(new RefreshTokenEntity
                {
                    Id = tokenId, AccountId = accountId, TokenValue = tokenDigest,
                    CreatedAt = createdAt, ExpiresAt = expiresAt, AppId = "code-contract-app"
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

                var accountsBefore = await GetPostgreSqlColumnsAsync(context, "accounts");
                var sessionsBefore = await GetPostgreSqlColumnsAsync(context, "identity_sessions");
                var continuationsBefore = await GetPostgreSqlColumnsAsync(
                    context, "authorization_requests");
                Assert.False(await PostgreSqlTableExistsAsync(context, "authorization_codes"));

                await migrator.MigrateAsync(cancellationToken: cancellationToken);

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

                await migrator.MigrateAsync(cancellationToken: cancellationToken);
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

        var token = await context.RefreshTokens.AsNoTracking()
            .SingleAsync(item => item.Id == tokenId, cancellationToken);
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
            seedContext.RefreshTokens.Add(new RefreshTokenEntity
            {
                Id = Guid.NewGuid(),
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
