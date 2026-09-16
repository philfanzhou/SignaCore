using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Validators;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

public sealed class SqliteDatabaseContractTests
{
    private const string PreOidcMigration = "20260820091047_PersistDataProtectionKeys";

    [Fact]
    public async Task InteractiveOidcMigration_FreshDatabaseUsesFailClosedDefaultsAndConstraints()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-oidc-fresh-{Guid.NewGuid():N}.db");
        var options = CreateSqliteOptions(databasePath);
        var appId = Guid.NewGuid();

        try
        {
            await using var context = new IdentityDbContext(options);
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
            await InsertLegacyApplicationAsync(context, appId, callbackUrl: null);

            var application = await context.AppRegistrations
                .AsNoTracking()
                .SingleAsync(
                    app => app.Id == appId,
                    TestContext.Current.CancellationToken);
            Assert.Equal(OidcClientType.Confidential, application.ClientType);
            Assert.False(application.AllowAuthorizationCode);
            Assert.Equal("openid", application.AllowedScopes);
            Assert.False(application.AllowRefreshToken);
            Assert.Null(application.IdentitySessionMaxAgeSeconds);
            Assert.Empty(await context.AppRedirectUris.ToListAsync(
                TestContext.Current.CancellationToken));

            var canonicalUri = "https://example.com/callback?tenant=one";
            context.AppRedirectUris.Add(new AppRedirectUriEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = appId,
                Kind = RedirectUriKind.Redirect,
                CanonicalUri = canonicalUri
            });
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);

            context.AppRedirectUris.Add(new AppRedirectUriEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = appId,
                Kind = RedirectUriKind.Redirect,
                CanonicalUri = canonicalUri
            });
            await Assert.ThrowsAsync<DbUpdateException>(() =>
                context.SaveChangesAsync(TestContext.Current.CancellationToken));
            context.ChangeTracker.Clear();

            context.AppRedirectUris.Add(new AppRedirectUriEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = appId,
                Kind = RedirectUriKind.PostLogout,
                CanonicalUri = canonicalUri
            });
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);

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
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
            Assert.Equal(
                boundaryCanonicalUri,
                await context.AppRedirectUris
                    .AsNoTracking()
                    .Where(uri => uri.CanonicalUri == boundaryCanonicalUri)
                    .Select(uri => uri.CanonicalUri)
                    .SingleAsync(TestContext.Current.CancellationToken));

            var repository = new AppRegistrationRepository(context);
            var withOidcConfiguration = await repository
                .GetByAppIdWithOidcConfigurationAsync(
                    "OIDC-MIGRATION-APP",
                    TestContext.Current.CancellationToken);
            Assert.NotNull(withOidcConfiguration);
            Assert.Equal(3, withOidcConfiguration.RedirectUris.Count);

            context.AppRegistrations.Remove(withOidcConfiguration);
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
            Assert.Empty(await context.AppRedirectUris.AsNoTracking().ToListAsync(
                TestContext.Current.CancellationToken));

            context.AppRedirectUris.Add(new AppRedirectUriEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = Guid.NewGuid(),
                Kind = RedirectUriKind.Redirect,
                CanonicalUri = "https://example.com/orphan"
            });
            await Assert.ThrowsAsync<DbUpdateException>(() =>
                context.SaveChangesAsync(TestContext.Current.CancellationToken));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath)) File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task InteractiveOidcMigration_LegacyUpgradePreservesApplicationAndDownIsSymmetric()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-oidc-upgrade-{Guid.NewGuid():N}.db");
        var options = CreateSqliteOptions(databasePath);
        var appId = Guid.NewGuid();
        const string callbackUrl = "https://claims.example.com/callback?tenant=legacy";

        try
        {
            await using var context = new IdentityDbContext(options);
            var migrator = context.Database.GetService<IMigrator>();
            await migrator.MigrateAsync(
                PreOidcMigration,
                TestContext.Current.CancellationToken);
            await InsertLegacyApplicationAsync(context, appId, callbackUrl);

            await migrator.MigrateAsync(cancellationToken: TestContext.Current.CancellationToken);

            var application = await context.AppRegistrations
                .AsNoTracking()
                .SingleAsync(
                    app => app.Id == appId,
                    TestContext.Current.CancellationToken);
            Assert.Equal(callbackUrl, application.CallbackUrl);
            Assert.Equal(LdapLoginMode.ManualApproval, application.LdapLoginMode);
            Assert.Equal(SmsLoginMode.AutoProvision, application.SmsLoginMode);
            Assert.Equal("legacy-profile", application.SmsProfileKey);
            Assert.Equal(WechatLoginMode.BindRequired, application.WechatLoginMode);
            Assert.Equal(AudienceMode.Shared, application.AudienceMode);
            Assert.Equal(OidcClientType.Confidential, application.ClientType);
            Assert.False(application.AllowAuthorizationCode);
            Assert.Equal("openid", application.AllowedScopes);
            Assert.False(application.AllowRefreshToken);
            Assert.Null(application.IdentitySessionMaxAgeSeconds);
            Assert.Empty(await context.AppRedirectUris.AsNoTracking().ToListAsync(
                TestContext.Current.CancellationToken));

            context.ChangeTracker.Clear();
            await migrator.MigrateAsync(
                PreOidcMigration,
                TestContext.Current.CancellationToken);
            Assert.False(await SqliteTableExistsAsync(context, "app_redirect_uris"));
            var columns = await GetSqliteColumnsAsync(context, "app_registrations");
            Assert.DoesNotContain("allow_authorization_code", columns);
            Assert.DoesNotContain("allow_refresh_token", columns);
            Assert.DoesNotContain("allowed_scopes", columns);
            Assert.DoesNotContain("client_type", columns);
            Assert.DoesNotContain("identity_session_max_age_seconds", columns);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath)) File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task AuthorizationRequestsMigration_FreshDatabaseMatchesContinuationContract()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-continuation-fresh-{Guid.NewGuid():N}.db");
        var options = CreateSqliteOptions(databasePath);

        try
        {
            await using var context = new IdentityDbContext(options);
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);

            // PS-03 column set and nullability, exactly.
            var columns = await ReadPragmaAsync(context, "PRAGMA table_info(authorization_requests)");
            Assert.Equal(
                new[]
                {
                    ("id", true),
                    ("handle_digest", true),
                    ("app_registration_id", true),
                    ("redirect_uri", true),
                    ("scope", true),
                    ("state", true),
                    ("nonce", true),
                    ("code_challenge", true),
                    ("created_at", true),
                    ("expires_at", true),
                    ("consumed_at", false)
                },
                columns.Select(row => (row[1], row[3] == "1")).ToArray());

            // The digest carries a single-column unique index.
            var indexNames = await ReadPragmaAsync(context, "PRAGMA index_list(authorization_requests)");
            var uniqueDigestIndexes = new List<string>();
            foreach (var index in indexNames.Where(row => row[2] == "1"))
            {
                var indexColumns = await ReadPragmaAsync(context, $"PRAGMA index_info(\"{index[1]}\")");
                if (indexColumns.Count == 1 && indexColumns[0][2] == "handle_digest")
                {
                    uniqueDigestIndexes.Add(index[1]);
                }
            }

            Assert.Single(uniqueDigestIndexes);

            // PS-23: one non-null restrictive reference to app_registrations; nothing cascades.
            var foreignKeys = await ReadPragmaAsync(context, "PRAGMA foreign_key_list(authorization_requests)");
            var reference = Assert.Single(foreignKeys);
            Assert.Equal("app_registrations", reference[2]);
            Assert.Equal("app_registration_id", reference[3]);
            Assert.Equal("id", reference[4]);
            Assert.Equal("RESTRICT", reference[6], ignoreCase: true);

            // The restrictive reference is enforced in both directions: an orphan row fails, and
            // deleting an application with a continuation row fails without cascading.
            var appId = Guid.NewGuid();
            context.AppRegistrations.Add(new AppRegistrationEntity
            {
                Id = appId,
                AppId = "continuation-contract-app",
                AppSecretHash = "hash",
                AppName = "Continuation Contract",
                IsActive = true,
                CreatedAt = DateTimeOffset.UtcNow
            });
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);

            context.AuthorizationRequests.Add(
                CreateAuthorizationRequest(Guid.NewGuid(), "orphan-handle-0123456789abcdefghijklmnopqrstu"));
            await Assert.ThrowsAsync<DbUpdateException>(() =>
                context.SaveChangesAsync(TestContext.Current.CancellationToken));
            context.ChangeTracker.Clear();

            context.AuthorizationRequests.Add(
                CreateAuthorizationRequest(appId, "live-handle-0123456789abcdefghijklmnopqrstu"));
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);

            // The database enforces the restriction: clear the tracker so the failure is SQLite's
            // RESTRICT enforcement rather than EF's client-side cascade check.
            context.ChangeTracker.Clear();
            var application = await context.AppRegistrations
                .SingleAsync(app => app.Id == appId, TestContext.Current.CancellationToken);
            context.AppRegistrations.Remove(application);
            await Assert.ThrowsAsync<DbUpdateException>(() =>
                context.SaveChangesAsync(TestContext.Current.CancellationToken));
            context.ChangeTracker.Clear();

            Assert.Single(await context.AuthorizationRequests
                .AsNoTracking()
                .ToListAsync(TestContext.Current.CancellationToken));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath)) File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task AuthorizationRequestsMigration_UpgradeFromDropLegacyDataProtectionKeysIsAdditiveAndDownIsSymmetric()
    {
        const string preContinuationMigration = "20260914171840_DropLegacyDataProtectionKeys";
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-continuation-upgrade-{Guid.NewGuid():N}.db");
        var options = CreateSqliteOptions(databasePath);
        var accountId = Guid.NewGuid();
        var appId = Guid.NewGuid();
        var tokenId = Guid.NewGuid();
        var createdAt = DateTimeOffset.UtcNow;
        var expiresAt = createdAt.AddHours(1);
        var tokenDigest = RefreshTokenDigest.Compute("continuation-upgrade-token");

        try
        {
            await using var context = new IdentityDbContext(options);
            var migrator = context.Database.GetService<IMigrator>();
            await migrator.MigrateAsync(preContinuationMigration, TestContext.Current.CancellationToken);

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
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);

            var refreshColumnsBefore = await GetSqliteColumnsAsync(context, "refresh_tokens");
            var appColumnsBefore = await GetSqliteColumnsAsync(context, "app_registrations");
            Assert.False(await SqliteTableExistsAsync(context, "authorization_requests"));

            await migrator.MigrateAsync(cancellationToken: TestContext.Current.CancellationToken);

            // Purely additive: the new table exists and is empty, existing tables keep their shape.
            Assert.True(await SqliteTableExistsAsync(context, "authorization_requests"));
            Assert.Empty(await context.AuthorizationRequests
                .AsNoTracking()
                .ToListAsync(TestContext.Current.CancellationToken));
            Assert.True(refreshColumnsBefore.SetEquals(await GetSqliteColumnsAsync(context, "refresh_tokens")));
            Assert.True(appColumnsBefore.SetEquals(await GetSqliteColumnsAsync(context, "app_registrations")));

            await AssertSeedUnchangedAsync(context, accountId, appId, tokenId, createdAt, expiresAt, tokenDigest);

            // Down removes exactly the new schema and leaves every existing row untouched.
            context.ChangeTracker.Clear();
            await migrator.MigrateAsync(preContinuationMigration, TestContext.Current.CancellationToken);
            Assert.False(await SqliteTableExistsAsync(context, "authorization_requests"));
            Assert.True(refreshColumnsBefore.SetEquals(await GetSqliteColumnsAsync(context, "refresh_tokens")));
            Assert.True(appColumnsBefore.SetEquals(await GetSqliteColumnsAsync(context, "app_registrations")));
            await AssertSeedUnchangedAsync(context, accountId, appId, tokenId, createdAt, expiresAt, tokenDigest);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath)) File.Delete(databasePath);
        }
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

    private static AuthorizationRequestEntity CreateAuthorizationRequest(
        Guid appRegistrationId,
        string plaintextHandle) => new()
    {
        Id = Guid.NewGuid(),
        HandleDigest = LoginHandleDigest.Compute(plaintextHandle),
        AppRegistrationId = appRegistrationId,
        RedirectUri = "https://client.example.com/callback",
        Scope = "openid",
        State = "sqlite-contract-state-value",
        Nonce = "sqlite-contract-nonce-value",
        CodeChallenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        CreatedAt = DateTimeOffset.UtcNow,
        ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(
            IdentityConstants.LoginHandleLifetimeMinutes)
    };

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
                    : Convert.ToString(reader.GetValue(ordinal), System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
            }

            rows.Add(row);
        }

        return rows;
    }

    [Fact]
    public async Task SmsMigration_DropsLegacyEphemeralOtpRowsBeforeAddingAppForeignKey()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"signacore-sms-migration-{Guid.NewGuid():N}.db");
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = $"Data Source={databasePath}"
        });

        try
        {
            await using var context = new IdentityDbContext(optionsBuilder.Options);
            var migrator = context.Database.GetService<IMigrator>();
            await migrator.MigrateAsync("20260805151934_EnableAppScopedLdapLogin", TestContext.Current.CancellationToken);
            var now = (DateTimeOffset.UtcNow.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10;
            await context.Database.ExecuteSqlRawAsync(
                "INSERT INTO otps (id, phone, code, expires_at, attempts, lockout_until, created_at) VALUES ({0}, {1}, {2}, {3}, 0, 0, {3})",
                Guid.NewGuid(), "13800138000", "123456", now);

            await migrator.MigrateAsync(cancellationToken: TestContext.Current.CancellationToken);

            Assert.Empty(await context.Otps.AsNoTracking().ToListAsync(cancellationToken: TestContext.Current.CancellationToken));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath)) File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task MigrationAndCrud_PreserveUtcInstantAtMicrosecondPrecision()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-{Guid.NewGuid():N}.db");

        try
        {
            var databaseOptions = new DatabaseOptions
            {
                Provider = "SQLite",
                ConnectionString = $"Data Source={databasePath}"
            };
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(databaseOptions);

            var sourceInstant = new DateTimeOffset(
                2026,
                7,
                30,
                12,
                34,
                56,
                TimeSpan.FromHours(8)).AddTicks(1234560);
            var accountId = Guid.NewGuid();

            await using (var writeContext = new IdentityDbContext(optionsBuilder.Options))
            {
                await writeContext.Database.MigrateAsync(cancellationToken: TestContext.Current.CancellationToken);
                writeContext.Accounts.Add(new AccountEntity
                {
                    Id = accountId,
                    IsActive = true,
                    CreatedAt = sourceInstant
                });
                await writeContext.SaveChangesAsync(TestContext.Current.CancellationToken);

                writeContext.RefreshTokens.Add(new RefreshTokenEntity
                {
                    Id = Guid.NewGuid(),
                    AccountId = accountId,
                    TokenValue = Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
                    CreatedAt = sourceInstant,
                    ExpiresAt = sourceInstant.AddHours(1),
                    AppId = string.Empty
                });
                await Assert.ThrowsAsync<DbUpdateException>(
                    () => writeContext.SaveChangesAsync(TestContext.Current.CancellationToken));
            }

            await using var readContext = new IdentityDbContext(optionsBuilder.Options);
            var account = await readContext.Accounts
                .AsNoTracking()
                .SingleAsync(item => item.Id == accountId, cancellationToken: TestContext.Current.CancellationToken);

            Assert.Equal(TimeSpan.Zero, account.CreatedAt.Offset);
            Assert.Equal(sourceInstant.UtcTicks / 10, account.CreatedAt.UtcTicks / 10);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath))
            {
                File.Delete(databasePath);
            }
        }
    }

    [Fact]
    public async Task CaseInsensitiveKeysAndConcurrentConsumption_AreProviderIndependent()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"signacore-{Guid.NewGuid():N}.db");
        var databaseOptions = new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = $"Data Source={databasePath};Default Timeout=30"
        };
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(databaseOptions);

        try
        {
            var accountId = Guid.NewGuid();
            var appRegistrationId = Guid.NewGuid();
            const string refreshToken = "CaseSensitiveRefreshToken";
            const string phone = "13800138000";
            const string otpCode = "123456";

            await using (var seedContext = new IdentityDbContext(optionsBuilder.Options))
            {
                await seedContext.Database.MigrateAsync(cancellationToken: TestContext.Current.CancellationToken);
                seedContext.AppRegistrations.Add(new AppRegistrationEntity
                {
                    Id = appRegistrationId,
                    AppId = "database-contract-app",
                    AppSecretHash = "hash",
                    AppName = "Database Contract",
                    IsActive = true,
                    CreatedAt = DateTimeOffset.UtcNow
                });
                seedContext.Accounts.Add(new AccountEntity
                {
                    Id = accountId,
                    IsActive = true,
                    CreatedAt = DateTimeOffset.UtcNow
                });
                seedContext.PasswordCredentials.Add(new PasswordCredentialEntity
                {
                    Id = Guid.NewGuid(),
                    AccountId = accountId,
                    Username = "Cafe\u0301",
                    PasswordHash = "hash",
                    CreatedAt = DateTimeOffset.UtcNow
                });
                seedContext.RefreshTokens.Add(new RefreshTokenEntity
                {
                    Id = Guid.NewGuid(),
                    AccountId = accountId,
                    TokenValue = RefreshTokenDigest.Compute(refreshToken),
                    CreatedAt = DateTimeOffset.UtcNow,
                    ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
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
                await seedContext.SaveChangesAsync(TestContext.Current.CancellationToken);
            }

            await using (var queryContext = new IdentityDbContext(optionsBuilder.Options))
            {
                var credentialRepository =
                    new PasswordCredentialRepository(queryContext);
                var credential =
                    await credentialRepository.GetByUsernameAsync("CAFÉ");
                Assert.NotNull(credential);
                Assert.Equal("Cafe\u0301", credential.Username);
            }

            await VerifyOtpAuditTransactionRollbackAsync(
                optionsBuilder.Options,
                appRegistrationId,
                phone,
                otpCode);

            var rotateResults = await Task.WhenAll(
                TryRotateAsync(optionsBuilder.Options, refreshToken, accountId),
                TryRotateAsync(optionsBuilder.Options, refreshToken, accountId));
            Assert.Equal(1, rotateResults.Count(result => result));

            await using (var assertionContext = new IdentityDbContext(optionsBuilder.Options))
            {
                Assert.Single(await assertionContext.RefreshTokens
                    .Where(token => !token.IsRevoked)
                    .ToListAsync(cancellationToken: TestContext.Current.CancellationToken));
            }

            var consumeResults = await Task.WhenAll(
                TryConsumeOtpAsync(optionsBuilder.Options, appRegistrationId, phone, otpCode),
                TryConsumeOtpAsync(optionsBuilder.Options, appRegistrationId, phone, otpCode));
            Assert.Equal(1, consumeResults.Count(result => result));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath))
            {
                File.Delete(databasePath);
            }
        }
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

    private static DbContextOptions<IdentityDbContext> CreateSqliteOptions(string databasePath)
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(new DatabaseOptions
        {
            Provider = "SQLite",
            ConnectionString = $"Data Source={databasePath}"
        });
        return optionsBuilder.Options;
    }

    private static Task<int> InsertLegacyApplicationAsync(
        IdentityDbContext context,
        Guid id,
        string? callbackUrl)
    {
        var createdAt = (DateTimeOffset.UtcNow.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10;
        return context.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO app_registrations
                (id, app_id, app_id_normalized, app_secret_hash, app_name, callback_url,
                 is_active, created_at, ldap_login_mode, sms_login_mode, sms_profile_key,
                 wechat_login_mode, audience_mode)
            VALUES
                ({id}, {"oidc-migration-app"}, {"OIDC-MIGRATION-APP"}, {"hash"},
                 {"OIDC Migration"}, {callbackUrl}, {true}, {createdAt},
                 {(int)LdapLoginMode.ManualApproval}, {(int)SmsLoginMode.AutoProvision}, {"legacy-profile"},
                 {(int)WechatLoginMode.BindRequired}, {(int)AudienceMode.Shared});
            """, cancellationToken: TestContext.Current.CancellationToken);
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
        return Convert.ToInt64(await command.ExecuteScalarAsync(TestContext.Current.CancellationToken)) > 0;
    }

    private static async Task<HashSet<string>> GetSqliteColumnsAsync(
        IdentityDbContext context,
        string tableName)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        await using var command = context.Database.GetDbConnection().CreateCommand();
        command.CommandText = $"PRAGMA table_info({tableName})";
        await using var reader = await command.ExecuteReaderAsync(TestContext.Current.CancellationToken);
        var columns = new HashSet<string>(StringComparer.Ordinal);
        while (await reader.ReadAsync(TestContext.Current.CancellationToken))
        {
            columns.Add(reader.GetString(1));
        }

        return columns;
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
}
