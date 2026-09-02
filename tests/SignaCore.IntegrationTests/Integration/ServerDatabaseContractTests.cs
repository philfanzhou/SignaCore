using DotNet.Testcontainers.Containers;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
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

            await SchemaMigrator.MigrateAsync(
                context,
                databaseOptions,
                TestContext.Current.CancellationToken);

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
