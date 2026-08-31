using DotNet.Testcontainers.Containers;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
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

        // 用东八区表达一个瞬间，再转成 UTC 写入：验证"同一瞬间无论用哪个偏移表达，
        // 落库后都是同一个 UTC 值且微秒精度不丢"。
        //
        // 这里必须显式 ToUniversalTime()，不能直接写非零偏移的值：Npgsql 对
        // timestamp with time zone 只接受 Offset=0，写非零偏移会抛
        // ArgumentException（"only offset 0 (UTC) is supported"）。
        // 产品代码全程使用 DateTimeOffset.UtcNow，此处对齐产品的写入方式。
        var sourceInstant = new DateTimeOffset(
            2026,
            7,
            30,
            12,
            34,
            56,
            TimeSpan.FromHours(8)).AddTicks(1234560).ToUniversalTime();
        const string token = "CaseSensitiveRefreshToken";
        const string legacyToken = "LegacyPlaintextRefreshToken";
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
            seedContext.RefreshTokens.Add(new RefreshTokenEntity
            {
                Id = Guid.NewGuid(),
                AccountId = accountId,
                TokenValue = legacyToken,
                CreatedAt = sourceInstant,
                ExpiresAt = sourceInstant.AddHours(1),
                IsRevoked = true,
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
            await DatabaseInitializer.ProtectLegacyRefreshTokensAsync(
                queryContext,
                NullLogger.Instance);
            Assert.NotNull(await queryContext.RefreshTokens
                .AsNoTracking()
                .SingleOrDefaultAsync(refreshToken =>
                    refreshToken.TokenValue == RefreshTokenDigest.Compute(legacyToken)));

            var credentialRepository =
                new PasswordCredentialRepository(queryContext);
            // 写入的是分解形式 "Café"（e + 组合重音符），查询用预组合的大写形式
            // "CAFÉ"（É）：验证 IdentityValueNormalizer 的 FormC + ToUpperInvariant
            // 在各 provider 上行为一致。
            //
            // 这里刻意用 \u00C9 转义而不是直接写 É：该字面量曾被误按 GBK 解码再存回 UTF-8，
            // É(C3 89) 变成了汉字"脡"(U+8121)，于是查询的是一个从未写入过的值，
            // 用例因此长期失败。非 ASCII 字面量一律用转义，避免重蹈覆辙。
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

        var repository = new AppRegistrationRepository(context);
        var withOidcConfiguration = await repository.GetByAppIdWithOidcConfigurationAsync(
            "OIDC-MIGRATION-APP",
            TestContext.Current.CancellationToken);
        Assert.NotNull(withOidcConfiguration);
        Assert.Equal(2, withOidcConfiguration.RedirectUris.Count);

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

    private static bool ShouldRunContainerMatrix()
    {
        return string.Equals(
            Environment.GetEnvironmentVariable(
                "RUN_SIGNACORE_DATABASE_CONTRACTS"),
            "true",
            StringComparison.OrdinalIgnoreCase);
    }
}
