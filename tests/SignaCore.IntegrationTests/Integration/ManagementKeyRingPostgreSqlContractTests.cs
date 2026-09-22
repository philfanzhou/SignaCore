using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using ServiceMantle.Installation;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Keys;
using SignaCore.Host.Configuration;
using SignaCore.Host.Installation;
using SignaCore.Host.Startup;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.IntegrationTests.Integration;

/// <summary>
/// Real-PostgreSQL product regression for SignaCore issue #354 (upstream ServiceMantle #559,
/// fixed in ServiceMantle 0.1.0-alpha.10): with the PostgreSQL retrying execution strategy
/// enabled — the production default this regression must keep on — the management Data Protection
/// key ring persists its first key during the initial management login, survives a host rebuild,
/// upgrades from the 0.1.8-era migration history without rewriting business data, and fails
/// writes as a fixed, sanitized error with no partial rows. Gated behind
/// <c>RUN_SIGNACORE_DATABASE_CONTRACTS=true</c> like the other container contracts.
/// </summary>
public sealed class ManagementKeyRingPostgreSqlContractTests
{
    private const string RootSecret = "key-ring-root-secret-for-contract-tests-only";
    private const string AdminUsername = "keyring_contract_admin";
    private const string AdminPassword = "KeyRingContract123";
    private const string PublicBaseUrl = "https://identity.example.test";
    private const string CookieName = "__Host-ServiceMantle.Management";
    private const string UnsafeRequestHeader = "X-ServiceMantle-Request";
    private const string SetupEntryPath = "/management/v1/setup";
    private const string SessionRoot = "/management/v1";
    private const string CanarySecret = "key-ring-restart-canary-plaintext";

    // A distinctive container password so the secret-scan assertions cannot match routine words.
    private const string DatabasePassword = "keyring-contract-postgres";

    /// <summary>
    /// The migration head of release 0.1.8 (tag <c>0.1.8</c>): the lineage state a real 0.1.8
    /// database carries when it is upgraded. The 0.1.8 release predates the shared
    /// <c>service_installations</c> adoption and the shared settings aggregate, so its completed
    /// installation lives in the legacy <c>installation_state</c> singleton.
    /// </summary>
    private const string PostgreSql018Head = "20260820091041_PersistDataProtectionKeys";

    private static readonly string PostgreSqlImage =
        Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") is { Length: > 0 } image
            ? image
            : "postgres:15-alpine";

    [Fact]
    public async Task FreshInstall_FirstManagementLogin_PersistsEncryptedKeyRingWithoutLeakingSecrets()
    {
        await using var container = await StartContainerAsync();
        var database = ContainerDatabaseOptions(container);
        var masterKey = Convert.ToBase64String(new BootstrapMasterKeyProvider(RootSecret).GetMasterKey());

        using var bootstrapDirectory = new TemporaryDirectory();
        var bootstrapFilePath = await InstallationTestSupport.PrepareUninstalledBootstrapAsync(
            bootstrapDirectory.Path, database, RootSecret);
        await CompleteFirstRunSetupAsync(database, bootstrapFilePath);

        var capture = new LogCapture();
        using var factory = CreateHostFactory(
            bootstrapFilePath,
            services =>
            {
                services.RemoveAll<ILoggerFactory>();
                services.AddSingleton<ILoggerFactory>(_ => LoggerFactory.Create(logging =>
                    logging.AddProvider(capture)));
            });
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });

        var cookie = await LoginForCookieAsync(client);

        // The empty ring's first Protect during login persisted at least one encrypted record:
        // the ServiceMantle envelope prefix, never the plaintext, and never the external secrets.
        var rows = await KeyRowsAsync(database);
        Assert.True(rows.Length >= 1, $"Expected at least one persisted key row, found {rows.Length}.");
        Assert.All(rows, row =>
        {
            Assert.True(row.StartsWith("sm:v1:", StringComparison.Ordinal), "Key row is not encrypted.");
            Assert.DoesNotContain(masterKey, row, StringComparison.Ordinal);
            Assert.DoesNotContain(RootSecret, row, StringComparison.Ordinal);
            Assert.DoesNotContain(AdminPassword, row, StringComparison.Ordinal);
            Assert.DoesNotContain(cookie, row, StringComparison.Ordinal);
        });

        // The persisted ring backs the issued cookie on the same host: the session entry accepts it.
        client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", cookie);
        using var session = await client.GetAsync(SessionRoot + "/session", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, session.StatusCode);
        await AssertAuthenticatedSessionAsync(session);

        // The login path's logs carry none of the protected material either.
        var logged = string.Join('\n', capture.Messages);
        Assert.DoesNotContain(AdminPassword, logged, StringComparison.Ordinal);
        Assert.DoesNotContain(cookie, logged, StringComparison.Ordinal);
        Assert.DoesNotContain(masterKey, logged, StringComparison.Ordinal);
        Assert.DoesNotContain(RootSecret, logged, StringComparison.Ordinal);
        Assert.DoesNotContain(DatabasePassword, logged, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RebuiltHost_ReusesPersistedKeyRing_WithoutRegeneratingKeysOrInvalidatingCookies()
    {
        await using var container = await StartContainerAsync();
        var database = ContainerDatabaseOptions(container);

        using var bootstrapDirectory = new TemporaryDirectory();
        var bootstrapFilePath = await InstallationTestSupport.PrepareUninstalledBootstrapAsync(
            bootstrapDirectory.Path, database, RootSecret);
        await CompleteFirstRunSetupAsync(database, bootstrapFilePath);

        string cookie;
        string payload;
        string[] rowsAfterFirstLogin;
        using (var firstHost = CreateHostFactory(bootstrapFilePath))
        {
            using var client = firstHost.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost")
            });
            cookie = await LoginForCookieAsync(client);
            payload = firstHost.Services.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("key-ring-restart-contract").Protect(CanarySecret);
            rowsAfterFirstLogin = await KeyRowsAsync(database);
            Assert.True(rowsAfterFirstLogin.Length >= 1);
        }

        using var rebuilt = CreateHostFactory(bootstrapFilePath);

        // The rebuilt host reads the same persisted ring: the pre-rebuild payload decrypts, the
        // pre-rebuild cookie still authenticates, and no additional key was generated.
        Assert.Equal(
            CanarySecret,
            rebuilt.Services.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("key-ring-restart-contract").Unprotect(payload));

        using var client2 = rebuilt.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
        client2.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", cookie);
        using var session = await client2.GetAsync(SessionRoot + "/session", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, session.StatusCode);
        await AssertAuthenticatedSessionAsync(session);

        Assert.Equal(rowsAfterFirstLogin, await KeyRowsAsync(database));
    }

    [Fact]
    public async Task UpgradeFrom018History_AppliesFullMigration_PreservesBusinessData_AndPersistsFirstKey()
    {
        await using var container = await StartContainerAsync();
        var database = ContainerDatabaseOptions(container);

        // Bring the schema to the 0.1.8-era head and stage a real 0.1.8 deployment: the completed
        // legacy installation singleton plus the administrator's business rows. The legacy
        // system_settings table stays empty on purpose: crossing with live legacy rows is the
        // staged bridge of the system-settings retirement (docs/database/system-settings-retirement.md),
        // not this key-ring regression.
        await MigrateToAsync(database, PostgreSql018Head);
        var seeded = await Seed018EraDeploymentAsync(database);

        using var bootstrapDirectory = new TemporaryDirectory();
        var bootstrapFilePath = await InstallationTestSupport.PrepareUninstalledBootstrapAsync(
            bootstrapDirectory.Path, database, RootSecret);

        // The protected legacy import needs the deployment's public identity and the administrator
        // username from configuration for exactly this one start, the same way a 0.1.8 deployment
        // supplied them through appsettings.
        using var factory = CreateHostFactory(
            bootstrapFilePath,
            extraSettings: new Dictionary<string, string?>
            {
                [SystemSettingKeys.PublicBaseUrl] = PublicBaseUrl,
                [SystemSettingKeys.JwtIssuer] = PublicBaseUrl,
                [SystemSettingKeys.AdminUsername] = AdminUsername
            });
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });

        var cookie = await LoginForCookieAsync(client);

        // The startup gate applied the whole remaining lineage on top of the 0.1.8 history.
        await using var context = CreateContext(database);
        var applied = await context.Database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken);
        Assert.Equal(context.Database.GetMigrations().Count(), applied.Count());

        // The upgrade rewrote no business data: the 0.1.8-era administrator rows are byte-identical.
        var credential = await context.PasswordCredentials.AsNoTracking()
            .SingleAsync(item => item.Username == AdminUsername, TestContext.Current.CancellationToken);
        Assert.Equal(seeded.AccountId, credential.AccountId);
        Assert.Equal(AdminUsername, credential.Username);
        Assert.Equal(seeded.PasswordHash, credential.PasswordHash);
        Assert.Equal(seeded.CreatedAt, credential.CreatedAt);
        var account = await context.Accounts.AsNoTracking()
            .SingleAsync(item => item.Id == seeded.AccountId, TestContext.Current.CancellationToken);
        Assert.Equal(seeded.IsActive, account.IsActive);
        Assert.Equal(seeded.Remark, account.Remark);

        // The first management login after the upgrade persisted the encrypted ring, and the
        // issued cookie authenticates against it.
        var rows = await KeyRowsAsync(database);
        Assert.True(rows.Length >= 1, $"Expected at least one persisted key row, found {rows.Length}.");
        Assert.All(rows, row => Assert.True(row.StartsWith("sm:v1:", StringComparison.Ordinal)));

        client.DefaultRequestHeaders.TryAddWithoutValidation("Cookie", cookie);
        using var session = await client.GetAsync(SessionRoot + "/session", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, session.StatusCode);
        await AssertAuthenticatedSessionAsync(session);
    }

    [Fact]
    public async Task StoreElement_FailureOrCancellation_ReportsTheFixedStorageError_LeavesNoRowsAndNoSecrets()
    {
        await using var container = await StartContainerAsync();
        var database = ContainerDatabaseOptions(container);
        await MigrateToAsync(database, null);

        var masterKey = Convert.ToBase64String(new BootstrapMasterKeyProvider(RootSecret).GetMasterKey());

        foreach (var cancel in new[] { false, true })
        {
            var fault = new KeySaveFault(cancel);
            // The faulting factory keeps the production PostgreSQL options — including the
            // retrying execution strategy the issue forbids disabling — and only injects the
            // synthetic save failure.
            var repository = new EfCoreDataProtectionKeyRepository<IdentityDbContext>(
                new FaultingContextFactory(database, fault),
                InstallationStores.ServiceId,
                () => masterKey);

            var keyId = Guid.NewGuid();
            var element = new XElement(
                "key",
                new XAttribute("id", keyId.ToString("D")),
                new XAttribute("version", "1"),
                CanarySecret);

            var failure = Assert.Throws<DataProtectionKeyRepositoryException>(
                () => repository.StoreElement(element, $"key-{keyId:D}"));
            Assert.True(fault.Observed, "The injected save fault was not reached.");
            Assert.Equal(
                WellKnownDataProtectionKeyRepositoryErrorCodes.StorageError,
                failure.ErrorCode);

            var diagnostic = failure.ToString();
            Assert.DoesNotContain(masterKey, diagnostic, StringComparison.Ordinal);
            Assert.DoesNotContain(CanarySecret, diagnostic, StringComparison.Ordinal);
            Assert.DoesNotContain(DatabasePassword, diagnostic, StringComparison.Ordinal);

            // No partial row survives the failed or cancelled attempt.
            Assert.Empty(await KeyRowsAsync(database));
        }
    }

    private static async Task CompleteFirstRunSetupAsync(DatabaseOptions database, string bootstrapFilePath)
    {
        using var setupHost = CreateHostFactory(bootstrapFilePath);
        using var setupClient = setupHost.CreateClient();

        var code = await RotateSetupCodeAsync(database);
        using var request = new HttpRequestMessage(HttpMethod.Post, SetupEntryPath)
        {
            Content = JsonContent.Create(new
            {
                code,
                input = new
                {
                    publicBaseUrl = PublicBaseUrl,
                    allowNonHttpsIssuer = false,
                    jwtAudience = "SignaCore.Services",
                    username = AdminUsername,
                    password = AdminPassword
                }
            })
        };
        request.Headers.TryAddWithoutValidation(UnsafeRequestHeader, "1");

        using var response = await setupClient.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    private static async Task<string> RotateSetupCodeAsync(DatabaseOptions database)
    {
        // The harness context deliberately disables the retrying strategy: the product's own setup
        // host composes its contexts the same way for the one-shot setup code store.
        await using var db = CreateContext(database, enableRetryOnFailure: false);
        var setupCodeStore = new EfCoreServiceSetupCodeStore<IdentityDbContext>(
            db,
            lifetime: SetupCodeLifetime.Create(TimeSpan.FromHours(1)));
        var issued = await setupCodeStore.RotateAsync(
            InstallationStores.ServiceId, TestContext.Current.CancellationToken);
        Assert.True(issued.IsIssued, $"Rotation failed: {issued.ErrorCode}");
        return issued.SetupCode!.Reveal();
    }

    private static async Task<string> LoginForCookieAsync(HttpClient client)
    {
        using var login = new HttpRequestMessage(HttpMethod.Post, SessionRoot + "/session/login")
        {
            Content = JsonContent.Create(new { username = AdminUsername, password = AdminPassword })
        };
        login.Headers.TryAddWithoutValidation(UnsafeRequestHeader, "1");
        using var response = await client.SendAsync(login, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        if (!response.Headers.NonValidated.TryGetValues("Set-Cookie", out var values))
        {
            throw new InvalidOperationException("The login response carried no Set-Cookie header.");
        }

        foreach (var value in values)
        {
            var segment = value.Split(';')[0];
            if (segment.StartsWith($"{CookieName}=", StringComparison.Ordinal))
            {
                return segment;
            }
        }

        throw new InvalidOperationException($"The login response set no {CookieName} cookie.");
    }

    private static async Task AssertAuthenticatedSessionAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken));
        Assert.True(document.RootElement.GetProperty("authenticated").GetBoolean());
    }

    private sealed record Seeded018Era(
        Guid AccountId,
        string PasswordHash,
        DateTimeOffset CreatedAt,
        bool IsActive,
        string? Remark);

    /// <summary>
    /// Stages the completed 0.1.8 deployment at its own schema: the administrator's account and
    /// password credential through the current entities (the tables are unchanged since before
    /// 0.1.8), and the completed legacy <c>installation_state</c> singleton through raw SQL, the
    /// way the historical schema received it (the mapping is retired from the runtime model).
    /// </summary>
    private static async Task<Seeded018Era> Seed018EraDeploymentAsync(DatabaseOptions database)
    {
        await using var context = CreateContext(database, enableRetryOnFailure: false);

        // Truncate to whole microseconds: the physical timestamptz column stores microseconds, and
        // the not-rewritten assertion compares the seeded instant exactly.
        var createdAt = new DateTimeOffset(
            DateTime.UtcNow.Ticks / 10 * 10,
            TimeSpan.Zero);
        var passwordHash = BCrypt.Net.BCrypt.HashPassword(AdminPassword);
        const string remark = "0.1.8-era administrator";

        var accountId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity
        {
            Id = accountId,
            IsActive = true,
            CreatedAt = createdAt,
            Remark = remark
        });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = Guid.NewGuid(),
            AccountId = accountId,
            Username = AdminUsername,
            PasswordHash = passwordHash,
            CreatedAt = createdAt
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);

        var installationId = Guid.NewGuid();
        var completedAt = new DateTimeOffset(DateTime.UtcNow.Ticks / 10 * 10, TimeSpan.Zero);
        await context.Database.ExecuteSqlAsync($"""
            INSERT INTO installation_state (id, status, installation_id, setup_code_hash, setup_code_expires_at, completed_at, configuration_version)
            VALUES (1, 1, {installationId}, NULL, NULL, {completedAt}, 1)
            """, TestContext.Current.CancellationToken);

        return new Seeded018Era(accountId, passwordHash, createdAt, IsActive: true, remark);
    }

    private static WebApplicationFactory<Program> CreateHostFactory(
        string bootstrapFilePath,
        Action<IServiceCollection>? configureTestServices = null,
        IDictionary<string, string?>? extraSettings = null)
    {
        var factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                // The production rules — HTTPS-only public base URL, no Development fallbacks —
                // apply outside Development, and WebApplicationFactory defaults to Development.
                builder.UseSetting("environment", Environments.Production);
                builder.UseSetting("Bootstrap:FilePath", bootstrapFilePath);
                foreach (var (key, value) in extraSettings ?? new Dictionary<string, string?>())
                {
                    builder.UseSetting(key, value);
                }

                if (configureTestServices is not null)
                {
                    builder.ConfigureTestServices(configureTestServices);
                }
            });
        return factory;
    }

    private static async Task MigrateToAsync(DatabaseOptions database, string? migrationId)
    {
        await using var context = CreateContext(database, enableRetryOnFailure: false);
        var migrator = context.Database.GetService<IMigrator>();
        await migrator.MigrateAsync(migrationId, TestContext.Current.CancellationToken);
    }

    private static async Task<string[]> KeyRowsAsync(DatabaseOptions database)
    {
        await using var context = CreateContext(database, enableRetryOnFailure: false);
        return await context.Database.SqlQueryRaw<string>(
            "SELECT encrypted_xml AS \"Value\" FROM service_data_protection_keys ORDER BY service_id, key_id")
            .ToArrayAsync(TestContext.Current.CancellationToken);
    }

    private static IdentityDbContext CreateContext(
        DatabaseOptions database,
        bool enableRetryOnFailure = true)
    {
        var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
        optionsBuilder.UseIdentityDatabase(database, enableRetryOnFailure);
        return new IdentityDbContext(optionsBuilder.Options);
    }

    private static async Task<PostgreSqlContainer> StartContainerAsync()
    {
        Assert.SkipUnless(
            ShouldRunContainerMatrix(),
            "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the management key ring PostgreSQL contracts.");

        var container = new PostgreSqlBuilder(PostgreSqlImage)
            .WithDatabase("identity")
            .WithUsername("postgres")
            .WithPassword(DatabasePassword)
            .Build();
        await container.StartAsync(TestContext.Current.CancellationToken);

        await WaitUntilConnectableAsync(container.GetConnectionString());
        return container;
    }

    private static DatabaseOptions ContainerDatabaseOptions(PostgreSqlContainer container) => new()
    {
        Provider = "PostgreSQL",
        ServerVersion = "15",
        ConnectionString = container.GetConnectionString()
    };

    private static async Task WaitUntilConnectableAsync(string connectionString)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(120);
        Exception? lastError = null;
        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                await using var connection = new NpgsqlConnection(connectionString);
                await connection.OpenAsync();
                return;
            }
            catch (Exception exception)
            {
                lastError = exception;
            }

            await Task.Delay(TimeSpan.FromSeconds(1));
        }

        throw new InvalidOperationException(
            $"PostgreSQL did not become connectable within 120s. Last error: {lastError?.Message}");
    }

    private static bool ShouldRunContainerMatrix() =>
        bool.TryParse(
            Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS"),
            out var run) && run;

    /// <summary>
    /// A DbContext factory whose contexts carry the production PostgreSQL options — including the
    /// retrying execution strategy — plus an injected <see cref="SaveChangesInterceptor"/> fault.
    /// </summary>
    private sealed class FaultingContextFactory(DatabaseOptions database, IInterceptor interceptor)
        : IDbContextFactory<IdentityDbContext>
    {
        public IdentityDbContext CreateDbContext()
        {
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseIdentityDatabase(database);
            optionsBuilder.AddInterceptors(interceptor);
            return new IdentityDbContext(optionsBuilder.Options);
        }
    }

    private sealed class KeySaveFault(bool cancel) : SaveChangesInterceptor
    {
        public bool Observed { get; private set; }

        private void Fail()
        {
            Observed = true;
            if (cancel)
            {
                throw new OperationCanceledException(new CancellationToken(true));
            }

            throw new InvalidOperationException("Synthetic key save failure.");
        }

        public override InterceptionResult<int> SavingChanges(
            DbContextEventData eventData,
            InterceptionResult<int> result)
        {
            Fail();
            return result;
        }

        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData,
            InterceptionResult<int> result,
            CancellationToken cancellationToken = default)
        {
            Fail();
            return ValueTask.FromResult(result);
        }
    }

    private sealed class LogCapture : ILoggerProvider
    {
        public List<string> Messages { get; } = [];

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(LogCapture owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                owner.Messages.Add(
                    $"{formatter(state, exception)} {exception?.ToString() ?? string.Empty}");
        }
    }

    private sealed class TemporaryDirectory() : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            $"signacore-keyring-{Guid.NewGuid():N}");

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
