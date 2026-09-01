using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Host.Provisioning;
using Xunit;

namespace SignaCore.Tests.Host.Provisioning;

/// <summary>
/// The bootstrap-apps.json pre-seed at its product location. These tests pin the public contract of
/// the file — the configuration key, the default path, the field names, and the fact that neither a
/// missing nor an unreadable file interrupts startup — so that moving the implementation out of the
/// migration-orchestration file cannot change what a deployment observes.
/// </summary>
public class BootstrapAppSeederTests : IDisposable
{
    private readonly IdentityDbContext _dbContext;

    public BootstrapAppSeederTests()
    {
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _dbContext = new IdentityDbContext(options);
    }

    /// <summary>
    /// Without <c>BootstrapApps:FilePath</c> the seeder falls back to the documented default path.
    /// That path does not exist in the test environment, which is the same "missing file" case: it
    /// is not an error and nothing is written.
    /// </summary>
    [Fact]
    public async Task WithoutTheConfigurationKey_TheDefaultPathIsUsedAndAMissingFileIsNotAnError()
    {
        var configuration = new ConfigurationBuilder().Build();

        await BootstrapAppSeeder.SeedBootstrapAppsAsync(
            configuration,
            _dbContext,
            NullLogger.Instance,
            isDevelopment: false);

        Assert.Empty(await _dbContext.AppRegistrations.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A file that cannot be parsed is a Warning, not a startup failure: the seeder is a
    /// convenience, and the registrations can still be created from the administration console.
    /// </summary>
    [Fact]
    public async Task AnUnparsableFile_DoesNotInterruptStartup()
    {
        await SeedAsync("{ this is not json");

        Assert.Empty(await _dbContext.AppRegistrations.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// An entry missing either credential half is skipped without touching the database, and the
    /// remaining entries in the same file are still seeded.
    /// </summary>
    [Theory]
    [InlineData("\"AppId\": \"\", \"AppSecret\": \"secret-value\"")]
    [InlineData("\"AppId\": \"incomplete-app\", \"AppSecret\": \"\"")]
    public async Task AnEntryWithoutBothCredentialHalves_IsSkipped(string credentials)
    {
        await SeedAsync($$"""
            {
              "Apps": [
                { {{credentials}}, "AppName": "Incomplete" },
                {
                  "appId": "complete-app",
                  "appSecret": "another-secret-value",
                  "appName": "Complete App",
                  "callbackUrl": "https://claims.example.test/permissions"
                }
              ]
            }
            """);

        var app = Assert.Single(await _dbContext.AppRegistrations.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal("complete-app", app.AppId);
    }

    /// <summary>
    /// The documented field names seed the documented columns, the registration is active, and the
    /// secret is stored only as a hash.
    /// </summary>
    [Fact]
    public async Task AValidEntry_SeedsTheDocumentedFields()
    {
        await SeedAsync("""
            {
              "Apps": [
                {
                  "appId": "bootstrap-seeded-app",
                  "appSecret": "bootstrap-secret-value",
                  "appName": "Bootstrap Seeded App",
                  "callbackUrl": "https://claims.example.test/permissions"
                }
              ]
            }
            """);

        var app = Assert.Single(await _dbContext.AppRegistrations.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal("bootstrap-seeded-app", app.AppId);
        Assert.Equal("Bootstrap Seeded App", app.AppName);
        Assert.Equal("https://claims.example.test/permissions", app.CallbackUrl);
        Assert.True(app.IsActive);
        Assert.NotEqual(DateTimeOffset.MinValue, app.CreatedAt);
        Assert.NotEqual("bootstrap-secret-value", app.AppSecretHash);
        Assert.True(BCrypt.Net.BCrypt.Verify("bootstrap-secret-value", app.AppSecretHash));
    }

    /// <summary>
    /// An application that already exists keeps every field it has; the file never overwrites a
    /// registration.
    /// </summary>
    [Fact]
    public async Task AnEntryForAnExistingApplication_ChangesNothing()
    {
        _dbContext.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = "existing-app",
            AppSecretHash = "hashed-secret-value",
            AppName = "Existing App",
            CallbackUrl = "https://claims.example.test/permissions",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        await _dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        _dbContext.ChangeTracker.Clear();

        await SeedAsync("""
            {
              "Apps": [
                {
                  "appId": "existing-app",
                  "appSecret": "replacement-secret",
                  "appName": "Replacement Name",
                  "callbackUrl": "https://replacement.example.test/permissions"
                }
              ]
            }
            """);

        var app = Assert.Single(await _dbContext.AppRegistrations.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal("Existing App", app.AppName);
        Assert.Equal("hashed-secret-value", app.AppSecretHash);
        Assert.Equal("https://claims.example.test/permissions", app.CallbackUrl);
    }

    public void Dispose()
    {
        _dbContext.Dispose();
        GC.SuppressFinalize(this);
    }

    private async Task SeedAsync(string json)
    {
        var path = Path.Combine(Path.GetTempPath(), $"bootstrap-apps-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path, json, TestContext.Current.CancellationToken);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["BootstrapApps:FilePath"] = path
                })
                .Build();

            await BootstrapAppSeeder.SeedBootstrapAppsAsync(
                configuration,
                _dbContext,
                NullLogger.Instance,
                isDevelopment: false);
            _dbContext.ChangeTracker.Clear();
        }
        finally
        {
            File.Delete(path);
        }
    }
}
