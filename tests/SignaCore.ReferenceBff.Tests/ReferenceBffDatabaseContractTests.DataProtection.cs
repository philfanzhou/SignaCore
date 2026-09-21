extern alias BffSample;
using System.Security.Cryptography;
using System.Xml.Linq;
using BffSample::SignaCore.ReferenceBff;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ServiceMantle;
using ServiceMantle.Persistence.EntityFrameworkCore;
using SignaCore.ReferenceBff.Database;
using Xunit;

namespace SignaCore.ReferenceBff.Tests;

public sealed partial class ReferenceBffDatabaseContractTests
{
    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task DataProtection_RealHostRestartReusesEncryptedRing(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        await using var authority = await FakeAuthority.StartAsync();
        string payload;
        await using (var host = SetupHost(database, provider, authority))
        {
            payload = host.Services.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("restart-contract").Protect(CanarySecret);
            using var scope = host.Services.CreateScope();
            var scoped = scope.ServiceProvider.GetRequiredService<ReferenceBffDbContext>();
            await using var independent = await host.Services.GetRequiredService<IDbContextFactory<ReferenceBffDbContext>>()
                .CreateDbContextAsync(TestContext.Current.CancellationToken);
            Assert.NotSame(scoped, independent);
        }
        var rows = await KeyRows(database);
        Assert.Single(rows);
        Assert.All(rows, row => Assert.True(row.StartsWith("sm:v1:", StringComparison.Ordinal)
            && !row.Contains(CanarySecret, StringComparison.Ordinal)
            && !row.Contains(BffTestServer.DatabaseRootKey, StringComparison.Ordinal)));
        await using (var restarted = SetupHost(database, provider, authority))
        {
            Assert.True(CanarySecret == restarted.Services.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("restart-contract").Unprotect(payload));
        }
        Assert.Equal(rows, await KeyRows(database));
        await using var read = database.CreateContext();
        Assert.Empty(await read.ServiceInstallations.ToListAsync(TestContext.Current.CancellationToken));
        Assert.Empty(await read.ManagementRoleBindings.ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal(0, await CountSharedAuditRowsAsync(read));
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task DataProtection_WrongRootTamperingAndCopiedServiceFailWithoutRebuilding(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        await using var authority = await FakeAuthority.StartAsync();
        string payload;
        await using (var host = SetupHost(database, provider, authority))
            payload = host.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector("failure").Protect(CanarySecret);
        var rows = await KeyRows(database);
        await using (var wrong = SetupHost(database, provider, authority).WithWebHostBuilder(builder =>
            builder.UseSetting(ReferenceBffDatabaseSetup.RootKey, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)))))
        {
            var protector = wrong.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector("failure");
            Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(payload));
            Assert.ThrowsAny<CryptographicException>(() => protector.Protect(CanarySecret));
        }
        Assert.Equal(rows, await KeyRows(database));
        await using (var edit = database.CreateContext())
            await edit.Database.ExecuteSqlRawAsync(
                "UPDATE service_data_protection_keys SET service_id = 'other-service'", TestContext.Current.CancellationToken);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDbContextFactory<ReferenceBffDbContext>>(new KeyContextFactory(database, null));
        services.AddDataProtection().SetApplicationName(ReferenceBffServiceMantle.ServiceIdValue)
            .PersistKeysToServiceMantleEfCore<ReferenceBffDbContext>(ServiceId.Parse("other-service"), _ => BffTestServer.DatabaseRootKey);
        await using (var copied = services.BuildServiceProvider())
        {
            var protector = copied.GetRequiredService<IDataProtectionProvider>().CreateProtector("failure");
            Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(payload));
            Assert.ThrowsAny<CryptographicException>(() => protector.Protect(CanarySecret));
        }
        Assert.Equal(rows, await KeyRows(database));
        await using (var edit = database.CreateContext())
            await edit.Database.ExecuteSqlRawAsync(
                "UPDATE service_data_protection_keys SET service_id = 'reference-bff', encrypted_xml = 'sm:v1:corrupted'",
                TestContext.Current.CancellationToken);
        var damaged = await KeyRows(database);
        await using (var host = SetupHost(database, provider, authority))
        {
            var protector = host.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector("failure");
            Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(payload));
            Assert.ThrowsAny<CryptographicException>(() => protector.Protect(CanarySecret));
        }
        Assert.Equal(damaged, await KeyRows(database));
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task DataProtection_FailedOrCanceledSaveLeavesNoRowsAndDoesNotCommitCaller(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        foreach (var cancel in new[] { false, true })
        {
            var fault = new KeySaveFault(cancel);
            var repository = KeyRepository(database, interceptor: fault);
            var failure = Assert.ThrowsAny<Exception>(() => repository.StoreElement(KeyElement(), "key-12345678-1234-1234-1234-123456789abc"));
            Assert.True(fault.Observed);
            Assert.False(failure.ToString().Contains(BffTestServer.DatabaseRootKey, StringComparison.Ordinal));
            await using var connectionCheck = database.CreateContext();
            Assert.False(failure.ToString().Contains(connectionCheck.Database.GetConnectionString()!, StringComparison.Ordinal));
            Assert.Empty(await KeyRows(database));
        }
        await using var caller = database.CreateContext();
        await new ManagementRoleBindingStore(caller).StageInitialAdministratorAsync(Issuer, Subject, TestContext.Current.CancellationToken);
        // Begin a deferred SQLite transaction so an independent writer can run concurrently.
        await using var transaction = provider == "SQLite"
            ? await BeginDeferred(caller)
            : await caller.Database.BeginTransactionAsync(TestContext.Current.CancellationToken);
        KeyRepository(database).StoreElement(KeyElement(), "key-12345678-1234-1234-1234-123456789abc");
        await transaction.RollbackAsync(TestContext.Current.CancellationToken);
        await using var read = database.CreateContext();
        Assert.Empty(await read.ManagementRoleBindings.ToListAsync(TestContext.Current.CancellationToken));
        Assert.Single(await KeyRows(database));
    }

    private static async Task<Microsoft.EntityFrameworkCore.Storage.IDbContextTransaction> BeginDeferred(ReferenceBffDbContext context)
    {
        await context.Database.OpenConnectionAsync(TestContext.Current.CancellationToken);
        var connection = (Microsoft.Data.Sqlite.SqliteConnection)context.Database.GetDbConnection();
        return (await context.Database.UseTransactionAsync(connection.BeginTransaction(deferred: true), TestContext.Current.CancellationToken))!;
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task DataProtection_MissingSchemaFailsAndDownOnlyRemovesKeyTable(string provider)
    {
        await using var database = await BffDatabase.CreateMigratedAsync(provider);
        await using (var context = database.CreateContext())
        {
            await new ManagementRoleBindingStore(context).StageInitialAdministratorAsync(Issuer, Subject, TestContext.Current.CancellationToken);
            await context.SaveChangesAsync(TestContext.Current.CancellationToken);
            await context.GetService<IMigrator>().MigrateAsync("AddSharedInstallationAndAudit", TestContext.Current.CancellationToken);
            Assert.Single(await context.ManagementRoleBindings.ToListAsync(TestContext.Current.CancellationToken));
            Assert.Equal(0, await CountSharedAuditRowsAsync(context));
            Assert.Empty(await context.ServiceInstallations.ToListAsync(TestContext.Current.CancellationToken));
        }
        await using var authority = await FakeAuthority.StartAsync();
        await using (var host = SetupHost(database, provider, authority))
            Assert.ThrowsAny<CryptographicException>(() => host.Services.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("missing-schema").Protect(CanarySecret));
        Assert.ThrowsAny<Exception>(() => KeyRepository(database).GetAllElements());
        Assert.ThrowsAny<Exception>(() => KeyRepository(database).StoreElement(KeyElement(), "key-12345678-1234-1234-1234-123456789abc"));
        await using var upgrade = database.CreateContext();
        await upgrade.Database.MigrateAsync(TestContext.Current.CancellationToken);
        Assert.Empty(await KeyRows(database));
    }

    [Theory]
    [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)] [InlineData(5)] [InlineData(6)]
    public void DataProtection_PartialConfigurationNeverEchoesValues(int mask)
    {
        using var configuration = new ConfigurationManager();
        configuration[ReferenceBffDatabaseSetup.ProviderKey] = (mask & 1) != 0 ? "SQLite" : null;
        configuration[ReferenceBffDatabaseSetup.ConnectionStringKey] = (mask & 2) != 0 ? CanarySecret : null;
        configuration[ReferenceBffDatabaseSetup.RootKey] = (mask & 4) != 0 ? BffTestServer.DatabaseRootKey : null;
        var failure = Assert.Throws<InvalidOperationException>(() => ReferenceBffDatabaseSetup.Read(configuration));
        Assert.True(failure.Message == "The reference BFF database configuration is invalid: ReferenceBffDatabase:Provider, "
            + "ReferenceBffDatabase:ConnectionString and ReferenceBffDatabase:DataProtectionRootKey must be provided together, and Provider must be SQLite or PostgreSQL.");
    }

    private static XElement KeyElement() => new("key", new XAttribute("id", "12345678-1234-1234-1234-123456789abc"), new XAttribute("version", "1"), CanarySecret);

    private static EfCoreDataProtectionKeyRepository<ReferenceBffDbContext> KeyRepository(
        BffDatabase database, ServiceId? id = null, IInterceptor? interceptor = null) =>
        new(new KeyContextFactory(database, interceptor), id ?? ReferenceBffServiceMantle.ServiceId, () => BffTestServer.DatabaseRootKey);

    private sealed class KeyContextFactory(BffDatabase database, IInterceptor? interceptor) : IDbContextFactory<ReferenceBffDbContext>
    {
        public ReferenceBffDbContext CreateDbContext() => interceptor is null ? database.CreateContext() : database.CreateContext(interceptor);
    }

    private sealed class KeySaveFault(bool cancel) : SaveChangesInterceptor
    {
        public bool Observed { get; private set; }
        private void Fail()
        {
            Observed = true;
            if (cancel) throw new OperationCanceledException(new CancellationToken(true));
            throw new InvalidOperationException("Synthetic key save failure.");
        }
        public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result) { Fail(); return result; }
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default) { Fail(); return ValueTask.FromResult(result); }
    }

    private static async Task<string[]> KeyRows(BffDatabase database)
    {
        await using var read = database.CreateContext();
        return await read.Database.SqlQueryRaw<string>("SELECT encrypted_xml AS \"Value\" FROM service_data_protection_keys ORDER BY service_id, key_id")
            .ToArrayAsync(TestContext.Current.CancellationToken);
    }
}
