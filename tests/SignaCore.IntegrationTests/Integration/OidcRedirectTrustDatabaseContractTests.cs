using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Validators;
using SignaCore.Host.Services;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Tests.Integration;

public sealed class OidcRedirectTrustDatabaseContractTests
{
    private const string Redirect = "http://10.20.30.40:5008/callback";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static OidcRedirectUriPolicy Policy => OidcRedirectUriPolicy.Default;

    [Fact]
    public async Task Sqlite_TransactionRechecksExactRegistrationAndPolicy_AndPreservesCancellation()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(Ct);
        var options = new DbContextOptionsBuilder<IdentityDbContext>().UseSqlite(connection).Options;
        await using var db = new IdentityDbContext(options);
        await db.Database.EnsureCreatedAsync(Ct);
        var app = await SeedAsync(db);
        await using var transaction = await db.Database.BeginTransactionAsync(Ct);
        Assert.True(await AllowsAsync(db, app));
        Assert.False(await OidcCurrentRedirectTrust.AllowsAsync(db, app, RedirectUriKind.Redirect, Redirect + "/", Policy, Ct));
        await db.AppRedirectUris.ExecuteDeleteAsync(Ct);
        Assert.False(await AllowsAsync(db, app));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => OidcCurrentRedirectTrust.AllowsAsync(db, app, RedirectUriKind.Redirect, Redirect, Policy, cancelled.Token));
        Assert.Equal(cancelled.Token, error.CancellationToken);
        await transaction.RollbackAsync(Ct);
    }

    [Fact]
    public async Task PostgreSql_RegisteredUriRemovalSerializesWithLockedTrust_InBothOrders()
    {
        Assert.SkipUnless(Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS") == "true", "Set RUN_SIGNACORE_DATABASE_CONTRACTS=true to run the PostgreSQL redirect trust contract.");
        await using var container = new PostgreSqlBuilder(Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") ?? "postgres:15-alpine").Build();
        await container.StartAsync(Ct);
        var options = new DbContextOptionsBuilder<IdentityDbContext>().UseNpgsql(container.GetConnectionString()).Options;
        await using var first = new IdentityDbContext(options);
        await first.Database.MigrateAsync(Ct);
        var app = await SeedAsync(first);
        await using var transaction = await first.Database.BeginTransactionAsync(Ct);
        Assert.True(await AllowsAsync(first, app));
        await using var remover = new IdentityDbContext(options);
        var deletion = remover.AppRedirectUris.Where(x => x.AppRegistrationId == app).ExecuteDeleteAsync(Ct);
        await using var observer = new NpgsqlConnection(container.GetConnectionString());
        await observer.OpenAsync(Ct);
        var deadline = DateTime.UtcNow.AddSeconds(10);
        var waited = false;
        while (DateTime.UtcNow < deadline)
        {
            await using var query = new NpgsqlCommand("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%DELETE%')", observer);
            if ((bool)(await query.ExecuteScalarAsync(Ct))!) { waited = true; break; }
            await Task.Delay(25, Ct);
        }
        Assert.True(waited);
        Assert.False(deletion.IsCompleted);
        await transaction.CommitAsync(Ct);
        Assert.Equal(1, await deletion);
        await using var next = new IdentityDbContext(options);
        await using var nextTransaction = await next.Database.BeginTransactionAsync(Ct);
        Assert.False(await AllowsAsync(next, app));
        await nextTransaction.RollbackAsync(Ct);
    }

    private static Task<bool> AllowsAsync(IdentityDbContext db, Guid app) => OidcCurrentRedirectTrust.AllowsAsync(db, app, RedirectUriKind.Redirect, Redirect, Policy, Ct);
    private static async Task<Guid> SeedAsync(IdentityDbContext db)
    {
        var app = new AppRegistrationEntity { Id = Guid.NewGuid(), AppId = "http-lock-client", IsActive = true, CreatedAt = DateTimeOffset.UtcNow };
        app.RedirectUris.Add(new() { Id = Guid.NewGuid(), AppRegistrationId = app.Id, Kind = RedirectUriKind.Redirect, CanonicalUri = Redirect });
        db.AppRegistrations.Add(app);
        await db.SaveChangesAsync(Ct);
        return app.Id;
    }
}
