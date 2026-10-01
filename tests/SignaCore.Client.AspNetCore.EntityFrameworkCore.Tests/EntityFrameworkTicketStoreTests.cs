using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.Internal;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SignaCore.Client.AspNetCore;
using SignaCore.Client.AspNetCore.EntityFrameworkCore;
using Testcontainers.PostgreSql;
using Xunit;

namespace SignaCore.Client.AspNetCore.EntityFrameworkCore.Tests;

/// <summary>
/// The persistence contracts of the EF ticket store on both of SignaCore's own providers:
/// round-trip fidelity, expiry reclamation, revocation (plain and atomic-take), concurrent
/// revocation, restart recovery, corrupt records, and key-ring rotation — plus the proofs that
/// the database never holds a plaintext key or token and that failures surface as bounded log
/// categories instead of SQL or connection details. SQLite runs everywhere; PostgreSQL joins
/// through the container matrix gated by <c>RUN_SIGNACORE_DATABASE_CONTRACTS=true</c>, which the
/// CI database-contract job selects.
/// </summary>
public sealed partial class EntityFrameworkTicketStoreTests
{
    private const string Issuer = "https://identity.example.test/";
    private const string Subject = "order-manager-3f9c1d2b8e";
    private const string AccessToken = "synthetic-access-token-481c2b6d";
    private const string IdToken = "synthetic-id-token-9a3e5f7c";
    private const string OtherSubject = "another-manager-77b2c4d6";

    private static readonly string PostgreSqlImage =
        Environment.GetEnvironmentVariable("SIGNACORE_POSTGRES_IMAGE") is { Length: > 0 } image
            ? image
            : "postgres:15-alpine";

    private static bool ShouldRunContainerMatrix() =>
        string.Equals(
            Environment.GetEnvironmentVariable("RUN_SIGNACORE_DATABASE_CONTRACTS"),
            "true",
            StringComparison.OrdinalIgnoreCase);

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task StoreAndRetrieve_RoundTripsTheTicketExactly(string provider)
    {
        await using var database = await TicketStoreDatabase.CreateAsync(provider);
        var (store, _, capture) = database.BuildStore();

        var key = await StoreFreshSessionAsync(store);
        Assert.NotNull(key);

        var retrieved = await store.RetrieveAsync(key!, TestContext.Current.CancellationToken);
        Assert.NotNull(retrieved);
        Assert.Equal(Subject, retrieved!.Principal.FindFirst("sub")?.Value);
        Assert.Equal(Issuer, retrieved.Principal.FindFirst("iss")?.Value);
        Assert.Equal("order_manager", retrieved.Principal.FindFirst(ClaimTypes.Name)?.Value);
        Assert.True(retrieved.Principal.Identity?.IsAuthenticated);
        Assert.Equal(AccessToken, retrieved.AccessToken);
        Assert.Equal(IdToken, retrieved.IdToken);
        Assert.Equal(TimeSpan.FromMinutes(15), retrieved.ExpiresUtc - retrieved.IssuedUtc);
        Assert.Empty(capture.StoreLines);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task AnExpiredTicket_IsReclaimedOnReadAndByTheSweep(string provider)
    {
        await using var database = await TicketStoreDatabase.CreateAsync(provider);
        var time = new ManualTimeProvider();
        var (store, _, _) = database.BuildStore(timeProvider: time);

        var key = await StoreFreshSessionAsync(store);
        Assert.NotNull(key);

        time.Advance(TimeSpan.FromMinutes(16));
        Assert.Null(await store.RetrieveAsync(key!, TestContext.Current.CancellationToken));
        // The read reclaimed the row: nothing is left for the sweep.
        Assert.Equal(0, store.RemoveExpired(TestContext.Current.CancellationToken));

        var secondKey = await StoreFreshSessionAsync(store);
        Assert.NotNull(secondKey);
        time.Advance(TimeSpan.FromMinutes(16));
        Assert.Equal(1, store.RemoveExpired(TestContext.Current.CancellationToken));
        Assert.Null(await store.RetrieveAsync(secondKey!, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task Revocation_MakesTheKeyImmediatelyUnusable(string provider)
    {
        await using var database = await TicketStoreDatabase.CreateAsync(provider);
        var (store, _, _) = database.BuildStore();

        var key = await StoreFreshSessionAsync(store);
        Assert.NotNull(key);

        await store.RemoveAsync(key!, TestContext.Current.CancellationToken);
        Assert.Null(await store.RetrieveAsync(key!, TestContext.Current.CancellationToken));

        // An unknown key stays a non-error.
        await store.RemoveAsync(key!, TestContext.Current.CancellationToken);
        await store.RemoveAsync("never-issued-key", TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task ConcurrentAtomicTakes_HandExactlyOneRevokerTheSnapshot(string provider)
    {
        await using var database = await TicketStoreDatabase.CreateAsync(provider);
        var (store, _, _) = database.BuildStore();

        var key = await StoreFreshSessionAsync(store);
        Assert.NotNull(key);

        var revokers = Enumerable.Range(0, 8)
            .Select(_ => store.TakeAsync(key!, TestContext.Current.CancellationToken))
            .ToArray();
        var snapshots = await Task.WhenAll(revokers);

        var handed = snapshots.Where(snapshot => snapshot is not null).ToArray();
        var snapshot = Assert.Single(handed);
        Assert.Equal(AccessToken, snapshot!.AccessToken);
        Assert.Equal(IdToken, snapshot.IdToken);
        Assert.Equal(Subject, snapshot.Principal.FindFirst("sub")?.Value);

        Assert.Null(await store.RetrieveAsync(key!, TestContext.Current.CancellationToken));
        Assert.Equal(0, await CountRowsAsync(database));
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task ConcurrentPlainRevocations_AllCompleteAndDeleteTheRowOnce(string provider)
    {
        await using var database = await TicketStoreDatabase.CreateAsync(provider);
        var (store, _, _) = database.BuildStore();

        var key = await StoreFreshSessionAsync(store);
        Assert.NotNull(key);

        var revocations = Enumerable.Range(0, 8)
            .Select(_ => store.RemoveAsync(key!, TestContext.Current.CancellationToken))
            .ToArray();
        await Task.WhenAll(revocations);

        Assert.Equal(0, await CountRowsAsync(database));
        Assert.Null(await store.RetrieveAsync(key!, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task ASession_SurvivesAStoreRebuildAgainstTheSameDatabase(string provider)
    {
        await using var database = await TicketStoreDatabase.CreateAsync(provider);
        var (firstStore, services, _) = database.BuildStore();

        var key = await StoreFreshSessionAsync(firstStore);
        Assert.NotNull(key);
        await services.DisposeAsync();

        // A fresh process: new service provider, same database file or container, same key ring
        // directory — exactly what a restart or a second replica sees.
        var (secondStore, secondServices, _) = database.BuildStore();
        await using var _ = secondServices;
        var retrieved = await secondStore.RetrieveAsync(key!, TestContext.Current.CancellationToken);
        Assert.NotNull(retrieved);
        Assert.Equal(Subject, retrieved!.Principal.FindFirst("sub")?.Value);
        Assert.Equal(AccessToken, retrieved.AccessToken);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task ACorruptRecord_FailsClosedAndIsRemovedWithoutTouchingOtherSessions(string provider)
    {
        await using var database = await TicketStoreDatabase.CreateAsync(provider);
        var (store, _, capture) = database.BuildStore();

        var healthy = await StoreFreshSessionAsync(store, Subject);
        var corrupt = await StoreFreshSessionAsync(store, OtherSubject);
        Assert.NotNull(healthy);
        Assert.NotNull(corrupt);
        Assert.Equal(2, await CountRowsAsync(database));

        await CorruptPayloadAsync(database, corrupt!);

        Assert.Null(await store.RetrieveAsync(corrupt!, TestContext.Current.CancellationToken));
        Assert.Contains(
            capture.StoreLines,
            line => line.Contains("ticket_record_corrupt", StringComparison.Ordinal));

        // The corrupt row is gone; the untouched session still works.
        Assert.Equal(1, await CountRowsAsync(database));
        var survivor = await store.RetrieveAsync(healthy!, TestContext.Current.CancellationToken);
        Assert.NotNull(survivor);
        Assert.Equal(Subject, survivor!.Principal.FindFirst("sub")?.Value);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task ARotatedKeyRing_FailsClosedWithTheBoundedCategory(string provider)
    {
        // The key ring lives in a directory the first store's provider used; the second store's
        // provider uses a different one, which is the observed shape of a rotated-away ring.
        await using var database = await TicketStoreDatabase.CreateAsync(provider);
        var (firstStore, firstServices, _) = database.BuildStore(keyRing: database.KeyRingA);
        var key = await StoreFreshSessionAsync(firstStore);
        Assert.NotNull(key);
        await firstServices.DisposeAsync();

        var (secondStore, secondServices, capture) = database.BuildStore(keyRing: database.KeyRingB);
        await using var _ = secondServices;

        Assert.Null(await secondStore.RetrieveAsync(key!, TestContext.Current.CancellationToken));
        Assert.Contains(
            capture.StoreLines,
            line => line.Contains("ticket_record_corrupt", StringComparison.Ordinal));

        // The rotated store can still run its own sessions.
        var fresh = await StoreFreshSessionAsync(secondStore);
        Assert.NotNull(fresh);
        var retrieved = await secondStore.RetrieveAsync(fresh!, TestContext.Current.CancellationToken);
        Assert.NotNull(retrieved);
    }

    [Theory]
    [InlineData("SQLite")]
    [InlineData("PostgreSQL")]
    public async Task APersistedStore_FailsClosedWhenTheDatabaseIsUnreachable(string provider)
    {
        await using var database = await TicketStoreDatabase.CreateAsync(provider);
        var (store, _, capture) = database.BuildStore(broken: true);

        var ticket = NewTicket(Subject);
        Assert.Null(await store.StoreAsync(ticket, TestContext.Current.CancellationToken));
        Assert.Null(await store.RetrieveAsync("any-key", TestContext.Current.CancellationToken));
        await store.RemoveAsync("any-key", TestContext.Current.CancellationToken);
        Assert.Equal(0, store.RemoveExpired(TestContext.Current.CancellationToken));

        var logText = string.Join(Environment.NewLine, capture.StoreLines);
        Assert.Contains("ticket_store_unavailable", logText, StringComparison.Ordinal);
        // The bounded categories carry no SQL and no connection details.
        Assert.DoesNotContain("SELECT", logText, StringComparison.Ordinal);
        Assert.DoesNotContain("DELETE", logText, StringComparison.Ordinal);
        Assert.DoesNotContain("Host=", logText, StringComparison.Ordinal);
        Assert.DoesNotContain("Data Source", logText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheDatabase_NeverHoldsAPlaintextKeyTokenOrPrincipal()
    {
        await using var database = await TicketStoreDatabase.CreateAsync("SQLite");
        var (store, _, _) = database.BuildStore();

        var key = await StoreFreshSessionAsync(store);
        Assert.NotNull(key);

        var dump = await database.DumpAllRowsAsTextAsync();
        Assert.DoesNotContain(key!, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(AccessToken, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(IdToken, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(Subject, dump, StringComparison.Ordinal);
        Assert.DoesNotContain(Issuer, dump, StringComparison.Ordinal);
    }

    [Fact]
    public void TheModelBuilder_RegistersTheExpectedProviderNeutralShape()
    {
        using var context = TicketStoreDatabase.CreateSchemaOnlyContext();
        var entityType = context.Model.FindEntityType(typeof(SignaCoreSessionTicketEntity));
        Assert.NotNull(entityType);
        Assert.Equal(
            SignaCoreTicketStoreModelBuilderExtensions.TableName,
            entityType!.GetTableName());
        Assert.Equal("KeyDigest", entityType.FindPrimaryKey()!.Properties.Single().Name);
        Assert.Contains(
            entityType.GetIndexes(),
            index => index.Properties.Single().Name == "ExpiresUtc");
        // The digest column is bounded so both providers see the same shape.
        Assert.Equal(
            64,
            entityType.FindProperty(nameof(SignaCoreSessionTicketEntity.KeyDigest))!
                .GetMaxLength());
    }

    private static async Task<string?> StoreFreshSessionAsync(
        ITicketStore store,
        string subject = Subject)
    {
        var key = await store.StoreAsync(NewTicket(subject), TestContext.Current.CancellationToken);
        Assert.NotNull(key);
        return key;
    }

    private static SignaCoreSessionTicket NewTicket(string subject) =>
        new(
            new ClaimsPrincipal(new ClaimsIdentity(
                new[]
                {
                    new Claim("sub", subject),
                    new Claim("iss", Issuer),
                    new Claim(ClaimTypes.Name, "order_manager")
                },
                "SignaCoreHostedLogin")),
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddMinutes(15),
            AccessToken,
            IdToken);

    private static async Task<int> CountRowsAsync(TicketStoreDatabase database)
    {
        await using var context = database.CreateContext();
        return await context.Set<SignaCoreSessionTicketEntity>()
            .CountAsync(TestContext.Current.CancellationToken);
    }

    private static async Task CorruptPayloadAsync(TicketStoreDatabase database, string key)
    {
        await using var context = database.CreateContext();
        var entity = await context.Set<SignaCoreSessionTicketEntity>()
            .SingleAsync(
                ticket => ticket.KeyDigest == Convert.ToBase64String(
                    System.Security.Cryptography.SHA256.HashData(
                        System.Text.Encoding.ASCII.GetBytes(key))),
                TestContext.Current.CancellationToken);
        entity.Payload = "not-a-protected-payload"u8.ToArray();
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    /// <summary>A test-controlled clock for expiry decisions.</summary>
    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _utcNow = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan duration) => _utcNow += duration;
    }
}
