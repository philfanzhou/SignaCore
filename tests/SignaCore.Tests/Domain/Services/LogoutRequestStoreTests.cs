using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

/// <summary>
/// The <c>PS-08</c> store as a unit: the digest-only five-minute row, the single "unavailable"
/// answer of every unusable handle, the conditional one-time consumption, and retention cleanup.
/// </summary>
public sealed class LogoutRequestStoreTests
{
    [Fact]
    public async Task CreateAsync_StoresOnlyTheDigestAndTheFiveMinuteLifecycle()
    {
        await using var harness = await CreateHarnessAsync();
        var now = DateTimeOffset.UtcNow;
        var descriptor = new LogoutRequestDescriptor(
            harness.ApplicationId, Guid.NewGuid(), Guid.NewGuid(),
            "https://bff.unit.test/logged-out", "unit-state-0123456789abcdef");

        var creation = await harness.Store.CreateAsync(descriptor, now, TestContext.Current.CancellationToken);

        Assert.NotEqual(Guid.Empty, creation.Id);
        Assert.Equal(43, creation.LogoutHandle.Length);
        Assert.All(creation.LogoutHandle, character =>
            Assert.True(char.IsAsciiLetterOrDigit(character) || character is '-' or '_'));

        var row = Assert.Single(await harness.Context.LogoutRequests.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal(descriptor.ApplicationId, row.AppRegistrationId);
        Assert.Equal(descriptor.AccountId, row.AccountId);
        Assert.Equal(descriptor.IdentitySessionId, row.IdentitySessionId);
        Assert.Equal(descriptor.VerifiedPostLogoutRedirectUri, row.PostLogoutRedirectUri);
        Assert.Equal(descriptor.State, row.State);
        // Both providers persist timestamps with microsecond precision; compare at that
        // contract rather than the raw 100ns clock ticks.
        Assert.Equal(now.UtcTicks / 10, row.CreatedAt.UtcTicks / 10);
        Assert.Equal(
            now.AddMinutes(IdentityConstants.LogoutHandleLifetimeMinutes).UtcTicks / 10,
            row.ExpiresAt.UtcTicks / 10);
        Assert.Null(row.ConsumedAt);
        // DF-10: only the versioned digest is persisted; the plaintext handle never touches the row.
        Assert.Equal(LoginHandleDigest.Compute(creation.LogoutHandle), row.HandleDigest);
        Assert.DoesNotContain(creation.LogoutHandle, row.HandleDigest, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetActiveAsync_AnswersNullForEveryUnusableHandle()
    {
        await using var harness = await CreateHarnessAsync();
        var now = DateTimeOffset.UtcNow;
        var creation = await harness.Store.CreateAsync(
            Descriptor(harness), now, TestContext.Current.CancellationToken);

        // Usable now.
        Assert.NotNull(await harness.Store.GetActiveAsync(
            creation.LogoutHandle, now.AddSeconds(1), TestContext.Current.CancellationToken));

        // Expired: the boundary is inclusive — the operation instant at the deadline is past it.
        Assert.Null(await harness.Store.GetActiveAsync(
            creation.LogoutHandle,
            now.AddMinutes(IdentityConstants.LogoutHandleLifetimeMinutes),
            TestContext.Current.CancellationToken));

        // Consumed.
        Assert.True(await harness.Store.TryConsumeAsync(
            creation.LogoutHandle, now.AddSeconds(1), TestContext.Current.CancellationToken));
        Assert.Null(await harness.Store.GetActiveAsync(
            creation.LogoutHandle, now.AddSeconds(2), TestContext.Current.CancellationToken));

        // Missing and malformed share the single answer and never become a query key.
        Assert.Null(await harness.Store.GetActiveAsync(
            new string('z', 43), now, TestContext.Current.CancellationToken));
        Assert.Null(await harness.Store.GetActiveAsync(
            "short", now, TestContext.Current.CancellationToken));
        Assert.Null(await harness.Store.GetActiveAsync(
            new string('z', 42) + "!", now, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TryConsumeAsync_IsExactlyOnce()
    {
        await using var harness = await CreateHarnessAsync();
        var now = DateTimeOffset.UtcNow;
        var creation = await harness.Store.CreateAsync(
            Descriptor(harness), now, TestContext.Current.CancellationToken);

        Assert.True(await harness.Store.TryConsumeAsync(
            creation.LogoutHandle, now.AddSeconds(1), TestContext.Current.CancellationToken));
        Assert.False(await harness.Store.TryConsumeAsync(
            creation.LogoutHandle, now.AddSeconds(2), TestContext.Current.CancellationToken));

        var row = Assert.Single(await harness.Context.LogoutRequests.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.NotNull(row.ConsumedAt);
    }

    [Fact]
    public async Task CleanupExpiredAsync_KeepsRowsInsideTheRetentionWindow()
    {
        await using var harness = await CreateHarnessAsync();
        var now = DateTimeOffset.UtcNow;
        var fresh = await harness.Store.CreateAsync(Descriptor(harness), now, TestContext.Current.CancellationToken);
        var old = await harness.Store.CreateAsync(
            Descriptor(harness),
            now.AddHours(-IdentityConstants.LogoutRequestRetentionHours).AddMinutes(-10),
            TestContext.Current.CancellationToken);

        var deleted = await harness.Store.CleanupExpiredAsync(now, TestContext.Current.CancellationToken);

        Assert.Equal(1, deleted);
        var remaining = await harness.Context.LogoutRequests.AsNoTracking()
            .Select(row => row.HandleDigest).ToListAsync(TestContext.Current.CancellationToken);
        Assert.Equal([LoginHandleDigest.Compute(fresh.LogoutHandle)], remaining);
        _ = old;
    }

    private static LogoutRequestDescriptor Descriptor(Harness harness) =>
        new(harness.ApplicationId, Guid.NewGuid(), Guid.NewGuid(), null, null);

    private sealed record Harness(
        SqliteConnection Connection,
        IdentityDbContext Context,
        LogoutRequestStore Store,
        Guid ApplicationId) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }

    private static async Task<Harness> CreateHarnessAsync()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var context = new IdentityDbContext(new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(connection).Options);
        await context.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);

        // The restrictive client reference needs a real application row.
        var applicationId = Guid.NewGuid();
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = applicationId,
            AppId = "logout-store-unit-app",
            AppSecretHash = "hash",
            AppName = "Logout Store Unit App",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();

        var unitOfWork = new EfCoreUnitOfWork(context);
        var store = new LogoutRequestStore(new LogoutRequestRepository(context), unitOfWork);
        return new Harness(connection, context, store, applicationId);
    }
}
