using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services;
using Xunit;

namespace SignaCore.Tests.Domain.Services;

/// <summary>
/// The interactive refresh family write API as a unit: the <c>EV-21</c> root shape (singleton
/// family, complete interactive marker, versioned digest only, the 7-day cap), the precondition
/// discipline, the <c>EV-24</c>/<c>EV-06</c>/<c>EV-15</c> conditional whole-family revocations
/// (first fact authoritative, interactive rows only), and the child-first retention cleanup that
/// keeps a linked code's family resolvable inside the retention window.
/// </summary>
public sealed class RefreshTokenFamilyStoreTests
{
    private const string ClientId = "family-unit-app";
    private const string CanonicalScope = "openid profile offline_access";

    [Fact]
    public async Task CreateRootAsync_WritesTheCanonicalRootShapeAndReturnsThePlaintextOnce()
    {
        await using var harness = await CreateHarnessAsync();
        var now = DateTimeOffset.UtcNow;
        var authTime = now.AddMinutes(-5);
        var descriptor = new InteractiveRefreshFamilyRootDescriptor(
            harness.AccountId, ClientId, harness.SessionId, CanonicalScope, authTime);

        var creation = await harness.Store.CreateRootAsync(descriptor, now, TestContext.Current.CancellationToken);

        Assert.NotEqual(Guid.Empty, creation.RootId);
        Assert.Equal(43, creation.RefreshToken.Length);
        Assert.All(creation.RefreshToken, character =>
            Assert.True(char.IsAsciiLetterOrDigit(character) || character is '-' or '_'));
        Assert.Equal(now.AddDays(IdentityConstants.InteractiveRefreshFamilyLifetimeDays), creation.ExpiresAt);

        var root = Assert.Single(await harness.Context.RefreshTokens.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal(creation.RootId, root.Id);
        Assert.Equal(root.Id, root.FamilyId);
        Assert.Null(root.ParentId);
        Assert.Null(root.LdapCredentialId);
        Assert.Null(root.SmsUserLoginId);
        Assert.Null(root.WechatUserLoginId);
        Assert.Null(root.SourceAppId);
        Assert.Null(root.ConsumedAt);
        Assert.False(root.IsRevoked);
        Assert.Equal(harness.AccountId, root.AccountId);
        Assert.Equal(ClientId, root.AppId);
        Assert.Equal(harness.SessionId, root.IdentitySessionId);
        Assert.Equal(CanonicalScope, root.Scope);
        // Both providers persist timestamps with microsecond precision; compare at that
        // contract rather than the raw 100ns clock ticks.
        Assert.Equal(authTime.UtcTicks / 10, root.AuthTime!.Value.UtcTicks / 10);
        Assert.Equal(creation.ExpiresAt.UtcTicks / 10, root.ExpiresAt.UtcTicks / 10);
        // DF-09: only the versioned digest is persisted; the plaintext never touches the row.
        Assert.Equal(RefreshTokenDigest.Compute(creation.RefreshToken), root.TokenValue);
        Assert.DoesNotContain(creation.RefreshToken, root.TokenValue, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateRootAsync_RejectsInvalidDescriptorsWithoutEchoingValues()
    {
        await using var harness = await CreateHarnessAsync();
        var now = DateTimeOffset.UtcNow;
        var descriptor = new InteractiveRefreshFamilyRootDescriptor(
            harness.AccountId, ClientId, harness.SessionId, CanonicalScope, now);

        var cases = new Func<InteractiveRefreshFamilyRootDescriptor>[]
        {
            () => descriptor with { AccountId = Guid.Empty },
            () => descriptor with { IdentitySessionId = Guid.Empty },
            () => descriptor with { AppId = "" },
            () => descriptor with { Scope = "profile" }
        };

        foreach (var build in cases)
        {
            var exception = await Assert.ThrowsAnyAsync<ArgumentException>(() =>
                harness.Store.CreateRootAsync(build(), now, TestContext.Current.CancellationToken));
            Assert.DoesNotContain(CanonicalScope, exception.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(ClientId, exception.Message, StringComparison.Ordinal);
        }

        Assert.Empty(await harness.Context.RefreshTokens.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RevokeFamilyAsync_RevokesOnlyTheNamedInteractiveFamilyAndKeepsTheFirstFact()
    {
        await using var harness = await CreateHarnessAsync();
        var (rootId, siblingId, legacyId, childId) = await SeedFamiliesAsync(harness);

        // First call revokes the named family (root + child); the sibling and the legacy row stay.
        Assert.Equal(2, await harness.Store.RevokeFamilyAsync(
            rootId, RefreshFamilyRevocationReason.CodeReplay, TestContext.Current.CancellationToken));

        var revoked = await harness.Context.RefreshTokens.AsNoTracking()
            .Where(row => row.IsRevoked)
            .Select(row => row.Id)
            .ToListAsync(TestContext.Current.CancellationToken);
        Assert.Equal(
            new[] { rootId, childId }.OrderBy(id => id),
            revoked.OrderBy(id => id));

        // A second call is a no-op — the first revocation fact stays authoritative.
        Assert.Equal(0, await harness.Store.RevokeFamilyAsync(
            rootId, RefreshFamilyRevocationReason.Logout, TestContext.Current.CancellationToken));

        _ = (siblingId, legacyId);
    }

    [Fact]
    public async Task RevokeBySessionAsync_RevokesEveryInteractiveFamilyOfTheSession()
    {
        await using var harness = await CreateHarnessAsync();
        var (rootId, siblingId, legacyId, childId) = await SeedFamiliesAsync(harness);

        Assert.Equal(3, await harness.Store.RevokeBySessionAsync(
            harness.SessionId, RefreshFamilyRevocationReason.Administrative, TestContext.Current.CancellationToken));

        var survivors = await harness.Context.RefreshTokens.AsNoTracking()
            .Where(row => !row.IsRevoked)
            .Select(row => row.Id)
            .ToListAsync(TestContext.Current.CancellationToken);
        // Only the legacy row — structurally out of reach of the session predicate — survives.
        Assert.Equal([legacyId], survivors);

        _ = (rootId, siblingId, childId);
    }

    [Fact]
    public async Task CleanupExpiredAsync_RemovesWholeExpiredFamiliesChildFirstAndKeepsLinkedOnes()
    {
        await using var harness = await CreateHarnessAsync();
        var cancellationToken = TestContext.Current.CancellationToken;
        var now = DateTimeOffset.UtcNow;
        var expiredFamilyRoot = Guid.NewGuid();
        var expiredFamilyChild = Guid.NewGuid();
        await InsertInteractiveMemberAsync(harness.Context,
            expiredFamilyRoot, expiredFamilyRoot, parentId: null, harness, now.AddHours(-3), now.AddHours(-1));
        await InsertInteractiveMemberAsync(harness.Context,
            expiredFamilyChild, expiredFamilyRoot, parentId: expiredFamilyRoot, harness, now.AddHours(-3), now.AddHours(-1));

        // A live family: past nothing, stays whole.
        var liveRoot = Guid.NewGuid();
        await InsertInteractiveMemberAsync(harness.Context,
            liveRoot, liveRoot, parentId: null, harness, now, now.AddDays(7));

        // An expired family whose root a retained (consumed) code still links: stays resolvable.
        var linkedRoot = Guid.NewGuid();
        await InsertInteractiveMemberAsync(harness.Context,
            linkedRoot, linkedRoot, parentId: null, harness, now.AddHours(-3), now.AddHours(-1));
        var applicationRowId = harness.Context.AppRegistrations.Single().Id;
        harness.Context.AuthorizationCodes.Add(new AuthorizationCodeEntity
        {
            Id = Guid.NewGuid(),
            CodeDigest = AuthorizationCodeDigest.Compute("family-cleanup-code-0123456789ab"),
            AppRegistrationId = applicationRowId,
            AccountId = harness.AccountId,
            IdentitySessionId = harness.SessionId,
            RedirectUri = "https://client.example.test/callback",
            Scope = CanonicalScope,
            Nonce = "family-cleanup-nonce",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            AuthTime = now,
            CreatedAt = now.AddHours(-2),
            ExpiresAt = now.AddHours(-2).AddMinutes(1),
            ConsumedAt = now.AddHours(-2),
            RefreshFamilyId = linkedRoot
        });
        await harness.Context.SaveChangesAsync(cancellationToken);
        harness.Context.ChangeTracker.Clear();

        var deleted = await harness.Store.CleanupExpiredAsync(now, cancellationToken);

        Assert.Equal(2, deleted);
        var remaining = await harness.Context.RefreshTokens.AsNoTracking()
            .Select(row => row.Id)
            .ToListAsync(cancellationToken);
        Assert.Equal(
            new[] { liveRoot, linkedRoot }.OrderBy(id => id),
            remaining.OrderBy(id => id));
    }

    // ---- Harness ----

    private sealed record Harness(
        SqliteConnection Connection,
        IdentityDbContext Context,
        RefreshTokenFamilyStore Store,
        Guid AccountId,
        Guid SessionId) : IAsyncDisposable
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

        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = Guid.NewGuid(),
            AppId = ClientId,
            AppSecretHash = "hash",
            AppName = "Family Unit Client",
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        });
        context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = DateTimeOffset.UtcNow });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = credentialId,
            AccountId = accountId,
            Username = "family_unit_user",
            PasswordHash = "hash",
            CreatedAt = DateTimeOffset.UtcNow
        });
        await context.SaveChangesAsync(TestContext.Current.CancellationToken);
        context.ChangeTracker.Clear();

        var unitOfWork = new EfCoreUnitOfWork(context);
        var sessions = new IdentitySessionStore(new IdentitySessionRepository(context), unitOfWork);
        var session = await sessions.CreateAsync(accountId, credentialId, DateTimeOffset.UtcNow, TestContext.Current.CancellationToken);

        var store = new RefreshTokenFamilyStore(
            new RefreshTokenRepository(context), unitOfWork, NullLogger<RefreshTokenFamilyStore>.Instance);
        return new Harness(connection, context, store, accountId, session.Id);
    }

    /// <summary>Two interactive families of one session (root + child, and a sibling root) plus a legacy row.</summary>
    private static async Task<(Guid RootId, Guid SiblingId, Guid LegacyId, Guid ChildId)> SeedFamiliesAsync(
        Harness harness)
    {
        var now = DateTimeOffset.UtcNow;
        var rootId = Guid.NewGuid();
        var childId = Guid.NewGuid();
        var siblingId = Guid.NewGuid();
        var legacyId = Guid.NewGuid();
        await InsertInteractiveMemberAsync(harness.Context, rootId, rootId, null, harness, now, now.AddDays(7));
        await InsertInteractiveMemberAsync(harness.Context, childId, rootId, rootId, harness, now, now.AddDays(7));
        await InsertInteractiveMemberAsync(harness.Context, siblingId, siblingId, null, harness, now, now.AddDays(7));
        harness.Context.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = legacyId,
            FamilyId = legacyId,
            AccountId = harness.AccountId,
            TokenValue = RefreshTokenDigest.Compute("family-unit-legacy-token"),
            CreatedAt = now,
            ExpiresAt = now.AddDays(7),
            AppId = ClientId
        });
        await harness.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        harness.Context.ChangeTracker.Clear();
        return (rootId, siblingId, legacyId, childId);
    }

    private static async Task InsertInteractiveMemberAsync(
        IdentityDbContext context,
        Guid id,
        Guid familyId,
        Guid? parentId,
        Harness harness,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        context.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = id,
            FamilyId = familyId,
            ParentId = parentId,
            AccountId = harness.AccountId,
            TokenValue = RefreshTokenDigest.Compute("family-unit-member-" + id.ToString("N")),
            CreatedAt = createdAt,
            ExpiresAt = expiresAt,
            AppId = ClientId,
            IdentitySessionId = harness.SessionId,
            Scope = CanonicalScope,
            AuthTime = createdAt
        });
    }
}
