using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
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

    /// <summary>
    /// Ordinary revoke diagnostics carry no account or session identity (canonical DF-06): the
    /// captured logger sees neither the raw id nor any common Guid rendering of it — in the
    /// formatter text or in the structured state values themselves — while the repository still
    /// receives the exact id and the caller's original token, and the success log keeps only the
    /// fixed operation, the count, and the closed-set reason.
    /// </summary>
    [Fact]
    public async Task RevokeByAccountAndSession_LogNoIdentityInStructuredStateOrText()
    {
        var accountId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        Assert.NotEqual(accountId, sessionId);
        var cancellationToken = TestContext.Current.CancellationToken;
        var repository = new Mock<IRefreshTokenRepository>();
        repository
            .Setup(value => value.RevokeByAccountAsync(accountId, cancellationToken))
            .ReturnsAsync(3);
        repository
            .Setup(value => value.RevokeBySessionAsync(sessionId, cancellationToken))
            .ReturnsAsync(2);
        var logger = new StructuredStateLogger();
        var store = new RefreshTokenFamilyStore(repository.Object, new Mock<IUnitOfWork>().Object, logger);

        Assert.Equal(3, await store.RevokeByAccountAsync(
            accountId, RefreshFamilyRevocationReason.Administrative, cancellationToken));
        Assert.Equal(2, await store.RevokeBySessionAsync(
            sessionId, RefreshFamilyRevocationReason.Logout, cancellationToken));

        Assert.Equal(2, logger.Entries.Count);
        foreach (var entry in logger.Entries)
        {
            Assert.DoesNotContain(accountId.ToString("D"), entry.Text, StringComparison.Ordinal);
            Assert.DoesNotContain(accountId.ToString("N"), entry.Text, StringComparison.Ordinal);
            Assert.DoesNotContain(sessionId.ToString("D"), entry.Text, StringComparison.Ordinal);
            Assert.DoesNotContain(sessionId.ToString("N"), entry.Text, StringComparison.Ordinal);
            foreach (var field in entry.State)
            {
                Assert.DoesNotContain("AccountId", field.Key, StringComparison.Ordinal);
                Assert.DoesNotContain("SessionId", field.Key, StringComparison.Ordinal);
                var value = field.Value?.ToString();
                Assert.DoesNotContain(accountId.ToString("D"), value, StringComparison.Ordinal);
                Assert.DoesNotContain(accountId.ToString("N"), value, StringComparison.Ordinal);
                Assert.DoesNotContain(sessionId.ToString("D"), value, StringComparison.Ordinal);
                Assert.DoesNotContain(sessionId.ToString("N"), value, StringComparison.Ordinal);
            }

            // The success projection is bounded: the fixed message, the affected count, and the
            // reason — no hashed or otherwise derived identity substitute either.
            var keys = entry.State.Select(field => field.Key).ToList();
            Assert.Contains("Count", keys);
            Assert.Contains("Reason", keys);
            Assert.True(keys.TrueForAll(key =>
                key is "Count" or "Reason" or "{OriginalFormat}"));
        }

        repository.Verify(value => value.RevokeByAccountAsync(accountId, cancellationToken), Times.Once);
        repository.Verify(value => value.RevokeBySessionAsync(sessionId, cancellationToken), Times.Once);
    }

    /// <summary>
    /// A revoke that affects nothing stays silent: a zero count adds no success log, and the
    /// result still returns the repository's count unchanged.
    /// </summary>
    [Fact]
    public async Task RevokeByAccountAndSession_WhenNothingMatches_WriteNoSuccessLog()
    {
        var accountId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var cancellationToken = TestContext.Current.CancellationToken;
        var repository = new Mock<IRefreshTokenRepository>();
        repository
            .Setup(value => value.RevokeByAccountAsync(accountId, cancellationToken))
            .ReturnsAsync(0);
        repository
            .Setup(value => value.RevokeBySessionAsync(sessionId, cancellationToken))
            .ReturnsAsync(0);
        var logger = new StructuredStateLogger();
        var store = new RefreshTokenFamilyStore(repository.Object, new Mock<IUnitOfWork>().Object, logger);

        Assert.Equal(0, await store.RevokeByAccountAsync(
            accountId, RefreshFamilyRevocationReason.Administrative, cancellationToken));
        Assert.Equal(0, await store.RevokeBySessionAsync(
            sessionId, RefreshFamilyRevocationReason.Logout, cancellationToken));

        Assert.Empty(logger.Entries);
    }

    /// <summary>
    /// Repository failure propagates unchanged and adds no success log; the raw id was still
    /// handed to the repository call.
    /// </summary>
    [Fact]
    public async Task RevokeByAccount_WhenTheRepositoryFails_PropagatesAndStaysSilent()
    {
        var accountId = Guid.NewGuid();
        var cancellationToken = TestContext.Current.CancellationToken;
        var repository = new Mock<IRefreshTokenRepository>();
        repository
            .Setup(value => value.RevokeByAccountAsync(accountId, cancellationToken))
            .ThrowsAsync(new InvalidOperationException("The repository is unavailable."));
        var logger = new StructuredStateLogger();
        var store = new RefreshTokenFamilyStore(repository.Object, new Mock<IUnitOfWork>().Object, logger);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            store.RevokeByAccountAsync(accountId, RefreshFamilyRevocationReason.Administrative, cancellationToken));

        Assert.Empty(logger.Entries);
        repository.Verify(value => value.RevokeByAccountAsync(accountId, cancellationToken), Times.Once);
    }

    /// <summary>
    /// Cancellation travels both ways: a pre-canceled token never reaches the repository, and a
    /// cancellation observed inside the repository propagates as cancellation — neither path adds a
    /// success log, and neither undoes the caller's id or token.
    /// </summary>
    [Fact]
    public async Task RevokeBySession_ObservesPreCanceledAndInFlightCanceledTokens()
    {
        var sessionId = Guid.NewGuid();
        var reason = RefreshFamilyRevocationReason.SessionExpired;
        using var cancellation = new CancellationTokenSource();
        var repository = new Mock<IRefreshTokenRepository>();
        repository
            .Setup(value => value.RevokeBySessionAsync(sessionId, cancellation.Token))
            .ThrowsAsync(new OperationCanceledException(cancellation.Token));
        var logger = new StructuredStateLogger();
        var store = new RefreshTokenFamilyStore(repository.Object, new Mock<IUnitOfWork>().Object, logger);

        var preCanceled = new CancellationToken(canceled: true);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.RevokeBySessionAsync(sessionId, reason, preCanceled));
        repository.VerifyNoOtherCalls();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.RevokeBySessionAsync(sessionId, reason, cancellation.Token));
        repository.Verify(value => value.RevokeBySessionAsync(sessionId, cancellation.Token), Times.Once);

        Assert.Empty(logger.Entries);
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

    [Fact]
    public async Task CreateChildAsync_WritesTheCanonicalChildShapeWithTheRootsCopies()
    {
        await using var harness = await CreateHarnessAsync();
        var cancellationToken = TestContext.Current.CancellationToken;
        var now = DateTimeOffset.UtcNow;
        var rootCreation = await harness.Store.CreateRootAsync(
            new InteractiveRefreshFamilyRootDescriptor(
                harness.AccountId, ClientId, harness.SessionId, CanonicalScope, now.AddMinutes(-5)),
            now,
            cancellationToken);

        var childId = Guid.NewGuid();
        var childPlaintext = RefreshTokenFamilyStore.GenerateRefreshToken();
        var descriptor = new InteractiveRefreshChildDescriptor(
            childId,
            rootCreation.RootId,
            rootCreation.RootId,
            harness.AccountId,
            ClientId,
            harness.SessionId,
            CanonicalScope,
            now.AddMinutes(-5),
            rootCreation.ExpiresAt,
            RefreshTokenDigest.Compute(childPlaintext));

        await harness.Store.CreateChildAsync(descriptor, now, cancellationToken);

        var child = Assert.Single(await harness.Context.RefreshTokens.AsNoTracking()
            .Where(row => row.Id == childId)
            .ToListAsync(cancellationToken));
        var root = await harness.Context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == rootCreation.RootId, cancellationToken);
        // EV-29: byte-for-byte root copies, only the parent relationship and fresh digest are new.
        Assert.Equal(rootCreation.RootId, child.FamilyId);
        Assert.Equal(rootCreation.RootId, child.ParentId);
        Assert.Equal(root.AccountId, child.AccountId);
        Assert.Equal(root.AppId, child.AppId);
        Assert.Equal(root.IdentitySessionId, child.IdentitySessionId);
        Assert.Equal(root.Scope, child.Scope);
        Assert.Equal(root.AuthTime, child.AuthTime);
        Assert.Equal(root.ExpiresAt, child.ExpiresAt);
        // Both providers persist timestamps with microsecond precision.
        Assert.Equal(now.UtcTicks / 10, child.CreatedAt.UtcTicks / 10);
        Assert.Null(child.ConsumedAt);
        Assert.False(child.IsRevoked);
        // DF-09: the caller's digest is stored verbatim; the plaintext never enters the shape.
        Assert.Equal(RefreshTokenDigest.Compute(childPlaintext), child.TokenValue);
        Assert.DoesNotContain(childPlaintext, child.TokenValue, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateChildAsync_RejectsInvalidDescriptorsWithoutEchoingValues()
    {
        await using var harness = await CreateHarnessAsync();
        var now = DateTimeOffset.UtcNow;
        var descriptor = new InteractiveRefreshChildDescriptor(
            Guid.NewGuid(),
            Guid.NewGuid(),
            Guid.NewGuid(),
            harness.AccountId,
            ClientId,
            harness.SessionId,
            CanonicalScope,
            now,
            now.AddDays(7),
            RefreshTokenDigest.Compute(RefreshTokenFamilyStore.GenerateRefreshToken()));

        var cases = new Func<InteractiveRefreshChildDescriptor>[]
        {
            () => descriptor with { ChildId = Guid.Empty },
            () => descriptor with { ChildId = descriptor.ParentId },
            () => descriptor with { ChildId = descriptor.RootId },
            () => descriptor with { ParentId = Guid.Empty },
            () => descriptor with { RootId = Guid.Empty },
            () => descriptor with { AppId = "" },
            () => descriptor with { Scope = "profile" },
            () => descriptor with { TokenDigest = "not-a-digest" }
        };

        foreach (var build in cases)
        {
            var exception = await Assert.ThrowsAnyAsync<ArgumentException>(() =>
                harness.Store.CreateChildAsync(build(), now, TestContext.Current.CancellationToken));
            Assert.DoesNotContain(CanonicalScope, exception.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(ClientId, exception.Message, StringComparison.Ordinal);
        }

        Assert.Empty(await harness.Context.RefreshTokens.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TryConsumeAsync_ConsumesExactlyOnceAndNeverRevokedMembers()
    {
        await using var harness = await CreateHarnessAsync();
        var cancellationToken = TestContext.Current.CancellationToken;
        var now = DateTimeOffset.UtcNow;
        var (rootId, siblingId, legacyId, childId) = await SeedFamiliesAsync(harness);

        Assert.True(await harness.Store.TryConsumeAsync(rootId, now, cancellationToken));
        // A second consumption of the same member matches nothing.
        Assert.False(await harness.Store.TryConsumeAsync(rootId, now, cancellationToken));

        // A revoked member and a legacy row are structurally out of reach.
        await harness.Context.RefreshTokens
            .Where(row => row.Id == siblingId)
            .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsRevoked, true), cancellationToken);
        Assert.False(await harness.Store.TryConsumeAsync(siblingId, now, cancellationToken));
        Assert.False(await harness.Store.TryConsumeAsync(legacyId, now, cancellationToken));

        var root = await harness.Context.RefreshTokens.AsNoTracking()
            .SingleAsync(row => row.Id == rootId, cancellationToken);
        // Both providers persist timestamps with microsecond precision.
        Assert.Equal(now.UtcTicks / 10, root.ConsumedAt!.Value.UtcTicks / 10);
        Assert.False(root.IsRevoked);
        _ = childId;
    }

    [Fact]
    public async Task RevokeLiveDescendantsAsync_RevokesOnlyLiveDescendantsOfThePresentedMember()
    {
        await using var harness = await CreateHarnessAsync();
        var now = DateTimeOffset.UtcNow;
        // One chain — the unique parent index admits exactly one child per member:
        // root -> consumedChild(consumed) -> revokedChild(revoked) -> liveGreatGrandchild(live).
        var rootId = Guid.NewGuid();
        var consumedChild = Guid.NewGuid();
        var revokedChild = Guid.NewGuid();
        var liveGreatGrandchild = Guid.NewGuid();
        var otherFamilyRoot = Guid.NewGuid();
        await InsertInteractiveMemberAsync(harness.Context, rootId, rootId, null, harness, now, now.AddDays(7));
        await InsertInteractiveMemberAsync(harness.Context, consumedChild, rootId, rootId, harness, now, now.AddDays(7));
        await InsertInteractiveMemberAsync(harness.Context, revokedChild, rootId, consumedChild, harness, now, now.AddDays(7));
        await InsertInteractiveMemberAsync(harness.Context, liveGreatGrandchild, rootId, revokedChild, harness, now, now.AddDays(7));
        await InsertInteractiveMemberAsync(harness.Context, otherFamilyRoot, otherFamilyRoot, null, harness, now, now.AddDays(7));
        await harness.Context.SaveChangesAsync(TestContext.Current.CancellationToken);
        await harness.Context.RefreshTokens
            .Where(row => row.Id == consumedChild)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(row => row.ConsumedAt, now.AddMinutes(-1)), TestContext.Current.CancellationToken);
        await harness.Context.RefreshTokens
            .Where(row => row.Id == revokedChild)
            .ExecuteUpdateAsync(setters => setters.SetProperty(row => row.IsRevoked, true), TestContext.Current.CancellationToken);
        harness.Context.ChangeTracker.Clear();

        // Presenting the root: the live member below the revoked link is reached; the consumed
        // child keeps its fact, the sibling family stays untouched, and the presented member
        // itself is never marked (EV-31 marks only live descendants).
        var revoked = await harness.Store.RevokeLiveDescendantsAsync(
            rootId, rootId, RefreshFamilyRevocationReason.RefreshReuse, TestContext.Current.CancellationToken);

        Assert.Equal(1, revoked);
        var rows = (await harness.Context.RefreshTokens.AsNoTracking()
            .ToListAsync(TestContext.Current.CancellationToken)).ToDictionary(row => row.Id);
        Assert.False(rows[rootId].IsRevoked);
        Assert.NotNull(rows[consumedChild].ConsumedAt);
        Assert.False(rows[consumedChild].IsRevoked);
        Assert.True(rows[revokedChild].IsRevoked);
        Assert.True(rows[liveGreatGrandchild].IsRevoked);
        Assert.False(rows[otherFamilyRoot].IsRevoked);
    }

    [Fact]
    public void ClassifyMarker_SeparatesInteractiveLegacyAndPartialRows()
    {
        Guid sessionId = Guid.NewGuid();
        DateTimeOffset authTime = DateTimeOffset.UtcNow;

        RefreshTokenEntity Member(Guid? session, string? scope, DateTimeOffset? auth) => new()
        {
            IdentitySessionId = session,
            Scope = scope,
            AuthTime = auth
        };

        Assert.Equal(
            RefreshMemberMarker.Interactive,
            RefreshTokenFamilyStore.ClassifyMarker(Member(sessionId, CanonicalScope, authTime)));
        Assert.Equal(RefreshMemberMarker.Legacy, RefreshTokenFamilyStore.ClassifyMarker(Member(null, null, null)));
        Assert.Equal(
            RefreshMemberMarker.Partial,
            RefreshTokenFamilyStore.ClassifyMarker(Member(sessionId, null, authTime)));
        Assert.Equal(
            RefreshMemberMarker.Partial,
            RefreshTokenFamilyStore.ClassifyMarker(Member(null, CanonicalScope, authTime)));
        Assert.Equal(
            RefreshMemberMarker.Partial,
            RefreshTokenFamilyStore.ClassifyMarker(Member(sessionId, CanonicalScope, null)));
    }

    [Fact]
    public async Task GenerateRefreshToken_ProducesTheCanonical43CharacterShape()
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < 32; index++)
        {
            var token = RefreshTokenFamilyStore.GenerateRefreshToken();
            Assert.Equal(43, token.Length);
            Assert.All(token, character =>
                Assert.True(char.IsAsciiLetterOrDigit(character) || character is '-' or '_'));
            Assert.True(seen.Add(token));
        }
    }

    // ---- Harness ----

    /// <summary>
    /// Captures both projections of every log call: the rendered formatter text and the structured
    /// state itself. Asserting only on rendered text cannot prove a sink is free of the raw
    /// value — the structured fields travel to JSON and log databases verbatim.
    /// </summary>
    private sealed class StructuredStateLogger : ILogger<RefreshTokenFamilyStore>
    {
        public sealed record Entry(string Text, IReadOnlyList<KeyValuePair<string, object?>> State);

        public List<Entry> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add(new Entry(
                formatter(state, exception),
                state is IEnumerable<KeyValuePair<string, object?>> fields ? [.. fields] : []));
    }

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
