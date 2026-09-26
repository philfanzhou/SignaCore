using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using Xunit;
using static SignaCore.Tests.Integration.OidcDatabaseTestSupport;

namespace SignaCore.Tests.Integration;

public sealed class OidcNamedRevocationDatabaseContractTests
{
    private const string Owner = "named-revocation-client";

    [Fact]
    public async Task Sqlite_NamedRevocation_ChangesOnlyTheOwnedLiveMember()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(Ct);
        var options = new DbContextOptionsBuilder<IdentityDbContext>()
            .UseSqlite(connection, sqlite => sqlite.MigrationsAssembly("SignaCore.Database.Migrations.Sqlite"))
            .Options;
        await using var context = new IdentityDbContext(options);
        await context.Database.MigrateAsync(Ct);
        await VerifyNamedRevocationAsync(context);
    }

    [Fact]
    public async Task PostgreSql_NamedRevocation_ChangesOnlyTheOwnedLiveMember()
    {
        await using var harness = await Harness.CreateAsync();
        await using var context = harness.Context();
        await VerifyNamedRevocationAsync(context);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task PostgreSql_RevocationAndConsumption_RecheckTheWinnerAfterRowLock(bool revokeFirst)
    {
        await using var harness = await Harness.CreateAsync();
        await using var first = harness.Context();
        var ids = await SeedAsync(first);
        await using var second = harness.Context();
        await using var transaction = await first.Database.BeginTransactionAsync(Ct);
        var firstRepository = new RefreshTokenRepository(first);
        var secondRepository = new RefreshTokenRepository(second);
        var now = DateTimeOffset.UtcNow;
        Assert.True(revokeFirst
            ? await firstRepository.TryRevokeForAppAsync(Token(ids[0]), Owner, Ct)
            : await firstRepository.TryConsumeInteractiveAsync(ids[0], now, Ct));
        var competing = revokeFirst
            ? secondRepository.TryConsumeInteractiveAsync(ids[0], now, Ct)
            : secondRepository.TryRevokeForAppAsync(Token(ids[0]), Owner, Ct);
        await harness.WaitForLockWaitAsync();
        Assert.False(competing.IsCompleted);
        await transaction.CommitAsync(Ct);
        Assert.False(await competing);
        var row = await second.RefreshTokens.AsNoTracking().SingleAsync(x => x.Id == ids[0], Ct);
        Assert.Equal(revokeFirst, row.IsRevoked);
        Assert.Equal(!revokeFirst, row.ConsumedAt.HasValue);
        Assert.False(await second.RefreshTokens.AnyAsync(x => x.Id != ids[0] && x.IsRevoked && x.Id != ids[4], Ct));
    }

    [Fact]
    public async Task PostgreSql_CancelledRevocation_DoesNotWriteAfterLockRelease()
    {
        await using var harness = await Harness.CreateAsync();
        await using var first = harness.Context();
        var ids = await SeedAsync(first);
        await using var second = harness.Context();
        await using var transaction = await first.Database.BeginTransactionAsync(Ct);
        await new RefreshTokenRepository(first).LockByIdAsync(ids[0], Ct);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var pending = new RefreshTokenRepository(second)
            .TryRevokeForAppAsync(Token(ids[0]), Owner, cancellation.Token);
        await harness.WaitForLockWaitAsync();
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        await transaction.RollbackAsync(Ct);
        Assert.False(await second.RefreshTokens.AsNoTracking()
            .Where(x => x.Id == ids[0]).Select(x => x.IsRevoked).SingleAsync(Ct));
    }

    private static async Task VerifyNamedRevocationAsync(IdentityDbContext context)
    {
        var ids = await SeedAsync(context);
        var repository = new RefreshTokenRepository(context);
        var expected = await SnapshotAsync(context);
        Assert.False(await repository.TryRevokeAsync(Token(ids[0]), Ct));
        Assert.False(await repository.TryRevokeForAppAsync(Token(ids[0]), "other-client", Ct));
        Assert.False(await repository.TryRevokeForAppAsync("unknown-token", Owner, Ct));
        // The consumed root is retained as replay evidence; expiry and repeated revocation are no-ops.
        foreach (var id in ids.Skip(2).Take(3))
        {
            Assert.False(await repository.TryRevokeForAppAsync(Token(id), Owner, Ct));
        }
        using (var cancellation = new CancellationTokenSource())
        {
            await cancellation.CancelAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                repository.TryRevokeForAppAsync(Token(ids[0]), Owner, cancellation.Token));
        }
        await AssertSnapshotAsync(context, expected);

        // Both a fresh root and a live child can be named. Every other cell, including the
        // linked code, session, parent and other family of the same session, stays unchanged.
        foreach (var id in ids.Take(2))
        {
            Assert.True(await repository.TryRevokeForAppAsync(Token(id), Owner, Ct));
            expected[(typeof(RefreshTokenEntity), id)][nameof(RefreshTokenEntity.IsRevoked)] = true;
            await AssertSnapshotAsync(context, expected);
            Assert.False(await repository.TryRevokeForAppAsync(Token(id), Owner, Ct));
            Assert.False(await repository.TryConsumeInteractiveAsync(id, DateTimeOffset.UtcNow, Ct));
        }
        // Expired legacy rows remain revocable by the owning client, as before EV-14.
        Assert.True(await repository.TryRevokeForAppAsync(Token(ids[5]), Owner, Ct));
        expected[(typeof(RefreshTokenEntity), ids[5])][nameof(RefreshTokenEntity.IsRevoked)] = true;
        await AssertSnapshotAsync(context, expected);
    }

    private static async Task<Guid[]> SeedAsync(IdentityDbContext context)
    {
        var now = DateTimeOffset.UtcNow;
        var accountId = Guid.NewGuid();
        var credentialId = Guid.NewGuid();
        var appId = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        context.Accounts.Add(new AccountEntity { Id = accountId, IsActive = true, CreatedAt = now });
        context.PasswordCredentials.Add(new PasswordCredentialEntity
        {
            Id = credentialId, AccountId = accountId, Username = "named-revocation-user",
            PasswordHash = "synthetic-hash", CreatedAt = now
        });
        context.AppRegistrations.Add(new AppRegistrationEntity
        {
            Id = appId, AppId = Owner, AppSecretHash = "synthetic-hash",
            AppName = "Named Revocation", IsActive = true, CreatedAt = now
        });
        context.IdentitySessions.Add(new IdentitySessionEntity
        {
            Id = sessionId, AccountId = accountId, PasswordCredentialId = credentialId,
            AuthMethod = IdentityConstants.AuthMethodPassword, AuthTime = now, LastSeenAt = now,
            IdleExpiresAt = now.AddMinutes(30), AbsoluteExpiresAt = now.AddHours(1)
        });
        await context.SaveChangesAsync(Ct);
        // Live root, live child, consumed parent, expired root, revoked root, expired legacy,
        // and another live family belonging to the same session.
        var ids = Enumerable.Range(0, 7).Select(_ => Guid.NewGuid()).ToArray();
        foreach (var i in new[] { 0, 2, 1, 3, 4, 5, 6 })
        {
            context.RefreshTokens.Add(new RefreshTokenEntity
            {
                Id = ids[i], FamilyId = i == 1 ? ids[2] : ids[i], ParentId = i == 1 ? ids[2] : null,
                AccountId = accountId, AppId = Owner, TokenValue = RefreshTokenDigest.Compute(Token(ids[i])),
                IdentitySessionId = i == 5 ? null : sessionId, Scope = i == 5 ? null : "openid offline_access",
                AuthTime = i == 5 ? null : now, CreatedAt = now.AddMinutes(-5),
                ExpiresAt = i is 3 or 5 ? now.AddMinutes(-1) : now.AddHours(1),
                IsRevoked = i == 4, ConsumedAt = i == 2 ? now : null
            });
            await context.SaveChangesAsync(Ct);
        }
        context.AuthorizationCodes.Add(new AuthorizationCodeEntity
        {
            Id = Guid.NewGuid(), CodeDigest = AuthorizationCodeDigest.Compute("synthetic-authorization-code"),
            AppRegistrationId = appId, AccountId = accountId, IdentitySessionId = sessionId,
            RedirectUri = "https://client.example/callback", Scope = "openid offline_access",
            Nonce = "synthetic-nonce", CodeChallenge = CodeChallenge, AuthTime = now,
            CreatedAt = now, ExpiresAt = now.AddSeconds(60), ConsumedAt = now, RefreshFamilyId = ids[2]
        });
        await context.SaveChangesAsync(Ct);
        context.ChangeTracker.Clear();
        return ids;
    }

    private static string Token(Guid id) => "synthetic-named-refresh-" + id.ToString("N");

    private static async Task<Dictionary<(Type, Guid), PropertyValues>> SnapshotAsync(IdentityDbContext context)
    {
        context.ChangeTracker.Clear();
        await context.RefreshTokens.LoadAsync(Ct);
        await context.IdentitySessions.LoadAsync(Ct);
        await context.AuthorizationCodes.LoadAsync(Ct);
        return context.ChangeTracker.Entries().ToDictionary(
            entry => (entry.Entity.GetType(), (Guid)entry.Property("Id").CurrentValue!),
            entry => entry.CurrentValues.Clone());
    }

    private static async Task AssertSnapshotAsync(
        IdentityDbContext context, Dictionary<(Type, Guid), PropertyValues> expected)
    {
        var actual = await SnapshotAsync(context);
        Assert.Equal(expected.Count, actual.Count);
        foreach (var (key, values) in expected)
        {
            Assert.True(actual.TryGetValue(key, out var row), "Named revocation removed an unrelated row.");
            foreach (var property in values.Properties)
            {
                Assert.True(Equals(values[property], row[property]),
                    "Named revocation changed an unexpected persisted value.");
            }
        }
    }
}
