using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public class RefreshTokenRepository : IRefreshTokenRepository
{
    private const string SqliteProviderName = "Microsoft.EntityFrameworkCore.Sqlite";

    private readonly IdentityDbContext _dbContext;

    public RefreshTokenRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<RefreshTokenEntity?> GetByTokenValueAsync(
        string tokenValue,
        CancellationToken cancellationToken = default)
    {
        var tokenDigest = RefreshTokenDigest.Compute(tokenValue);
        return await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(r => r.TokenValue == tokenDigest, cancellationToken);
    }

    public Task AddAsync(
        RefreshTokenEntity refreshToken,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        refreshToken.TokenValue = RefreshTokenDigest.EnsureDigest(refreshToken.TokenValue);
        EnsureLegacySingletonRoot(refreshToken);
        _dbContext.RefreshTokens.Add(refreshToken);
        return Task.CompletedTask;
    }

    /// <summary>
    /// The single legacy shape guard (<c>PS-07</c>) of every write through this repository: a row
    /// without an id gets a fresh one, and a legacy row — no identity session — without a family
    /// becomes the singleton root <c>family_id = id</c>. An interactive row is left exactly as its
    /// writer built it; the interactive family shape belongs to the family write API (#98).
    /// </summary>
    private static void EnsureLegacySingletonRoot(RefreshTokenEntity refreshToken)
    {
        if (refreshToken.Id == Guid.Empty)
        {
            refreshToken.Id = Guid.NewGuid();
        }

        if (refreshToken.IdentitySessionId is null && refreshToken.FamilyId == Guid.Empty)
        {
            refreshToken.FamilyId = refreshToken.Id;
        }
    }

    public async Task<bool> TryRevokeAsync(
        string tokenValue,
        CancellationToken cancellationToken = default)
    {
        var tokenDigest = RefreshTokenDigest.Compute(tokenValue);
        // Legacy-only revocation (EV-33): an interactive family member never takes family
        // semantics from the legacy paths, so the predicate structurally excludes it.
        var affectedRows = await _dbContext.RefreshTokens
            .Where(token => token.TokenValue == tokenDigest
                && !token.IsRevoked
                && token.IdentitySessionId == null)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(token => token.IsRevoked, true), cancellationToken);
        return affectedRows == 1;
    }

    /// <summary>
    /// The comparison is exact equality rather than normalization: both sides come from the same
    /// column, app_registrations.app_id — issuance writes <c>app.AppId</c>, and the identity of the
    /// revoking party is the same <c>app.AppId</c> resolved by gateway authentication. On top of
    /// that, <c>IdentityValueNormalizer.Normalize</c> does not translate to SQL, so putting it here
    /// would drag the whole query to client-side evaluation.
    /// </summary>
    public async Task<bool> TryRevokeForAppAsync(
        string tokenValue,
        string appId,
        CancellationToken cancellationToken = default)
    {
        var tokenDigest = RefreshTokenDigest.Compute(tokenValue);
        // Legacy-only revocation (EV-33), same defense as TryRevokeAsync: the identity-session
        // predicate keeps a family member out of the legacy single-row revocation path.
        var affectedRows = await _dbContext.RefreshTokens
            .Where(token => token.TokenValue == tokenDigest
                && !token.IsRevoked
                && token.AppId == appId
                && token.IdentitySessionId == null)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(token => token.IsRevoked, true), cancellationToken);
        return affectedRows == 1;
    }

    /// <summary>
    /// Rotates a refresh token in one step: revoking the old token and inserting its replacement
    /// happen inside the same transaction and succeed or fail atomically.
    /// <para>
    /// The explicit transaction <b>must</b> run as a whole inside <c>CreateExecutionStrategy()</c>.
    /// PostgreSQL enables <c>EnableRetryOnFailure()</c> (see
    /// <see cref="IdentityDatabaseOptionsExtensions"/>), and the retrying strategy refuses to run
    /// commands inside a transaction the caller started itself: calling
    /// <c>BeginTransactionAsync</c> directly makes the first command throw
    /// <c>InvalidOperationException: ... does not support user-initiated transactions</c>, which
    /// ExceptionHandlingMiddleware turns into an HTTP 409 and takes the whole refresh flow down.
    /// SQLite does not enable retries and gets a NonRetryingExecutionStrategy, so the lambda runs
    /// exactly once and the behaviour is unchanged.
    /// </para>
    /// <para>
    /// The lambda is replayed as a whole, so every step inside it has to be written as if it may run
    /// again; nothing may be lifted out of it.
    /// </para>
    /// </summary>
    public async Task<bool> TryRotateAsync(
        string tokenValue,
        RefreshTokenEntity replacement,
        CancellationToken cancellationToken = default)
    {
        var tokenDigest = RefreshTokenDigest.Compute(tokenValue);
        replacement.TokenValue = RefreshTokenDigest.EnsureDigest(replacement.TokenValue);
        EnsureLegacySingletonRoot(replacement);

        // Token issuance owns a wider transaction that also contains the account update and login
        // history row. In that path this repository stages the replacement and leaves the only
        // SaveChanges/commit to the caller; the conditional update is protected by that ambient
        // transaction. Standalone callers retain the self-contained transaction below.
        // The identity-session predicate keeps legacy rotation off interactive family members:
        // only a legacy row can ever be revoked and replaced here (EV-33); interactive rotation
        // with its consumption semantics belongs to the family API (#98).
        if (_dbContext.Database.CurrentTransaction is not null)
        {
            var affectedRows = await _dbContext.RefreshTokens
                .Where(token => token.TokenValue == tokenDigest
                    && !token.IsRevoked
                    && token.IdentitySessionId == null)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(token => token.IsRevoked, true), cancellationToken);
            if (affectedRows != 1)
            {
                return false;
            }

            _dbContext.RefreshTokens.Add(replacement);
            return true;
        }

        var executionStrategy = _dbContext.Database.CreateExecutionStrategy();
        return await executionStrategy.ExecuteAsync(async operationCancellationToken =>
        {
            await using var transaction = await _dbContext.Database.BeginTransactionAsync(
                operationCancellationToken);

            // The concurrency semantics come from this conditional update plus the lock the
            // transaction holds: when two requests rotate the same token at once, the later one
            // blocks on the row lock, re-evaluates is_revoked after the first commits, matches 0
            // rows, and returns false.
            var affectedRows = await _dbContext.RefreshTokens
                .Where(token => token.TokenValue == tokenDigest
                    && !token.IsRevoked
                    && token.IdentitySessionId == null)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(token => token.IsRevoked, true), operationCancellationToken);

            if (affectedRows != 1)
            {
                // On the retry path, the replacement may already have been added by a previous
                // attempt. A rollback does not clear the ChangeTracker, so without detaching it
                // explicitly any later SaveChanges in this request would persist a token that must
                // not exist.
                _dbContext.Entry(replacement).State = EntityState.Detached;
                await transaction.RollbackAsync(operationCancellationToken);
                return false;
            }

            _dbContext.RefreshTokens.Add(replacement);

            // acceptAllChangesOnSuccess: false — pending state is not marked as saved until the
            // commit has succeeded. Otherwise the replacement would become Unchanged right after
            // SaveChanges, and if the commit failed and triggered a retry the replay would not
            // insert it again, leaving the half-finished state of "old token revoked, replacement
            // lost".
            await _dbContext.SaveChangesAsync(
                acceptAllChangesOnSuccess: false,
                operationCancellationToken);
            await transaction.CommitAsync(operationCancellationToken);
            _dbContext.ChangeTracker.AcceptAllChanges();
            return true;
        }, cancellationToken);
    }

    public Task RemoveRangeAsync(
        IEnumerable<RefreshTokenEntity> tokens,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.RefreshTokens.RemoveRange(tokens);
        return Task.CompletedTask;
    }

    public async Task<int> RemoveExpiredAndRevokedAsync(
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        // Legacy-only cleanup (PS-07): a legacy singleton root self-references, and deleting
        // self-referencing rows in one statement succeeds identically on both providers, so the
        // current expired-or-revoked behavior is preserved. Interactive family members are never
        // touched here — under ON DELETE RESTRICT a whole-family single-statement delete fails on
        // SQLite while it succeeds on PostgreSQL, so the child-first interactive cleanup belongs
        // to RemoveInteractiveFamiliesAsync instead of this statement.
        return await _dbContext.RefreshTokens
            .Where(r => r.IdentitySessionId == null && (r.IsRevoked || r.ExpiresAt < now))
            .ExecuteDeleteAsync(cancellationToken);
    }

    public async Task<int> RevokeFamilyAsync(
        Guid rootId,
        CancellationToken cancellationToken = default)
    {
        // EV-24: revoke exactly the family the replayed code names. The conditional update keeps
        // the first revocation fact authoritative — an already-revoked member matches nothing —
        // and the identity-session predicate keeps a legacy singleton id structurally out.
        return await _dbContext.RefreshTokens
            .Where(token => token.FamilyId == rootId
                && token.IdentitySessionId != null
                && !token.IsRevoked)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(token => token.IsRevoked, true), cancellationToken);
    }

    public async Task<int> RevokeBySessionAsync(
        Guid identitySessionId,
        CancellationToken cancellationToken = default)
    {
        // EV-06/EV-15: session-scoped whole-family revocation over interactive rows only; legacy
        // rows have no session and cannot match. First fact stays authoritative.
        return await _dbContext.RefreshTokens
            .Where(token => token.IdentitySessionId == identitySessionId
                && !token.IsRevoked)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(token => token.IsRevoked, true), cancellationToken);
    }

    /// <summary>
    /// Same lock discipline as <see cref="IdentitySessionRepository.LockByIdAsync"/>: the
    /// ambient-transaction guard, the cleared change tracker, PostgreSQL <c>FOR UPDATE</c>
    /// versus the SQLite plain read inside the caller's transaction (<c>Persistence.md</c> lock
    /// order — session first, then the family root, then the presented member).
    /// </summary>
    public async Task<RefreshTokenEntity?> LockByIdAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        if (_dbContext.Database.CurrentTransaction is null)
        {
            throw new InvalidOperationException(
                "Locking a refresh token requires a caller-owned ambient transaction; none is active.");
        }

        _dbContext.ChangeTracker.Clear();

        if (string.Equals(
                _dbContext.Database.ProviderName,
                SqliteProviderName,
                StringComparison.Ordinal))
        {
            return await _dbContext.RefreshTokens
                .FirstOrDefaultAsync(token => token.Id == id, cancellationToken);
        }

        var rows = await _dbContext.RefreshTokens
            .FromSqlInterpolated(
                $"SELECT * FROM refresh_tokens WHERE id = {id} FOR UPDATE")
            .ToListAsync(cancellationToken);

        return rows.FirstOrDefault();
    }

    public Task<RefreshTokenEntity?> GetByIdAsync(
        Guid id,
        CancellationToken cancellationToken = default) =>
        _dbContext.RefreshTokens
            .AsNoTracking()
            .FirstOrDefaultAsync(token => token.Id == id, cancellationToken);

    public async Task<bool> TryConsumeInteractiveAsync(
        Guid memberId,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        // EV-29: the conditional consumption is the single point the one-child invariant is
        // enforced against concurrency and implementation drift — an already consumed or revoked
        // member matches nothing, so only one rotation of the same member can ever succeed here.
        // Legacy rows are structurally out of reach (EV-33).
        var affectedRows = await _dbContext.RefreshTokens
            .Where(token => token.Id == memberId
                && token.IdentitySessionId != null
                && !token.IsRevoked
                && token.ConsumedAt == null)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(token => token.ConsumedAt, now), cancellationToken);
        return affectedRows == 1;
    }

    public async Task<int> RevokeLiveDescendantsAsync(
        Guid familyId,
        Guid memberId,
        CancellationToken cancellationToken = default)
    {
        // EV-31: walk the parent chain down from the presented member — through links that may
        // already be consumed or revoked — revoking each still-live descendant (unconsumed and
        // unrevoked) by a conditional update so the first revocation fact stays authoritative.
        // Ancestors and sibling families are structurally out of reach, and a consumed member
        // keeps its committed consumption fact without a revocation mark. The chain is bounded
        // by the family's membership.
        var revoked = 0;
        var frontier = new List<Guid> { memberId };
        while (frontier.Count > 0)
        {
            var children = await _dbContext.RefreshTokens
                .Where(token => token.FamilyId == familyId
                    && token.ParentId != null
                    && frontier.Contains(token.ParentId.Value))
                .Select(token => token.Id)
                .ToListAsync(cancellationToken);
            if (children.Count == 0)
            {
                break;
            }

            revoked += await _dbContext.RefreshTokens
                .Where(token => children.Contains(token.Id)
                    && !token.IsRevoked
                    && token.ConsumedAt == null)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(token => token.IsRevoked, true), cancellationToken);
            frontier = children;
        }

        return revoked;
    }

    public async Task<int> RemoveInteractiveFamiliesAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        var executionStrategy = _dbContext.Database.CreateExecutionStrategy();
        return await executionStrategy.ExecuteAsync(async operationCancellationToken =>
        {
            await using var transaction = await _dbContext.Database.BeginTransactionAsync(
                operationCancellationToken);

            // A family is removable only when every member is past the family deadline (all
            // members copy the root's expires_at) and no authorization code still links the root:
            // a retained code keeps its replay evidence resolvable (SC-18), and the code cleanup
            // segment runs before this one in the same cleanup round.
            var familyIds = await _dbContext.RefreshTokens
                .Where(token => token.IdentitySessionId != null)
                .GroupBy(token => token.FamilyId)
                .Where(group => group.Max(member => member.ExpiresAt) <= now
                    && !_dbContext.AuthorizationCodes.Any(
                        code => code.RefreshFamilyId == group.Key))
                .Select(group => group.Key)
                .ToListAsync(operationCancellationToken);
            if (familyIds.Count == 0)
            {
                await transaction.CommitAsync(operationCancellationToken);
                return 0;
            }

            // Child-first (PS-06): under the restrictive family_id/parent_id self-references a
            // single-statement whole-family delete fails on SQLite, so children go before roots
            // in two statements inside one unit.
            var deletedChildren = await _dbContext.RefreshTokens
                .Where(token => familyIds.Contains(token.FamilyId)
                    && token.ParentId != null
                    && token.IdentitySessionId != null)
                .ExecuteDeleteAsync(operationCancellationToken);
            var deletedRoots = await _dbContext.RefreshTokens
                .Where(token => familyIds.Contains(token.FamilyId)
                    && token.ParentId == null
                    && token.IdentitySessionId != null)
                .ExecuteDeleteAsync(operationCancellationToken);

            await transaction.CommitAsync(operationCancellationToken);
            return deletedChildren + deletedRoots;
        }, cancellationToken);
    }
}
