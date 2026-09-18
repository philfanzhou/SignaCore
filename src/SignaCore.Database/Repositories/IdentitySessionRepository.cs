using Microsoft.EntityFrameworkCore;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public class IdentitySessionRepository : IIdentitySessionRepository
{
    private const string SqliteProviderName = "Microsoft.EntityFrameworkCore.Sqlite";

    private readonly IdentityDbContext _dbContext;

    public IdentitySessionRepository(IdentityDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public Task AddAsync(
        IdentitySessionEntity session,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _dbContext.IdentitySessions.Add(session);
        return Task.CompletedTask;
    }

    public async Task<bool> PasswordCredentialExistsForAccountAsync(
        Guid passwordCredentialId,
        Guid accountId,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext.PasswordCredentials
            .AsNoTracking()
            .AnyAsync(
                credential => credential.Id == passwordCredentialId
                    && credential.AccountId == accountId,
                cancellationToken);
    }

    public async Task<IdentitySessionEntity?> GetByIdAsync(
        Guid sessionId,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext.IdentitySessions
            .AsNoTracking()
            .FirstOrDefaultAsync(session => session.Id == sessionId, cancellationToken);
    }

    /// <summary>
    /// Follows the <c>InstallationStateLock</c> precedent: PostgreSQL takes an explicit
    /// <c>FOR UPDATE</c> row lock that blocks a second locker until this transaction ends, while
    /// SQLite relies on its file-level writer serialization and reads inside the transaction. The
    /// change tracker is cleared first so the lock always re-reads the committed row instead of
    /// returning a stale tracked copy; callers must therefore lock before staging writes, which
    /// is the canonical lock order anyway.
    /// </summary>
    public async Task<IdentitySessionEntity?> LockByIdAsync(
        Guid sessionId,
        CancellationToken cancellationToken = default)
    {
        if (_dbContext.Database.CurrentTransaction is null)
        {
            throw new InvalidOperationException(
                "Locking an identity session requires a caller-owned ambient transaction; none is active.");
        }

        _dbContext.ChangeTracker.Clear();

        if (string.Equals(
                _dbContext.Database.ProviderName,
                SqliteProviderName,
                StringComparison.Ordinal))
        {
            return await _dbContext.IdentitySessions
                .FirstOrDefaultAsync(session => session.Id == sessionId, cancellationToken);
        }

        var rows = await _dbContext.IdentitySessions
            .FromSqlInterpolated(
                $"SELECT * FROM identity_sessions WHERE id = {sessionId} FOR UPDATE")
            .ToListAsync(cancellationToken);

        return rows.FirstOrDefault();
    }

    public async Task<int> TouchActivityAsync(
        Guid sessionId,
        DateTimeOffset now,
        DateTimeOffset staleBefore,
        DateTimeOffset idleExpiresAtCandidate,
        CancellationToken cancellationToken = default)
    {
        // An activity write inside a caller-owned transaction joins it and leaves the only
        // commit to the caller.
        if (_dbContext.Database.CurrentTransaction is not null)
        {
            return await ExecuteTouchAsync(
                sessionId, now, staleBefore, idleExpiresAtCandidate, cancellationToken);
        }

        var executionStrategy = _dbContext.Database.CreateExecutionStrategy();
        return await executionStrategy.ExecuteAsync(async operationCancellationToken =>
        {
            await using var transaction = await _dbContext.Database.BeginTransactionAsync(
                operationCancellationToken);

            var affectedRows = await ExecuteTouchAsync(
                sessionId, now, staleBefore, idleExpiresAtCandidate, operationCancellationToken);

            await transaction.CommitAsync(operationCancellationToken);
            return affectedRows;
        }, cancellationToken);
    }

    private Task<int> ExecuteTouchAsync(
        Guid sessionId,
        DateTimeOffset now,
        DateTimeOffset staleBefore,
        DateTimeOffset idleExpiresAtCandidate,
        CancellationToken cancellationToken)
    {
        return _dbContext.IdentitySessions
            .Where(session => session.Id == sessionId
                && session.RevokedAt == null
                && now < session.IdleExpiresAt
                && now < session.AbsoluteExpiresAt
                && session.LastSeenAt <= staleBefore)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(session => session.LastSeenAt, now)
                // The slide is capped at the row's own absolute deadline, so the update can never
                // invert the idle <= absolute invariant.
                .SetProperty(
                    session => session.IdleExpiresAt,
                    session => session.AbsoluteExpiresAt < idleExpiresAtCandidate
                        ? session.AbsoluteExpiresAt
                        : idleExpiresAtCandidate),
            cancellationToken);
    }

    public async Task<int> MarkRevokedAsync(
        Guid sessionId,
        string revocationReason,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        // A revocation inside a caller-owned transaction joins it and leaves the only commit to
        // the caller.
        if (_dbContext.Database.CurrentTransaction is not null)
        {
            return await ExecuteRevokeAsync(sessionId, revocationReason, now, cancellationToken);
        }

        var executionStrategy = _dbContext.Database.CreateExecutionStrategy();
        return await executionStrategy.ExecuteAsync(async operationCancellationToken =>
        {
            await using var transaction = await _dbContext.Database.BeginTransactionAsync(
                operationCancellationToken);

            var affectedRows = await ExecuteRevokeAsync(
                sessionId, revocationReason, now, operationCancellationToken);

            await transaction.CommitAsync(operationCancellationToken);
            return affectedRows;
        }, cancellationToken);
    }

    private Task<int> ExecuteRevokeAsync(
        Guid sessionId,
        string revocationReason,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        return _dbContext.IdentitySessions
            .Where(session => session.Id == sessionId && session.RevokedAt == null)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(session => session.RevokedAt, now)
                .SetProperty(session => session.RevocationReason, revocationReason),
            cancellationToken);
    }

    public async Task<IReadOnlyList<IdentitySessionEntity>> ListByAccountAsync(
        Guid accountId,
        int take,
        int skip,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext.IdentitySessions
            .AsNoTracking()
            .Where(session => session.AccountId == accountId)
            .OrderByDescending(session => session.AuthTime)
            .ThenBy(session => session.Id)
            .Skip(skip)
            .Take(take)
            .ToListAsync(cancellationToken);
    }

    public async Task<int> CountByAccountAsync(
        Guid accountId,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext.IdentitySessions
            .CountAsync(session => session.AccountId == accountId, cancellationToken);
    }

    public async Task<int> RemoveExpiredBeforeAsync(
        DateTimeOffset cutoff,
        CancellationToken cancellationToken = default)
    {
        var executionStrategy = _dbContext.Database.CreateExecutionStrategy();
        return await executionStrategy.ExecuteAsync(async operationCancellationToken =>
        {
            await using var transaction = await _dbContext.Database.BeginTransactionAsync(
                operationCancellationToken);

            var deletedRows = await _dbContext.IdentitySessions
                .Where(session => (session.IdleExpiresAt <= cutoff
                        || session.RevokedAt <= cutoff)
                    // PS-23 (authorization_codes slice): a session stays while any retained code
                    // row still references it, even past the session's own retention window. The
                    // code cleanup segment runs before this one in the same cleanup round, so a
                    // code past its retention is already gone by the time this predicate runs.
                    && !_dbContext.AuthorizationCodes.Any(
                        code => code.IdentitySessionId == session.Id)
                    // Same rule for interactive refresh families (refresh_tokens slice): the
                    // restrictive session reference blocks the delete while any family member
                    // survives, and the child-first family cleanup segment runs before this one.
                    && !_dbContext.RefreshTokens.Any(
                        token => token.IdentitySessionId == session.Id))
                .ExecuteDeleteAsync(operationCancellationToken);

            await transaction.CommitAsync(operationCancellationToken);
            return deletedRows;
        }, cancellationToken);
    }
}
