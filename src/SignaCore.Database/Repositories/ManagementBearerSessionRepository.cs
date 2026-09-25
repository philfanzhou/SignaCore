using Microsoft.EntityFrameworkCore;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public sealed class ManagementBearerSessionRepository : IManagementBearerSessionRepository
{
    public async Task AddAsync(
        IdentityDbContext db,
        ManagementBearerSessionEntity session,
        CancellationToken cancellationToken)
    {
        db.ManagementBearerSessions.Add(session);
        await db.SaveChangesAsync(cancellationToken);
    }

    public Task<ManagementBearerSessionEntity?> FindByDigestAsync(
        IdentityDbContext db,
        string tokenDigest,
        CancellationToken cancellationToken) =>
        db.ManagementBearerSessions
            .AsNoTracking()
            .SingleOrDefaultAsync(session => session.TokenDigest == tokenDigest, cancellationToken);

    public Task<string?> FindActiveCredentialUsernameAsync(
        IdentityDbContext db,
        Guid accountId,
        string usernameNormalized,
        CancellationToken cancellationToken) =>
        db.PasswordCredentials
            .AsNoTracking()
            .Where(credential => credential.UsernameNormalized == usernameNormalized
                && credential.AccountId == accountId
                && db.Accounts.Any(account => account.Id == accountId && account.IsActive))
            .Select(credential => credential.Username)
            .FirstOrDefaultAsync(cancellationToken);

    public Task<int> RevokeAsync(
        IdentityDbContext db,
        string tokenDigest,
        DateTimeOffset now,
        CancellationToken cancellationToken) =>
        db.ManagementBearerSessions
            .Where(session => session.TokenDigest == tokenDigest
                && session.RevokedAt == null
                && session.ExpiresAt > now)
            .ExecuteUpdateAsync(
                setters => setters.SetProperty(session => session.RevokedAt, (DateTimeOffset?)now),
                cancellationToken);

    public Task<int> DeleteExpiredAsync(
        IdentityDbContext db,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var cutoff = now.AddHours(-IdentityConstants.ManagementBearerRetentionHours);
        return db.ManagementBearerSessions
            .Where(session => session.ExpiresAt <= cutoff)
            .OrderBy(session => session.ExpiresAt)
            .Take(IdentityConstants.ManagementBearerCleanupBatchSize)
            .ExecuteDeleteAsync(cancellationToken);
    }
}
