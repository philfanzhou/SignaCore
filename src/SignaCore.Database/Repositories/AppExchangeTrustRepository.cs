using Microsoft.EntityFrameworkCore;
using SignaCore.Database.Entity;

namespace SignaCore.Database.Repositories;

public sealed class AppExchangeTrustRepository : IAppExchangeTrustRepository
{
    private readonly IdentityDbContext _dbContext;

    public AppExchangeTrustRepository(IdentityDbContext dbContext) => _dbContext = dbContext;

    public Task<bool> IsTrustedSourceAsync(
        Guid appRegistrationId,
        string sourceAppId,
        CancellationToken cancellationToken = default)
    {
        var normalized = IdentityValueNormalizer.Normalize(sourceAppId);
        return _dbContext.AppExchangeTrusts.AsNoTracking()
            .Where(trust => trust.AppRegistrationId == appRegistrationId)
            .Join(
                _dbContext.AppRegistrations.AsNoTracking(),
                trust => trust.SourceAppRegistrationId,
                app => app.Id,
                (trust, app) => app)
            .AnyAsync(app => app.AppIdNormalized == normalized && app.IsActive, cancellationToken);
    }

    public async Task<IReadOnlyList<AppExchangeTrust>> ListSourcesAsync(
        Guid appRegistrationId,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext.AppExchangeTrusts.AsNoTracking()
            .Where(trust => trust.AppRegistrationId == appRegistrationId)
            .Join(
                _dbContext.AppRegistrations.AsNoTracking(),
                trust => trust.SourceAppRegistrationId,
                app => app.Id,
                (trust, app) => new { trust, app })
            .OrderByDescending(item => item.trust.CreatedAt)
            .Select(item => new AppExchangeTrust(
                item.app.Id,
                item.app.AppId,
                item.app.AppName,
                item.app.IsActive,
                item.trust.ApprovedBy,
                item.trust.CreatedAt))
            .ToListAsync(cancellationToken);
    }

    public async Task<AppExchangeTrust> AddAsync(
        AppRegistrationEntity app,
        AppRegistrationEntity sourceApp,
        Guid? approvedBy,
        CancellationToken cancellationToken = default)
    {
        var existing = await _dbContext.AppExchangeTrusts.FirstOrDefaultAsync(
            trust => trust.AppRegistrationId == app.Id && trust.SourceAppRegistrationId == sourceApp.Id,
            cancellationToken);

        if (existing == null)
        {
            existing = new AppExchangeTrustEntity
            {
                Id = Guid.NewGuid(),
                AppRegistrationId = app.Id,
                SourceAppRegistrationId = sourceApp.Id,
                ApprovedBy = approvedBy,
                CreatedAt = DateTimeOffset.UtcNow
            };
            _dbContext.AppExchangeTrusts.Add(existing);
        }

        return new AppExchangeTrust(
            sourceApp.Id, sourceApp.AppId, sourceApp.AppName, sourceApp.IsActive,
            existing.ApprovedBy, existing.CreatedAt);
    }

    public async Task<bool> RemoveAsync(
        Guid appRegistrationId,
        Guid sourceAppRegistrationId,
        CancellationToken cancellationToken = default)
    {
        var trust = await _dbContext.AppExchangeTrusts.FirstOrDefaultAsync(
            item => item.AppRegistrationId == appRegistrationId &&
                item.SourceAppRegistrationId == sourceAppRegistrationId,
            cancellationToken);
        if (trust is null)
        {
            return false;
        }

        _dbContext.AppExchangeTrusts.Remove(trust);
        return true;
    }
}
