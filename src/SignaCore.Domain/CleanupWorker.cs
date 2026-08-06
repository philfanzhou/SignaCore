using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SignaCore.Domain.Keys;
using SignaCore.Database;
using SignaCore.Database.Repositories;

namespace SignaCore.Domain;

public class CleanupWorker : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IKeyManager _keyManager;
    private readonly ILogger<CleanupWorker> _logger;
    private readonly TimeSpan _interval = TimeSpan.FromHours(IdentityConstants.CleanupIntervalHours);

    public CleanupWorker(IServiceProvider serviceProvider, IKeyManager keyManager, ILogger<CleanupWorker> logger)
    {
        _serviceProvider = serviceProvider;
        _keyManager = keyManager;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Cleanup background service started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CleanupExpiredDataAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Cleanup task failed");
            }

            await Task.Delay(_interval, stoppingToken);
        }
    }

    private async Task CleanupExpiredDataAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting cleanup of expired data...");

        using var scope = _serviceProvider.CreateScope();
        var refreshTokenRepo = scope.ServiceProvider.GetRequiredService<IRefreshTokenRepository>();
        var appRegRepo = scope.ServiceProvider.GetRequiredService<IAppRegistrationRepository>();
        var securityKeyRepo = scope.ServiceProvider.GetRequiredService<ISecurityKeyRepository>();
        var loginAttemptRepo = scope.ServiceProvider.GetRequiredService<ILoginAttemptRepository>();
        var loginHistoryRepo = scope.ServiceProvider.GetRequiredService<ILoginHistoryRepository>();
        var auditLogRepo = scope.ServiceProvider.GetRequiredService<IAuditLogRepository>();
        var otpRepo = scope.ServiceProvider.GetService<IOtpRepository>();

        var deletedTokens = await refreshTokenRepo.RemoveExpiredAndRevokedAsync();
        if (deletedTokens > 0)
        {
            _logger.LogInformation("Deleted {Count} expired/revoked refresh tokens", deletedTokens);
        }

        var deactivatedApps = await appRegRepo.DeactivateExpiredCallbacksAsync(DateTimeOffset.UtcNow);
        if (deactivatedApps > 0)
        {
            _logger.LogInformation("Deactivated {Count} expired app registrations", deactivatedApps);
        }

        await securityKeyRepo.RemoveExpiredInactiveAsync();

        var lockoutCleanupCutoff = DateTimeOffset.UtcNow.AddDays(-1);
        await loginAttemptRepo.RemoveExpiredAsync(lockoutCleanupCutoff);

        if (otpRepo != null)
        {
            var now = DateTimeOffset.UtcNow;
            var deletedOtps = await otpRepo.RemoveInactiveAsync(now.AddDays(-2), now);
            if (deletedOtps > 0)
                _logger.LogInformation("Deleted {Count} inactive SMS OTP challenges", deletedOtps);
        }

        var loginHistoryCutoff = DateTimeOffset.UtcNow.AddDays(-IdentityConstants.LoginHistoryRetentionDays);
        var deletedHistories = await loginHistoryRepo.RemoveOlderThanAsync(loginHistoryCutoff);
        if (deletedHistories > 0)
        {
            _logger.LogInformation("Deleted {Count} old login history records", deletedHistories);
        }

        var auditLogCutoff = DateTimeOffset.UtcNow.AddDays(-IdentityConstants.AuditLogRetentionDays);
        var deletedLogs = await auditLogRepo.RemoveOlderThanAsync(auditLogCutoff);
        if (deletedLogs > 0)
        {
            _logger.LogInformation("Deleted {Count} old audit log records", deletedLogs);
        }

        if (await _keyManager.NeedsKeyRotationAsync())
        {
            await _keyManager.RotateKeyAsync();
        }

        _logger.LogInformation("Cleanup task completed");
    }
}
