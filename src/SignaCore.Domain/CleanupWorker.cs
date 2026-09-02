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
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
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
        cancellationToken.ThrowIfCancellationRequested();
        _logger.LogInformation("Starting cleanup of expired data...");

        using var scope = _serviceProvider.CreateScope();
        var refreshTokenRepo = scope.ServiceProvider.GetRequiredService<IRefreshTokenRepository>();
        var appRegRepo = scope.ServiceProvider.GetRequiredService<IAppRegistrationRepository>();
        var securityKeyRepo = scope.ServiceProvider.GetRequiredService<ISecurityKeyRepository>();
        var loginAttemptRepo = scope.ServiceProvider.GetRequiredService<ILoginAttemptRepository>();
        var loginHistoryRepo = scope.ServiceProvider.GetRequiredService<ILoginHistoryRepository>();
        var auditLogRepo = scope.ServiceProvider.GetRequiredService<IAuditLogRepository>();
        var otpRepo = scope.ServiceProvider.GetService<IOtpRepository>();

        var deletedTokens = await refreshTokenRepo.RemoveExpiredAndRevokedAsync(cancellationToken);
        if (deletedTokens > 0)
        {
            _logger.LogInformation("Deleted {Count} expired/revoked refresh tokens", deletedTokens);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var deactivatedApps = await appRegRepo.DeactivateExpiredCallbacksAsync(
            DateTimeOffset.UtcNow,
            cancellationToken);
        if (deactivatedApps > 0)
        {
            _logger.LogInformation("Deactivated {Count} expired app registrations", deactivatedApps);
        }

        cancellationToken.ThrowIfCancellationRequested();
        await securityKeyRepo.RemoveExpiredInactiveAsync(cancellationToken);

        cancellationToken.ThrowIfCancellationRequested();
        var lockoutCleanupCutoff = DateTimeOffset.UtcNow.AddDays(-1);
        await loginAttemptRepo.RemoveExpiredAsync(lockoutCleanupCutoff, cancellationToken);

        if (otpRepo != null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var now = DateTimeOffset.UtcNow;
            var deletedOtps = await otpRepo.RemoveInactiveAsync(
                now.AddDays(-2),
                now,
                cancellationToken);
            if (deletedOtps > 0)
                _logger.LogInformation("Deleted {Count} inactive SMS OTP challenges", deletedOtps);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var loginHistoryCutoff = DateTimeOffset.UtcNow.AddDays(-IdentityConstants.LoginHistoryRetentionDays);
        var deletedHistories = await loginHistoryRepo.RemoveOlderThanAsync(
            loginHistoryCutoff,
            cancellationToken);
        if (deletedHistories > 0)
        {
            _logger.LogInformation("Deleted {Count} old login history records", deletedHistories);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var auditLogCutoff = DateTimeOffset.UtcNow.AddDays(-IdentityConstants.AuditLogRetentionDays);
        var deletedLogs = await auditLogRepo.RemoveOlderThanAsync(auditLogCutoff, cancellationToken);
        if (deletedLogs > 0)
        {
            _logger.LogInformation("Deleted {Count} old audit log records", deletedLogs);
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (await _keyManager.NeedsKeyRotationAsync(cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            await _keyManager.RotateKeyAsync(cancellationToken);
        }

        _logger.LogInformation("Cleanup task completed");
    }
}
