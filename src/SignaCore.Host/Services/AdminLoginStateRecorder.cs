using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Repositories;
using SignaCore.Domain;
using SignaCore.Domain.Services;
using SignaCore.Domain.Validators;
using SignaCore.Host.Http;

namespace SignaCore.Host.Services;

/// <summary>
/// Commits one administrator login attempt — the login-attempt counter change, the login-history
/// audit row, and the unit-of-work save — through the same path for the legacy admin console and
/// the shared ServiceMantle management session.
/// </summary>
/// <remarks>
/// A failed-attempt change performs an immediate atomic update, so it and the login-history insert
/// are enclosed in one retryable transaction; the success path saves directly. Cookie I/O stays
/// outside: the caller decides the HTTP outcome after the state is committed.
/// </remarks>
public sealed class AdminLoginStateRecorder(
    ILoginAttemptRepository loginAttemptRepository,
    IAuditService auditService,
    IUnitOfWork unitOfWork,
    IdentityDbContext dbContext,
    ILogger<AdminLoginStateRecorder> logger)
{
    public async Task CommitAsync(
        ValidationResult validationResult,
        Guid? accountId,
        string username,
        string eventType,
        string? failureReason,
        string clientIp,
        string? userAgent,
        CancellationToken cancellationToken = default)
    {
        async Task StageAndSaveAsync(CancellationToken operationCancellationToken)
        {
            var loginAttempt = await LoginAttemptChangeApplier.ApplyAsync(
                validationResult.LoginAttemptChange,
                loginAttemptRepository,
                operationCancellationToken);
            if (loginAttempt?.LockoutUntil > DateTimeOffset.UtcNow)
            {
                logger.LogWarning(
                    "Account locked due to too many failed attempts, Username={Username}, LockoutUntil={LockoutUntil}",
                    LogValueSanitizer.Sanitize(loginAttempt.Username),
                    loginAttempt.LockoutUntil);
            }
            await auditService.RecordLoginAsync(
                accountId,
                username,
                "admin_login",
                eventType,
                clientIp,
                userAgent,
                failureReason,
                cancellationToken: operationCancellationToken);
            await unitOfWork.SaveChangesAsync(operationCancellationToken);
        }

        if (validationResult.LoginAttemptChange?.Kind != LoginAttemptChangeKind.RecordFailure)
        {
            await StageAndSaveAsync(cancellationToken);
            return;
        }

        var strategy = dbContext.Database.CreateExecutionStrategy();
        await strategy.ExecuteAsync(async operationCancellationToken =>
        {
            dbContext.ChangeTracker.Clear();
            await using var transaction = await dbContext.Database.BeginTransactionAsync(operationCancellationToken);
            await StageAndSaveAsync(operationCancellationToken);
            await transaction.CommitAsync(operationCancellationToken);
        }, cancellationToken);
    }
}
