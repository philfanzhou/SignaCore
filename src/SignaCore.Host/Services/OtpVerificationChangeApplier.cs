using SignaCore.Database.Repositories;
using SignaCore.Domain.Services.Sms;

namespace SignaCore.Host.Services;

internal static class OtpVerificationChangeApplier
{
    public static Task<bool> ApplyAsync(
        OtpVerificationChange change,
        IOtpRepository repository,
        CancellationToken cancellationToken)
    {
        if (change.Kind == OtpVerificationChangeKind.Consume)
        {
            return repository.TryConsumeAsync(
                change.AppRegistrationId,
                change.Phone,
                change.ExpectedCodeMac,
                change.ObservedAt,
                change.MaxAttempts,
                cancellationToken);
        }

        if (change.Kind == OtpVerificationChangeKind.RecordFailure)
        {
            return ApplyFailureAsync(change, repository, cancellationToken);
        }

        throw new ArgumentOutOfRangeException(nameof(change), change.Kind, "Unknown OTP change kind.");
    }

    private static async Task<bool> ApplyFailureAsync(
        OtpVerificationChange change,
        IOtpRepository repository,
        CancellationToken cancellationToken) =>
        await repository.IncrementFailedAttemptsAsync(
            change.AppRegistrationId,
            change.Phone,
            change.ExpectedCodeMac,
            change.ObservedAt,
            change.MaxAttempts,
            change.LockoutUntil,
            cancellationToken) == 1;
}
