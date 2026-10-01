using Microsoft.Extensions.Logging;

namespace SignaCore.Client.AspNetCore;

/// <summary>
/// The bounded operation log of the hosted-login package. Every entry is a finite
/// operation/outcome pair — nothing else is ever accepted: no message text, no exception, no
/// URL, no query string, and by construction no code, state, nonce, verifier, token, or secret.
/// </summary>
internal static class SignaCoreClientLog
{
    internal enum Operation
    {
        SignInStarted,
        SignInSucceeded,
        SignInRejected,
        SessionStatus
    }

    internal static class Outcome
    {
        internal const string Started = "started";
        internal const string Succeeded = "succeeded";
        internal const string Rejected = "rejected";
        internal const string Authenticated = "authenticated";
        internal const string RequiresReauthentication = "requires_reauthentication";
        internal const string RequiringDecision = "with_decision";
    }

    internal static void SignInStarted(ILogger logger, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        logger.LogInformation(
            "SignaCore hosted login sign-in started. Operation: {Operation} Outcome: {Outcome}",
            Operation.SignInStarted, Outcome.Started);
    }

    internal static void SignInSucceeded(ILogger logger, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        logger.LogInformation(
            "SignaCore hosted login sign-in succeeded. Operation: {Operation} Outcome: {Outcome}",
            Operation.SignInStarted, Outcome.Succeeded);
    }

    internal static void SignInRejected(
        ILogger logger,
        SignaCoreSignInReason reason,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        logger.LogInformation(
            "SignaCore hosted login sign-in rejected. Operation: {Operation} Outcome: {Outcome} Reason: {Reason}",
            Operation.SignInRejected, Outcome.Rejected, reason.ToString());
    }

    internal static void SessionStatus(
        ILogger logger,
        bool authenticated,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        logger.LogInformation(
            "SignaCore hosted login session queried. Operation: {Operation} Outcome: {Outcome}",
            Operation.SessionStatus,
            authenticated ? Outcome.Authenticated : Outcome.RequiresReauthentication);
    }
}
