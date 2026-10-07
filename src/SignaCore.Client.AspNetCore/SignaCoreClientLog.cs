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
        SessionStatus,
        CsrfIssued,
        Logout,
        LogoutReturn
    }

    internal static class Outcome
    {
        internal const string Started = "started";
        internal const string Unavailable = "unavailable";
        internal const string Succeeded = "succeeded";
        internal const string Rejected = "rejected";
        internal const string Authenticated = "authenticated";
        internal const string RequiresReauthentication = "requires_reauthentication";
        internal const string RequiringDecision = "with_decision";
        internal const string Issued = "issued";
        internal const string Prepared = "prepared";
        internal const string LocalOnly = "local_only";
        internal const string CsrfRejected = "csrf_rejected";
        internal const string Completed = "completed";
        internal const string Invalid = "invalid";
    }

    internal static void SignInStarted(ILogger logger, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        logger.LogInformation(
            "SignaCore hosted login sign-in started. Operation: {Operation} Outcome: {Outcome}",
            Operation.SignInStarted, Outcome.Started);
    }

    internal static void SignInUnavailable(ILogger logger, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        logger.LogInformation(
            "SignaCore hosted login sign-in unavailable: the host is running unconfigured. Operation: {Operation} Outcome: {Outcome}",
            Operation.SignInStarted, Outcome.Unavailable);
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

    internal static void CsrfIssued(ILogger logger, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        logger.LogInformation(
            "SignaCore hosted login antiforgery token issued. Operation: {Operation} Outcome: {Outcome}",
            Operation.CsrfIssued, Outcome.Issued);
    }

    internal static void Logout(
        ILogger logger,
        string outcome,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        logger.LogInformation(
            "SignaCore hosted login logout finished. Operation: {Operation} Outcome: {Outcome}",
            Operation.Logout, outcome);
    }

    internal static void LogoutReturn(
        ILogger logger,
        bool completed,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        logger.LogInformation(
            "SignaCore hosted login logout return answered. Operation: {Operation} Outcome: {Outcome}",
            Operation.LogoutReturn, completed ? Outcome.Completed : Outcome.Invalid);
    }
}
