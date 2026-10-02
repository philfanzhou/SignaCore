using SignaCore.Client.AspNetCore;

namespace SignaCore.ReferenceBff;

/// <summary>
/// The sample's presentation of the client package's bounded sign-in outcomes: a failure
/// redirects to the sample's own fixed <c>/error</c> page carrying the closed reason as its only
/// query parameter, the failure page itself answers with the same bounded page, and the
/// session-status answer keeps the package's fixed JSON body. The package defines the protocol
/// outcomes; this writer defines their presentation, exactly as its response-format extension
/// point intends.
/// </summary>
internal sealed class BffResponseWriter : ISignaCoreHostedLoginResponseWriter
{
    private BffResponseWriter()
    {
    }

    /// <summary>The stateless instance the sample's configuration shares.</summary>
    internal static BffResponseWriter Instance { get; } = new();

    /// <inheritdoc />
    public Task WriteSignInFailureAsync(
        HttpContext context,
        SignaCoreSignInReason reason,
        CancellationToken cancellationToken)
    {
        context.Response.Redirect("/error?reason=" + ReasonText(reason));
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task WriteFailurePageAsync(
        HttpContext context,
        SignaCoreSignInReason? reason,
        CancellationToken cancellationToken)
    {
        // The sample routes every failure presentation through its own bounded /error page; the
        // closed reason vocabulary is shared, so no new failure surface is introduced.
        context.Response.Redirect("/error"
            + (reason is null ? string.Empty : "?reason=" + ReasonText(reason.Value)));
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task WriteSessionStatusAsync(
        HttpContext context,
        SignaCoreSessionStatus status,
        CancellationToken cancellationToken) =>
        // The package's fixed JSON session body already carries the status fields and no token;
        // the sample keeps it verbatim.
        SignaCoreDefaultResponseWriter.Instance.WriteSessionStatusAsync(context, status, cancellationToken);

    /// <summary>
    /// The closed reason vocabulary the package defines; the sample re-declares the bounded
    /// strings because its own <c>/error</c> page renders them.
    /// </summary>
    internal static string ReasonText(SignaCoreSignInReason reason) => reason switch
    {
        SignaCoreSignInReason.AuthorityUnreachable => "authority_unreachable",
        SignaCoreSignInReason.InvalidReturnUrl => "invalid_return_url",
        SignaCoreSignInReason.InvalidResponse => "invalid_response",
        SignaCoreSignInReason.AccessDenied => "access_denied",
        SignaCoreSignInReason.StateMismatch => "state_mismatch",
        SignaCoreSignInReason.IssuerMismatch => "issuer_mismatch",
        SignaCoreSignInReason.TokenExchangeFailed => "token_exchange_failed",
        SignaCoreSignInReason.InvalidToken => "invalid_token",
        SignaCoreSignInReason.SessionStoreFull => "session_store_full",
        SignaCoreSignInReason.RequiresReauthentication => "requires_reauthentication",
        _ => "invalid_response"
    };
}
