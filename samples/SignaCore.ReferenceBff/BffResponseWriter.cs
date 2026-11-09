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
internal sealed class BffResponseWriter : IHostedLoginResponseWriter
{
    private BffResponseWriter()
    {
    }

    /// <summary>The stateless instance the sample's configuration shares.</summary>
    internal static BffResponseWriter Instance { get; } = new();

    /// <inheritdoc />
    public Task WriteSignInFailureAsync(
        HttpContext context,
        SignInReason reason,
        CancellationToken cancellationToken)
    {
        context.Response.Redirect("/error?reason=" + ReasonText(reason));
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task WriteFailurePageAsync(
        HttpContext context,
        SignInReason? reason,
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
        SessionStatus status,
        CancellationToken cancellationToken) =>
        // The package's fixed JSON session body already carries the status fields and no token;
        // the sample keeps it verbatim.
        DefaultHostedLoginResponseWriter.Instance.WriteSessionStatusAsync(context, status, cancellationToken);

    /// <summary>
    /// The closed reason vocabulary the package defines; the sample re-declares the bounded
    /// strings because its own <c>/error</c> page renders them. Every member of
    /// <see cref="SignInReason"/> must appear here — the switch is a mirror, not a
    /// second source of truth.
    /// </summary>
    internal static string ReasonText(SignInReason reason) => reason switch
    {
        SignInReason.AuthorityUnreachable => "authority_unreachable",
        SignInReason.InvalidReturnUrl => "invalid_return_url",
        SignInReason.InvalidResponse => "invalid_response",
        SignInReason.AccessDenied => "access_denied",
        SignInReason.UserCanceled => "user_canceled",
        SignInReason.PreSignInDenied => "pre_sign_in_denied",
        SignInReason.StateMismatch => "state_mismatch",
        SignInReason.IssuerMismatch => "issuer_mismatch",
        SignInReason.TokenExchangeFailed => "token_exchange_failed",
        SignInReason.InvalidToken => "invalid_token",
        SignInReason.SessionStoreFull => "session_store_full",
        SignInReason.RequiresReauthentication => "requires_reauthentication",
        _ => "invalid_response"
    };
}
