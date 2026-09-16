using SignaCore.Database.Entity;
using SignaCore.Domain.Models;

namespace SignaCore.Domain.Services;

/// <summary>
/// The single continuation revalidation entry shared by the cancel (<c>EV-02</c>) and the login
/// success (<c>EV-01</c>) orchestration: it rebuilds the original authorization request from the
/// stored snapshot so the real <see cref="IOidcAuthorizationRequestValidator"/> decides the
/// current client and redirect trust again. No second client/redirect judgement exists anywhere.
/// <para>
/// The rebuilt request carries exactly the eight single-value parameters a validated continuation
/// was created from — nothing else — with the snapshot values verbatim. Stage-4 policy drift
/// (scope removal, refresh disablement) therefore answers through the verified URI and never
/// blocks a cancel, while client, capability, and redirect-URI drift stay local errors.
/// </para>
/// </summary>
public static class OidcContinuationRevalidation
{
    public static OidcAuthorizationParameters BuildParameters(
        AuthorizationRequestEntity continuation,
        string clientId)
    {
        ArgumentNullException.ThrowIfNull(continuation);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);

        return new OidcAuthorizationParameters(
        [
            Pair("response_type", "code"),
            Pair("client_id", clientId),
            Pair("redirect_uri", continuation.RedirectUri),
            Pair("scope", continuation.Scope),
            Pair("state", continuation.State),
            Pair("nonce", continuation.Nonce),
            Pair("code_challenge", continuation.CodeChallenge),
            Pair("code_challenge_method", "S256"),
        ]);

        static KeyValuePair<string, IReadOnlyList<string>> Pair(string name, string value) =>
            new(name, new[] { value });
    }
}
