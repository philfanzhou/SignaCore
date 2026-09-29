using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Database.Repositories;
using SignaCore.Domain.Services.Sms;

namespace SignaCore.Host.Services;

/// <summary>
/// The auth-method-dependent rules every application operation on an interactive identity
/// session shares — authorize reuse, code redemption, interactive refresh, and UserInfo — kept in
/// one place so the four paths cannot drift: the <c>PS-04</c> SMS admission predicate
/// (<c>EV-38</c>) and the <c>PS-12</c>/<c>PS-16</c> <c>name</c> source.
/// </summary>
internal static class InteractiveSessionAuthMethodRules
{
    /// <summary>
    /// Whether <paramref name="session"/> passes the auth-method part of the live-session
    /// judgement for <paramref name="application"/>, read live: a <c>Password</c> session has no
    /// SMS predicate; an <c>Sms</c> session requires the application's current
    /// <c>PS-04</c> SMS admission predicate for its SMS login identity. Any other shape — an
    /// unknown auth method or an <c>Sms</c> row without its identity reference, which the
    /// database CHECK already rejects — fails closed. The account-active term is each caller's
    /// existing account check.
    /// </summary>
    public static async Task<bool> AdmitsAsync(
        ISmsAdmissionService smsAdmissions,
        IdentitySessionEntity session,
        AppRegistrationEntity application,
        CancellationToken cancellationToken)
    {
        if (string.Equals(session.AuthMethod, IdentityConstants.AuthMethodPassword, StringComparison.Ordinal))
        {
            return true;
        }

        if (!string.Equals(session.AuthMethod, IdentityConstants.AuthMethodSms, StringComparison.Ordinal)
            || session.SmsUserLoginId is not Guid smsUserLoginId)
        {
            return false;
        }

        return await smsAdmissions.IsSessionAdmittedAsync(
            application.Id, application.SmsLoginMode, smsUserLoginId, cancellationToken);
    }

    /// <summary>
    /// The <c>PS-12</c>/<c>PS-16</c> <c>name</c> source, read at issuance: for a <c>Password</c>
    /// session the account's Password username (unchanged behavior); for an <c>Sms</c> session the
    /// username of the account's Password credential only when exactly one exists, otherwise
    /// <c>null</c> so the claim is omitted. A phone number is never a source. The access token's
    /// display-name fallback uses the same value.
    /// </summary>
    public static async Task<string?> ResolveNameAsync(
        IPasswordCredentialRepository passwordCredentials,
        string authMethod,
        Guid accountId,
        CancellationToken cancellationToken)
    {
        if (string.Equals(authMethod, IdentityConstants.AuthMethodSms, StringComparison.Ordinal))
        {
            return await passwordCredentials.GetSoleUsernameByAccountIdAsync(accountId, cancellationToken);
        }

        var credential = await passwordCredentials.GetByAccountIdAsync(accountId, cancellationToken);
        return credential?.Username;
    }
}
