using System.Diagnostics.CodeAnalysis;
using SignaCore.Database.Entity;
using SignaCore.Domain.Services.Sms;

namespace SignaCore.Domain.Validators;

public interface IIdentityValidator
{
    string GrantType { get; }
    Task<ValidationResult> ValidateAsync(ValidationRequest request);
}

public class ValidationRequest
{
    public string GrantType { get; set; } = string.Empty;
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string? Phone { get; set; }

    /// <summary>
    /// The SMS verification code or the WeChat code, interpreted according to
    /// <see cref="GrantType"/>.
    /// </summary>
    public string? Code { get; set; }

    public string? RefreshToken { get; set; }
    public string? AppId { get; set; }
    public AppRegistrationEntity? App { get; set; }
    public CancellationToken CancellationToken { get; set; }
}

public class ValidationResult
{
    /// <summary>
    /// Whether validation passed.
    /// <para>
    /// The three <see cref="MemberNotNullWhenAttribute"/> annotations hand the guarantees in the
    /// factory method signatures to the compiler: <c>account</c> / <c>authMethod</c> on
    /// <see cref="Success"/> and <c>message</c> on <see cref="Failure"/> are all non-nullable
    /// parameters, and an instance can only be produced by those two methods (every property is
    /// private set). So <see cref="Account"/> and <see cref="AuthMethod"/> are necessarily non-null
    /// in a success branch, and <see cref="ErrorMessage"/> is necessarily non-null in a failure
    /// branch.
    /// </para>
    /// <para>
    /// The same approach as <see cref="Services.GatewayAuthResult"/>: with the invariant written
    /// into the type, no call site has to reach for <c>!</c> or <c>?? "some fallback text"</c> of
    /// its own — sooner or later one of them is forgotten, and the forgotten one becomes a nullable
    /// warning.
    /// </para>
    /// </summary>
    [MemberNotNullWhen(false, nameof(ErrorMessage))]
    [MemberNotNullWhen(true, nameof(Account))]
    [MemberNotNullWhen(true, nameof(AuthMethod))]
    public bool IsSuccess { get; private set; }

    public string? ErrorMessage { get; private set; }

    public AccountEntity? Account { get; private set; }

    public string? AuthMethod { get; private set; }

    /// <summary>
    /// The display name; null is allowed, as it is an optional parameter of <see cref="Success"/>.
    /// </summary>
    public string? DisplayName { get; private set; }

    public Guid? LdapCredentialId { get; private set; }

    public Guid? SmsUserLoginId { get; private set; }

    public Guid? WechatUserLoginId { get; private set; }

    /// <summary>
    /// The OAuth 2.0 error code (RFC 6749 §5.2). <c>/api/auth/token</c> does not use it — the
    /// outward contract of that path is HTTP 200 plus message text; <c>/oauth2/token</c> uses it to
    /// decide the <c>error</c> field. It defaults to
    /// <see cref="OAuthErrorCodes.InvalidGrant"/> because credential failures are the vast majority;
    /// only "a parameter is missing" and "this application has not enabled this login method" need
    /// a different code stated explicitly at the call site.
    /// </summary>
    public string ErrorCode { get; private set; } = OAuthErrorCodes.InvalidGrant;

    /// <summary>
    /// This refresh is a cross-application exchange: the presented token belongs to
    /// <see cref="SourceAppId"/> and is admitted by a trust edge. The issuance path uses this to
    /// issue without rotating — the presented token is another application's session credential, and
    /// revoking it here would end that sign-in along the way. See
    /// docs/adr/0003-cross-application-refresh-grant.md.
    /// </summary>
    [MemberNotNullWhen(true, nameof(SourceAppId))]
    public bool IsCrossApplicationExchange { get; private set; }

    /// <summary>
    /// The AppId the exchanged refresh token belongs to; null when this is not a cross-application
    /// exchange.
    /// </summary>
    public string? SourceAppId { get; private set; }

    /// <summary>
    /// A login-attempt state change discovered while validating Password or LDAP credentials.
    /// Validation itself never persists this change: the Host applies it in the same unit of work
    /// as the corresponding login-history row.
    /// </summary>
    public LoginAttemptChange? LoginAttemptChange { get; private set; }

    /// <summary>
    /// A conditional OTP state change discovered during SMS validation. Validation never persists
    /// it; the Host applies it in the transaction that records the corresponding login result.
    /// </summary>
    public OtpVerificationChange? OtpVerificationChange { get; private set; }

    public static ValidationResult Success(
        AccountEntity account,
        string authMethod,
        string? displayName = null,
        Guid? ldapCredentialId = null,
        Guid? smsUserLoginId = null,
        Guid? wechatUserLoginId = null) => new()
        {
            IsSuccess = true,
            Account = account,
            AuthMethod = authMethod,
            DisplayName = displayName,
            LdapCredentialId = ldapCredentialId,
            SmsUserLoginId = smsUserLoginId,
            WechatUserLoginId = wechatUserLoginId
        };

    public static ValidationResult Failure(string message, string? errorCode = null) => new()
    {
        IsSuccess = false,
        ErrorMessage = message,
        ErrorCode = errorCode ?? OAuthErrorCodes.InvalidGrant
    };

    /// <summary>
    /// Marks a successful refresh validation as a cross-application exchange. It is only called in
    /// <see cref="RefreshTokenValidator"/>, immediately after <see cref="Success"/>. It is an
    /// instance method rather than two more optional parameters on Success because only one grant
    /// type has any use for this information, and putting it into the shared factory signature would
    /// force the other four call sites to skip past it.
    /// </summary>
    public ValidationResult AsCrossApplicationExchange(string sourceAppId)
    {
        IsCrossApplicationExchange = true;
        SourceAppId = sourceAppId;
        return this;
    }

    internal ValidationResult WithLoginAttemptChange(LoginAttemptChange? change)
    {
        LoginAttemptChange = change;
        return this;
    }

    internal ValidationResult WithOtpVerificationChange(OtpVerificationChange? change)
    {
        OtpVerificationChange = change;
        return this;
    }
}

public enum LoginAttemptChangeKind
{
    RecordFailure,
    Clear
}

public sealed record LoginAttemptChange(LoginAttemptChangeKind Kind, string Username);
