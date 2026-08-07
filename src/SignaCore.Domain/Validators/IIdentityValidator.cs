using System.Diagnostics.CodeAnalysis;
using SignaCore.Database.Entity;

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

    /// <summary>短信验证码或微信 code，按 <see cref="GrantType"/> 解释。</summary>
    public string? Code { get; set; }

    public string? RefreshToken { get; set; }
    public string? AppId { get; set; }
    public AppRegistrationEntity? App { get; set; }
    public CancellationToken CancellationToken { get; set; }
}

public class ValidationResult
{
    /// <summary>
    /// 校验是否通过。
    /// <para>
    /// 三条 <see cref="MemberNotNullWhenAttribute"/> 把工厂方法的签名保证交给编译器：
    /// <see cref="Success"/> 的 <c>account</c> / <c>authMethod</c> 与 <see cref="Failure"/>
    /// 的 <c>message</c> 都是非空参数，而实例只能由这两个方法产生（属性都是 private set），
    /// 所以成功分支里 <see cref="Account"/> / <see cref="AuthMethod"/> 必然非 null，
    /// 失败分支里 <see cref="ErrorMessage"/> 必然非 null。
    /// </para>
    /// <para>
    /// 与 <see cref="Services.GatewayAuthResult"/> 同一套做法：不变量写进类型，调用点就不必
    /// 各自 <c>!</c> 或 <c>?? "兜底文案"</c>——那样迟早会漏，而漏掉的那处就成了 nullable 警告。
    /// </para>
    /// </summary>
    [MemberNotNullWhen(false, nameof(ErrorMessage))]
    [MemberNotNullWhen(true, nameof(Account))]
    [MemberNotNullWhen(true, nameof(AuthMethod))]
    public bool IsSuccess { get; private set; }

    public string? ErrorMessage { get; private set; }

    public AccountEntity? Account { get; private set; }

    public string? AuthMethod { get; private set; }

    /// <summary>展示名，允许为 null（<see cref="Success"/> 的可选参数）。</summary>
    public string? DisplayName { get; private set; }

    public Guid? LdapCredentialId { get; private set; }

    public Guid? SmsUserLoginId { get; private set; }

    public Guid? WechatUserLoginId { get; private set; }

    /// <summary>
    /// OAuth 2.0 错误码（RFC 6749 §5.2）。<c>/api/auth/token</c> 不用它——那条路的对外契约是
    /// HTTP 200 + 文案；<c>/oauth2/token</c> 用它决定 <c>error</c> 字段。默认
    /// <see cref="OAuthErrorCodes.InvalidGrant"/>：凭据类失败是绝大多数，只有"参数缺失"和
    /// "该应用未开通此登录方式"需要在调用点显式给别的码。
    /// </summary>
    public string ErrorCode { get; private set; } = OAuthErrorCodes.InvalidGrant;

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
}
