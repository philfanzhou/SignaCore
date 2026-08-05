using System.Diagnostics.CodeAnalysis;
using QuantumZhou.Identity.Database.Entity;

namespace QuantumZhou.Identity.Domain.Validators;

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

    public static ValidationResult Success(AccountEntity account, string authMethod, string? displayName = null) => new()
    {
        IsSuccess = true,
        Account = account,
        AuthMethod = authMethod,
        DisplayName = displayName
    };

    public static ValidationResult Failure(string message) => new()
    {
        IsSuccess = false,
        ErrorMessage = message
    };
}