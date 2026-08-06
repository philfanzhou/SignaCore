using System.Diagnostics.CodeAnalysis;
using SignaCore.Database.Entity;

namespace SignaCore.Domain.Services;

public class GatewayAuthResult
{
    /// <summary>
    /// 网关校验是否通过。
    /// <para>
    /// <see cref="MemberNotNullWhenAttribute"/> 把"失败一定带原因"这条不变量交给编译器：
    /// <see cref="Failure"/> 的参数是非空 <see cref="string"/>，而实例只可能由下面两个工厂
    /// 方法产生（属性都是 private set，外部构造不出来），因此 <c>if (!result.IsSuccess)</c>
    /// 分支里 <see cref="ErrorMessage"/> 必然非 null。
    /// </para>
    /// <para>
    /// 没有这条标注时，每个调用点只能各自 <c>!</c> 或 <c>?? "兜底文案"</c>——同一个不变量
    /// 一度在四处有四种写法，其中一处漏写就留下了 nullable 警告。
    /// </para>
    /// </summary>
    [MemberNotNullWhen(false, nameof(ErrorMessage))]
    public bool IsSuccess { get; private set; }

    public string? ErrorMessage { get; private set; }

    public AppRegistrationEntity? App { get; private set; }

    public static GatewayAuthResult Success(AppRegistrationEntity? app = null) => new()
    {
        IsSuccess = true,
        App = app
    };

    public static GatewayAuthResult Failure(string message) => new()
    {
        IsSuccess = false,
        ErrorMessage = message
    };
}
