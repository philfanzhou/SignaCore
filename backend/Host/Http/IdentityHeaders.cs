namespace QuantumZhou.Identity.Host.Http;

/// <summary>
/// 本服务约定的自定义 HTTP 头名。跨 controller 与中间件共用，
/// 之前散落在 GatewayController 上（导致 AuthController 编译期依赖 GatewayController）
/// 和各处字面量里。
/// </summary>
public static class IdentityHeaders
{
    /// <summary>调用方 AppId。/api/gateway/* 必填；/api/auth/token 可选，带了才做网关校验。</summary>
    public const string AppId = "X-Admin-AppId";

    /// <summary>
    /// 调用方 AppSecret。<see cref="Middleware.SensitiveHeaderRedactionMiddleware"/> 会在认证之后
    /// 把它从请求头搬到 <c>HttpContext.Items</c>，因此读取一律走
    /// <see cref="HttpContextExtensions.GetAppSecret"/>，不要直接读请求头。
    /// </summary>
    public const string AppSecret = "X-Admin-AppSecret";

    /// <summary>反向代理透传的客户端 IP 链。</summary>
    public const string ForwardedFor = "X-Forwarded-For";
}
