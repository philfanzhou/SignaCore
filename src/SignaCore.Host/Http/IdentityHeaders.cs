namespace SignaCore.Host.Http;

/// <summary>
/// 本服务约定的自定义 HTTP 头名。跨 controller 与中间件共用，
/// 之前散落在 GatewayController 上（导致 AuthController 编译期依赖 GatewayController）
/// 和各处字面量里。
/// </summary>
public static class IdentityHeaders
{
    /// <summary>调用方 AppId。所有 gateway-facing 端点必填。</summary>
    public const string AppId = "X-Admin-AppId";

    /// <summary>
    /// 调用方 AppSecret。<see cref="Middleware.SensitiveHeaderRedactionMiddleware"/> 会在授权之前
    /// 把它从请求头搬到 <c>HttpContext.Items</c>，因此认证和业务代码读取一律走
    /// <see cref="HttpContextExtensions.GetAppSecret"/>，不要直接读请求头。
    /// </summary>
    public const string AppSecret = "X-Admin-AppSecret";

    /// <summary>认证处理器缓存已验证应用实体所用的 HttpContext.Items 键。</summary>
    public const string ValidatedApp = "SignaCore.ValidatedApp";

    /// <summary>反向代理透传的客户端 IP 链。</summary>
    public const string ForwardedFor = "X-Forwarded-For";
}
