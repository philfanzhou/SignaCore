namespace QuantumZhou.Identity.Host.Http;

/// <summary>
/// 从 <see cref="HttpContext"/> 取横切值的唯一实现。
/// 这些方法此前在 AdminController / AuthController / GatewayController 里各有一份，
/// 且行为并不一致（见 <see cref="GetClientIp"/> 注释）。新增 controller 请复用这里。
/// </summary>
public static class HttpContextExtensions
{
    /// <summary>
    /// 客户端 IP：优先取 X-Forwarded-For 链首，否则取连接的远端地址。
    /// <para>
    /// 注意：头存在但为空白时也回落到远端地址。此前 AuthController 那份实现会在这种情况下
    /// 返回空字符串，导致同一个客户端的审计记录因为走哪个 controller 而不同。
    /// </para>
    /// </summary>
    public static string? GetClientIp(this HttpContext context)
    {
        var forwarded = context.Request.Headers[IdentityHeaders.ForwardedFor].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(forwarded))
        {
            return forwarded.Split(',')[0].Trim();
        }

        return context.Connection.RemoteIpAddress?.ToString();
    }

    public static string? GetUserAgent(this HttpContext context) =>
        context.Request.Headers.UserAgent.ToString();

    /// <summary>
    /// 本次请求的 CorrelationId。必须复用 <see cref="CorrelationIdMiddleware"/> 已生成、
    /// 并写入响应头与日志 scope 的那一个，不能另生成——否则调用方没带 x-correlation-id 时，
    /// 审计表里记的 ID 和日志/响应头里的 ID 对不上，事后无法串联。
    /// </summary>
    public static string GetCorrelationId(this HttpContext context) =>
        context.Items[CorrelationIdMiddleware.HttpContextItemsKey] as string
        ?? context.Request.Headers[CorrelationIdMiddleware.CorrelationIdHeader].FirstOrDefault()
        ?? Guid.NewGuid().ToString("N");

    public static string? GetAppId(this HttpContext context) =>
        context.Items[IdentityHeaders.AppId] as string
        ?? context.Request.Headers[IdentityHeaders.AppId].FirstOrDefault();

    /// <summary>AppSecret 已被脱敏中间件搬到 Items，故先读 Items 再回落请求头。</summary>
    public static string? GetAppSecret(this HttpContext context) =>
        context.Items[IdentityHeaders.AppSecret] as string
        ?? context.Request.Headers[IdentityHeaders.AppSecret].FirstOrDefault();
}
