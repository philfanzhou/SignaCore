using Microsoft.Extensions.Logging;

namespace QuantumZhou.Identity.Host;

/// <summary>
/// HTTP CorrelationId 中间件：从请求头 x-correlation-id 读取或新建 CorrelationId，
/// 通过 ILogger.BeginScope 注入日志上下文，并回写响应头便于调用方关联。
/// 与 gRPC CorrelationIdInterceptor 使用相同的请求头名称。
/// 详见 docs/development/ErrorHandling.md「CorrelationId 流转」。
/// </summary>
public class CorrelationIdMiddleware
{
    public const string CorrelationIdHeader = "x-correlation-id";
    public const string CorrelationIdLogKey = "CorrelationId";
    public const string HttpContextItemsKey = "__CorrelationId";

    private readonly RequestDelegate _next;
    private readonly ILogger<CorrelationIdMiddleware> _logger;

    public CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // gRPC 请求由 CorrelationIdInterceptor 处理，避免双重生成 CorrelationId
        var contentType = context.Request.ContentType;
        if (contentType != null && contentType.StartsWith("application/grpc", StringComparison.OrdinalIgnoreCase))
        {
            await _next(context);
            return;
        }

        var correlationId = GetOrCreateCorrelationId(context);
        context.Items[HttpContextItemsKey] = correlationId;
        context.Response.Headers[CorrelationIdHeader] = correlationId;

        using var scope = _logger.BeginScope(new Dictionary<string, object>
        {
            [CorrelationIdLogKey] = correlationId
        });

        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "HTTP request failed: CorrelationId={CorrelationId}, Method={Method}, Path={Path}",
                correlationId, context.Request.Method, context.Request.Path);
            throw;
        }
    }

    private static string GetOrCreateCorrelationId(HttpContext context)
    {
        var correlationId = context.Request.Headers[CorrelationIdHeader].FirstOrDefault();
        if (string.IsNullOrEmpty(correlationId))
        {
            correlationId = Guid.NewGuid().ToString("N");
        }
        return correlationId;
    }
}
