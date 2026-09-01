using Microsoft.Extensions.Logging;
using SignaCore.Domain;

namespace SignaCore.Host;

/// <summary>
/// The HTTP correlation id middleware: it reads the correlation id from the x-correlation-id request
/// header or creates a new one, injects it into the logging context through ILogger.BeginScope, and
/// writes it back on the response headers so the caller can correlate.
/// See how the correlation id propagates in docs/development/ErrorHandling.md.
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
        var correlationId = GetOrCreateCorrelationId(context);
        context.Items[HttpContextItemsKey] = correlationId;
        context.Response.Headers[CorrelationIdHeader] = correlationId;

        using var scope = _logger.BeginScope(new Dictionary<string, object>
        {
            [CorrelationIdLogKey] = LogValueSanitizer.Sanitize(correlationId)
        });

        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "HTTP request failed: CorrelationId={CorrelationId}, Method={Method}, Path={Path}",
                LogValueSanitizer.Sanitize(correlationId),
                LogValueSanitizer.Sanitize(context.Request.Method),
                LogValueSanitizer.Sanitize(context.Request.Path.Value));
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
