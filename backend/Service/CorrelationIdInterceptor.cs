using Grpc.Core;
using Grpc.Core.Interceptors;
using Microsoft.Extensions.Logging;

namespace QuantumZhou.Identity.Service;

public class CorrelationIdInterceptor : Interceptor
{
    private const string CorrelationIdHeader = "x-correlation-id";
    private const string CorrelationIdLogKey = "CorrelationId";
    private readonly ILogger<CorrelationIdInterceptor> _logger;

    public CorrelationIdInterceptor(ILogger<CorrelationIdInterceptor> logger)
    {
        _logger = logger;
    }

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        var correlationId = GetOrCreateCorrelationId(context);

        using var scope = _logger.BeginScope(new Dictionary<string, object>
        {
            [CorrelationIdLogKey] = correlationId
        });

        context.ResponseTrailers.Add(CorrelationIdHeader, correlationId);

        _logger.LogDebug("Processing request: CorrelationId={CorrelationId}, Method={Method}", correlationId, context.Method);

        try
        {
            return await continuation(request, context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Request failed: CorrelationId={CorrelationId}", correlationId);
            throw;
        }
    }

    private static string GetOrCreateCorrelationId(ServerCallContext context)
    {
        var correlationId = context.RequestHeaders.FirstOrDefault(h => h.Key.Equals(CorrelationIdHeader, StringComparison.OrdinalIgnoreCase))?.Value;
        
        if (string.IsNullOrEmpty(correlationId))
        {
            correlationId = Guid.NewGuid().ToString("N");
        }

        return correlationId;
    }
}
