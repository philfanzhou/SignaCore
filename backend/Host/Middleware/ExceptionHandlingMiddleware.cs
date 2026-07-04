using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace QuantumZhou.Identity.Host;

/// <summary>
/// Global HTTP exception handling middleware — Phase 2 replacement for
/// ExceptionHandlingInterceptor. Maps domain exceptions to RFC 7807-style
/// ProblemDetails JSON responses.
/// 详见 docs/development/ErrorHandling.md「异常映射」。
/// </summary>
public class ExceptionHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ExceptionHandlingMiddleware> _logger;

    public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception: Type={ExceptionType}, Message={Message}",
                ex.GetType().Name, ex.Message);
            await WriteProblemDetailsAsync(context, ex);
        }
    }

    private static async Task WriteProblemDetailsAsync(HttpContext context, Exception ex)
    {
        var (status, title, detail) = ex switch
        {
            ArgumentException ae => (StatusCodes.Status400BadRequest, "Bad Request", ae.Message),
            InvalidOperationException ioe => (StatusCodes.Status409Conflict, "Conflict", ioe.Message),
            _ => (StatusCodes.Status500InternalServerError, "Internal Server Error", "An internal error occurred.")
        };

        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";

        var body = new ProblemDetailsPayload
        {
            Status = status,
            Title = title,
            Detail = detail
        };
        await JsonSerializer.SerializeAsync(context.Response.Body, body);
    }

    private sealed class ProblemDetailsPayload
    {
        public int Status { get; init; }
        public string Title { get; init; } = string.Empty;
        public string Detail { get; init; } = string.Empty;
    }
}
