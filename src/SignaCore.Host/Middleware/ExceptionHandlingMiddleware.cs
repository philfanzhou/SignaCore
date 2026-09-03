using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace SignaCore.Host;

/// <summary>
/// Global HTTP exception handling middleware — Phase 2 replacement for
/// ExceptionHandlingInterceptor. Maps domain exceptions to RFC 7807-style
/// ProblemDetails JSON responses.
/// See the exception mapping rules in docs/development/ErrorHandling.md.
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
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            _logger.LogDebug("Request aborted by the client.");
        }
        catch (Exception ex)
        {
            _logger.LogError("Unhandled exception: Type={ExceptionType}", ex.GetType().Name);
            await WriteProblemDetailsAsync(context, ex);
        }
    }

    private static async Task WriteProblemDetailsAsync(HttpContext context, Exception ex)
    {
        if (context.Response.HasStarted)
        {
            return;
        }

        // Do not expose raw exception messages to clients — they may contain
        // internal field names, database details, or stack-like information.
        // The correlation is via server-side logs (see CorrelationIdMiddleware).
        var (status, title) = ex switch
        {
            ArgumentException => (StatusCodes.Status400BadRequest, "Bad Request"),
            InvalidOperationException => (StatusCodes.Status409Conflict, "Conflict"),
            _ => (StatusCodes.Status500InternalServerError, "Internal Server Error")
        };

        var detail = status == StatusCodes.Status500InternalServerError
            ? "An internal error occurred."
            : "The request could not be processed. See server logs for details.";

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
