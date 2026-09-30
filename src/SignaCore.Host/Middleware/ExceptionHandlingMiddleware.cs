using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using ServiceMantle.Web.Http;

namespace SignaCore.Host;

/// <summary>Handles only failures before the shared HTTP exception boundary.</summary>
public class ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
{
    private static readonly object SharedPipelineEntry = new();

    internal static void MarkSharedPipelineEntry(HttpContext context) => context.Items[SharedPipelineEntry] = true;

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (Exception ex) when (!context.Items.ContainsKey(SharedPipelineEntry) &&
                                   !(ex is OperationCanceledException && context.RequestAborted.IsCancellationRequested))
        {
            logger.LogError("Unhandled pre-pipeline exception: Type={ExceptionType}", ex.GetType().Name);
            if (context.Response.HasStarted) return;

            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            context.Response.ContentType = "application/json";
            // Only fixed public values are serialized; writes retain the original request token.
            await JsonSerializer.SerializeAsync(context.Response.Body,
                new ProblemDetailsPayload(500, "Internal Server Error", "An internal error occurred."),
                cancellationToken: context.RequestAborted);
        }
    }

    private sealed record ProblemDetailsPayload(int Status, string Title, string Detail);
}

internal static class SignaCoreExceptionBoundary
{
    /// <summary>Marks this request before composing the shared pipeline exactly once.</summary>
    internal static WebApplication UseSignaCoreSharedHttpPipeline(this WebApplication app)
    {
        app.Use((context, next) =>
        {
            ExceptionHandlingMiddleware.MarkSharedPipelineEntry(context);
            return next(context);
        });
        return app.UseServiceMantlePipeline();
    }
}
