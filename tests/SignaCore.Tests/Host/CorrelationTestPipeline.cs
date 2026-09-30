using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SignaCore.Host;

namespace SignaCore.Tests.Host;

/// <summary>
/// Runs the real ServiceMantle correlation middleware over an in-process <see cref="HttpContext"/>,
/// through the same public registration (<see cref="ServiceMantleComposition.AddSignaCoreServiceMantle"/>
/// plus <c>UseServiceMantleCorrelationId</c>) that the three production hosts compose. Tests use it
/// to establish the correlation slot exactly as production does — never by writing the library's
/// private slot key directly.
/// </summary>
internal static class CorrelationTestPipeline
{
    private static readonly RequestDelegate Pipeline = Build();

    /// <summary>
    /// Runs the middleware once for the context, synchronously. The middleware pipeline completes
    /// without asynchronous I/O, so test doubles can call this from synchronous setup helpers.
    /// </summary>
    public static void Establish(HttpContext context, string? correlationId = null) =>
        EstablishAsync(context, correlationId).GetAwaiter().GetResult();

    /// <summary>
    /// Runs the middleware once for the context. When <paramref name="correlationId"/> is not null
    /// it is first placed on the request header, so an accepted-shape value flows through the real
    /// validation exactly like a caller-supplied header.
    /// </summary>
    public static async Task EstablishAsync(HttpContext context, string? correlationId = null)
    {
        if (correlationId is not null)
        {
            context.Request.Headers[ServiceMantle.Web.Http.ServiceHeaderNames.CorrelationId] = correlationId;
        }

        await Pipeline(context);
    }

    private static RequestDelegate Build()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSignaCoreServiceMantle();
        var provider = services.BuildServiceProvider();
        var app = new ApplicationBuilder(provider);
        app.UseServiceMantleCorrelationId();
        return app.Build();
    }
}
