using System.Text.Json;

namespace SignaCore.Host.Middleware;

/// <summary>
/// The only traffic policy Bootstrap Configuration Mode has: the bootstrap page, its API, and health
/// are reachable; everything else is explicitly not available yet.
/// <para>
/// API clients receive a structured <c>503 bootstrap_configuration_required</c> rather than an HTML
/// redirect — a token request that silently follows a redirect into a configuration page is far
/// harder to diagnose than an explicit status. Only browser navigation is redirected.
/// </para>
/// </summary>
internal sealed class BootstrapModeGateMiddleware
{
    public const string BootstrapPath = "/bootstrap";

    private static readonly string[] AlwaysAllowedPrefixes =
        ["/api/bootstrap", "/health"];

    private static readonly string[] BlockedApiPrefixes =
        ["/api", "/oauth2", "/.well-known", "/consul", "/metrics"];

    private static readonly byte[] BootstrapRequiredBody = JsonSerializer.SerializeToUtf8Bytes(new
    {
        error = "bootstrap_configuration_required",
        error_description =
            "SignaCore has no bootstrap configuration. Complete it at /bootstrap before using this API."
    });

    private readonly RequestDelegate _next;

    public BootstrapModeGateMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path;

        if (AlwaysAllowedPrefixes.Any(prefix => path.StartsWithSegments(prefix)))
        {
            await _next(context);
            return;
        }

        if (BlockedApiPrefixes.Any(prefix => path.StartsWithSegments(prefix)))
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.ContentType = "application/json; charset=utf-8";
            context.Response.Headers.RetryAfter = "30";
            await context.Response.Body.WriteAsync(BootstrapRequiredBody, context.RequestAborted);
            return;
        }

        if (path.StartsWithSegments(BootstrapPath))
        {
            await _next(context);
            return;
        }

        if (IsBrowserNavigation(context.Request))
        {
            context.Response.Redirect(BootstrapPath);
            return;
        }

        // Static assets referenced by the bootstrap page fall through to the SPA branch.
        await _next(context);
    }

    private static bool IsBrowserNavigation(HttpRequest request)
    {
        if (!HttpMethods.IsGet(request.Method))
        {
            return false;
        }

        foreach (var accept in request.Headers.Accept)
        {
            if (accept?.Contains("text/html", StringComparison.OrdinalIgnoreCase) == true)
            {
                return true;
            }
        }

        return false;
    }
}
