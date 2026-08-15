using System.Text.Json;

namespace SignaCore.Host.Middleware;

/// <summary>
/// The only traffic policy Setup Mode has: first-run setup and health are reachable, everything else
/// is explicitly not ready.
/// <para>
/// API clients receive a structured <c>503 installation_required</c> rather than an HTML redirect —
/// a token request that silently follows a redirect into the setup page is far harder to diagnose
/// than an explicit status. Only browser navigation is redirected.
/// </para>
/// </summary>
internal sealed class SetupModeGateMiddleware
{
    public const string SetupPath = "/setup";

    // /api/bootstrap is allowed so the console's startup probe learns that this instance is past
    // bootstrap configuration instead of reading a 503 as "unknown state".
    private static readonly string[] AlwaysAllowedPrefixes =
        ["/api/setup", "/api/bootstrap", "/health", "/metrics"];

    private static readonly string[] BlockedApiPrefixes =
        ["/api", "/oauth2", "/.well-known", "/consul"];

    private static readonly byte[] InstallationRequiredBody = JsonSerializer.SerializeToUtf8Bytes(new
    {
        error = "installation_required",
        error_description =
            "SignaCore has not been initialized. Complete first-run setup at /setup before using this API."
    });

    private readonly RequestDelegate _next;

    public SetupModeGateMiddleware(RequestDelegate next)
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
            await context.Response.Body.WriteAsync(InstallationRequiredBody, context.RequestAborted);
            return;
        }

        if (path.StartsWithSegments(SetupPath))
        {
            await _next(context);
            return;
        }

        if (IsBrowserNavigation(context.Request))
        {
            context.Response.Redirect(SetupPath);
            return;
        }

        // Static assets referenced by the setup page fall through to the SPA branch.
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
