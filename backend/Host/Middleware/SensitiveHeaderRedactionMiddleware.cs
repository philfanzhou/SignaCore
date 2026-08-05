using QuantumZhou.Identity.Host.Http;

namespace QuantumZhou.Identity.Host.Middleware;

/// <summary>
/// Strips the X-Admin-AppSecret header from incoming requests before authorization,
/// moving the value into HttpContext.Items so downstream logging/middleware cannot
/// record the secret. Gateway authentication and controllers read Items first.
/// </summary>
public class SensitiveHeaderRedactionMiddleware
{
    private readonly RequestDelegate _next;

    public SensitiveHeaderRedactionMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Headers.TryGetValue(IdentityHeaders.AppSecret, out var secretValue))
        {
            context.Items[IdentityHeaders.AppSecret] = secretValue.ToString();
            context.Request.Headers.Remove(IdentityHeaders.AppSecret);
        }

        await _next(context);
    }
}
