namespace QuantumZhou.Identity.Host.Middleware;

/// <summary>
/// Strips the X-Admin-AppSecret header from incoming requests after authentication,
/// moving the value into HttpContext.Items so downstream logging/middleware cannot
/// accidentally record the secret. Controllers read the secret from Items first.
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
        if (context.Request.Headers.TryGetValue(Controllers.GatewayController.AppSecretHeader, out var secretValue))
        {
            context.Items[Controllers.GatewayController.AppSecretHeader] = secretValue.ToString();
            context.Request.Headers.Remove(Controllers.GatewayController.AppSecretHeader);
        }

        await _next(context);
    }
}
