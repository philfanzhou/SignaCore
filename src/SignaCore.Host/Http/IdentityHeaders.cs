namespace SignaCore.Host.Http;

/// <summary>
/// The custom HTTP header names this service defines. They are shared across controllers and
/// middleware; they used to live on GatewayController, which made AuthController depend on
/// GatewayController at compile time, and as literals scattered around.
/// </summary>
public static class IdentityHeaders
{
    /// <summary>The caller's AppId. Required on every gateway-facing endpoint.</summary>
    public const string AppId = "X-Admin-AppId";

    /// <summary>
    /// The caller's AppSecret. <see cref="Middleware.SensitiveHeaderRedactionMiddleware"/> moves it
    /// from the request headers into <c>HttpContext.Items</c> before authorization runs, so
    /// authentication and business code must always read it through
    /// <see cref="HttpContextExtensions.GetAppSecret"/> and never from the request headers directly.
    /// </summary>
    public const string AppSecret = "X-Admin-AppSecret";

    /// <summary>
    /// The HttpContext.Items key the authentication handler caches the validated application entity
    /// under.
    /// </summary>
    public const string ValidatedApp = "SignaCore.ValidatedApp";

    /// <summary>The client IP chain forwarded by the reverse proxy.</summary>
    public const string ForwardedFor = "X-Forwarded-For";
}
