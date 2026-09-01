using SignaCore.Database.Entity;

namespace SignaCore.Host.Http;

/// <summary>
/// The single implementation for reading cross-cutting values off <see cref="HttpContext"/>.
/// AdminController, AuthController and GatewayController each used to carry their own copy of these
/// methods, and they did not behave alike (see the comments on <see cref="GetClientIp"/>). A new
/// controller reuses these.
/// </summary>
public static class HttpContextExtensions
{
    /// <summary>
    /// The client IP: the head of the X-Forwarded-For chain when present, otherwise the remote
    /// address of the connection.
    /// <para>
    /// Note that a header that exists but is blank also falls back to the remote address. The old
    /// AuthController copy returned an empty string in that case, which made the audit records of
    /// one and the same client differ depending on which controller had served the request.
    /// </para>
    /// </summary>
    public static string? GetClientIp(this HttpContext context)
    {
        var forwarded = context.Request.Headers[IdentityHeaders.ForwardedFor].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(forwarded))
        {
            return forwarded.Split(',')[0].Trim();
        }

        return context.Connection.RemoteIpAddress?.ToString();
    }

    public static string? GetUserAgent(this HttpContext context) =>
        context.Request.Headers.UserAgent.ToString();

    /// <summary>
    /// The correlation id of this request. It has to reuse the one
    /// <see cref="CorrelationIdMiddleware"/> already generated and wrote into the response headers
    /// and the logging scope, never generate another — otherwise, when a caller sends no
    /// x-correlation-id, the id recorded in the audit table would not match the one in the logs and
    /// the response headers, and the two could not be stitched together afterwards.
    /// </summary>
    public static string GetCorrelationId(this HttpContext context) =>
        context.Items[CorrelationIdMiddleware.HttpContextItemsKey] as string
        ?? context.Request.Headers[CorrelationIdMiddleware.CorrelationIdHeader].FirstOrDefault()
        ?? Guid.NewGuid().ToString("N");

    public static string? GetAppId(this HttpContext context) =>
        context.Items[IdentityHeaders.AppId] as string
        ?? context.Request.Headers[IdentityHeaders.AppId].FirstOrDefault();

    /// <summary>
    /// The redaction middleware has already moved the AppSecret into Items, so Items is read first
    /// and the request headers are only a fallback.
    /// </summary>
    public static string? GetAppSecret(this HttpContext context) =>
        context.Items[IdentityHeaders.AppSecret] as string
        ?? context.Request.Headers[IdentityHeaders.AppSecret].FirstOrDefault();

    public static AppRegistrationEntity? GetValidatedApp(this HttpContext context) =>
        context.Items[IdentityHeaders.ValidatedApp] as AppRegistrationEntity;
}
