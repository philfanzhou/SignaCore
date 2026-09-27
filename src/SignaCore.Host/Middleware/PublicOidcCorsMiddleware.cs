using Microsoft.EntityFrameworkCore;
using SignaCore.Database;
using SignaCore.Database.Entity;
using SignaCore.Domain.Validators;
using SignaCore.Host.Http;
using SignaCore.Host.Security;

namespace SignaCore.Host.Middleware;

/// <summary>
/// A preflight admits only a registered Public Origin and the endpoint's exact request shape.
/// Actual responses require a validated application binding; the preflight never supplies one.
/// </summary>
public sealed class PublicOidcCorsMiddleware(RequestDelegate next)
{
    private const string UserInfoAppIdItem = "SignaCore.UserInfoValidatedAppId";
    public static void BindUserInfo(HttpContext context, string appId) =>
        context.Items[UserInfoAppIdItem] = appId;

    public async Task InvokeAsync(HttpContext context, IdentityDbContext database, IWebHostEnvironment environment)
    {
        var token = context.Request.Path == "/oauth2/token";
        var userInfo = context.Request.Path == "/oauth2/userinfo";
        if (!token && !userInfo)
        {
            await next(context);
            return;
        }

        var origin = ReadOrigin(context, environment.IsDevelopment());
        if (HttpMethods.IsOptions(context.Request.Method))
        {
            AddVary(context.Response, "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers");
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.Pragma = "no-cache";
            context.Response.StatusCode = StatusCodes.Status204NoContent;
            if (origin is null || !ValidPreflight(context.Request, token))
            {
                return;
            }

            var registered = await database.AppAllowedOrigins.AsNoTracking().AnyAsync(
                row => row.CanonicalOrigin == origin
                    && row.AppRegistration.IsActive
                    && row.AppRegistration.ClientType == OidcClientType.Public,
                context.RequestAborted);
            if (registered && !context.RequestAborted.IsCancellationRequested)
            {
                context.Response.Headers.AccessControlAllowOrigin = origin;
                context.Response.Headers.AccessControlAllowMethods = token ? "POST" : "GET";
                context.Response.Headers.AccessControlAllowHeaders = token ? "Content-Type" : "Authorization";
            }

            return;
        }

        AddVary(context.Response, "Origin");
        if (origin is not null)
        {
            context.Response.OnStarting(async () =>
            {
                if (context.RequestAborted.IsCancellationRequested
                    || !(token ? HttpMethods.IsPost(context.Request.Method) : HttpMethods.IsGet(context.Request.Method)))
                {
                    return;
                }

                string? appId;
                if (token)
                {
                    appId = BoundedOidcFormReadingMiddleware.GetStatus(context) == OidcBoundedFormStatus.Parsed
                        && context.Request.HasFormContentType
                        && context.Request.Form["grant_type"].Count == 1
                        && context.Request.Form["grant_type"] == "authorization_code"
                        ? context.GetValidatedApp()?.AppId : null;
                }
                else
                {
                    appId = context.Items.TryGetValue(UserInfoAppIdItem, out var value) ? value as string : null;
                }

                if (appId is null)
                {
                    return;
                }

                var allowed = await database.AppAllowedOrigins.AsNoTracking().AnyAsync(
                    row => row.CanonicalOrigin == origin
                        && row.AppRegistration.AppId == appId
                        && row.AppRegistration.IsActive
                        && row.AppRegistration.ClientType == OidcClientType.Public,
                    context.RequestAborted);
                if (allowed && !context.RequestAborted.IsCancellationRequested)
                {
                    context.Response.Headers.AccessControlAllowOrigin = origin;
                }
            });
        }

        await next(context);
    }

    private static string? ReadOrigin(HttpContext context, bool development)
    {
        var values = context.Request.Headers.Origin;
        if (values.Count != 1)
        {
            return null;
        }

        var origin = values[0];
        try
        {
            var canonical = OidcAllowedOriginValidator.ValidateAndCanonicalize([origin!], development)[0];
            return string.Equals(origin, canonical, StringComparison.Ordinal) ? origin : null;
        }
        catch (OidcClientConfigurationException)
        {
            return null;
        }
    }

    private static bool ValidPreflight(HttpRequest request, bool token)
    {
        var method = request.Headers.AccessControlRequestMethod;
        var headers = request.Headers.AccessControlRequestHeaders;
        return method.Count == 1
            && string.Equals(method[0], token ? "POST" : "GET", StringComparison.Ordinal)
            && headers.Count == 1
            && string.Equals(headers[0], token ? "content-type" : "authorization", StringComparison.OrdinalIgnoreCase);
    }

    private static void AddVary(HttpResponse response, params string[] names)
    {
        var existing = response.Headers.Vary.ToString();
        var members = existing.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToList();
        foreach (var name in names)
        {
            if (!members.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                members.Add(name);
            }
        }

        response.Headers.Vary = string.Join(", ", members);
    }
}
