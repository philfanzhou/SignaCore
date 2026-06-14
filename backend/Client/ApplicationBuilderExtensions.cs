using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace QuantumZhou.Identity.Client;

/// <summary>
/// WebApplication 扩展方法，启用 Identity Client SDK 中间件和端点。
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// 启用认证和授权中间件。
    /// </summary>
    public static WebApplication UseIdentityClient(this WebApplication app)
    {
        app.UseAuthentication();
        app.UseAuthorization();
        return app;
    }

    /// <summary>
    /// 映射认证端点（login/refresh/me/logout）。
    /// </summary>
    public static WebApplication MapIdentityAuthEndpoints(this WebApplication app)
    {
        var options = app.Services.GetRequiredService<IdentityClientOptions>();
        var group = app.MapGroup(options.AuthEndpointPrefix);

        group.MapPost("/login", AuthEndpoints.Login).AllowAnonymous();
        group.MapPost("/refresh", AuthEndpoints.Refresh).AllowAnonymous();
        group.MapGet("/me", AuthEndpoints.GetCurrentUser).RequireAuthorization();
        group.MapPost("/logout", AuthEndpoints.Logout).RequireAuthorization();

        return app;
    }
}
