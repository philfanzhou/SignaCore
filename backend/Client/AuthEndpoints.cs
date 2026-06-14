using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using QuantumZhou.Identity.Contract.Protos;

namespace QuantumZhou.Identity.Client;

/// <summary>
/// ILogger category marker for AuthEndpoints.
/// </summary>
internal class AuthEndpointsLogger { }

/// <summary>
/// 认证端点实现，代理 Identity gRPC GetToken 接口。
/// </summary>
internal static class AuthEndpoints
{
    public static async Task<IResult> Login(
        LoginRequest request,
        AuthGrpcService.AuthGrpcServiceClient identityClient,
        IdentityClientOptions options,
        ILogger<AuthEndpointsLogger> logger)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
            return Results.BadRequest(new { success = false, message = "用户名和密码不能为空" });

        var appSecret = options.GetEffectiveAppSecret();

        try
        {
            var tokenRequest = new GetTokenRequest
            {
                GrantType = "password",
                AppId = options.AppId,
                AppSecret = appSecret,
                Password = new PasswordCredential
                {
                    Username = request.Username.Trim(),
                    Password = request.Password
                }
            };

            var response = await identityClient.GetTokenAsync(tokenRequest);

            if (!response.Success)
            {
                logger.LogWarning("登录失败: Username={Username}, Reason={Reason}",
                    request.Username.Trim(), response.Message);
                return Results.Unauthorized();
            }

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    accessToken = response.AccessToken,
                    refreshToken = response.RefreshToken,
                    expiresIn = response.ExpiresIn,
                    expiresAt = response.ExpiresAt,
                    userInfo = new
                    {
                        userId = response.UserInfo.UserId,
                        username = response.UserInfo.Username,
                        authMethod = response.UserInfo.AuthMethod,
                        roles = response.UserInfo.Roles,
                        permissions = response.UserInfo.Permissions
                    }
                }
            });
        }
        catch (Grpc.Core.RpcException ex)
        {
            logger.LogError(ex, "Identity gRPC 调用失败: Username={Username}", request.Username.Trim());
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }

    public static async Task<IResult> Refresh(
        RefreshRequest request,
        AuthGrpcService.AuthGrpcServiceClient identityClient,
        IdentityClientOptions options,
        ILogger<AuthEndpointsLogger> logger)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
            return Results.BadRequest(new { success = false, message = "RefreshToken 不能为空" });

        var appSecret = options.GetEffectiveAppSecret();

        try
        {
            var tokenRequest = new GetTokenRequest
            {
                GrantType = "refresh_token",
                AppId = options.AppId,
                AppSecret = appSecret,
                RefreshToken = new RefreshTokenCredential
                {
                    RefreshToken = request.RefreshToken
                }
            };

            var response = await identityClient.GetTokenAsync(tokenRequest);

            if (!response.Success)
            {
                logger.LogWarning("Token 刷新失败: Reason={Reason}", response.Message);
                return Results.Unauthorized();
            }

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    accessToken = response.AccessToken,
                    refreshToken = response.RefreshToken,
                    expiresIn = response.ExpiresIn,
                    expiresAt = response.ExpiresAt
                }
            });
        }
        catch (Grpc.Core.RpcException ex)
        {
            logger.LogError(ex, "Identity gRPC 调用失败 (refresh)");
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }

    public static Task<IResult> GetCurrentUser(ClaimsPrincipal user)
    {
        var userId = user.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
        var username = user.FindFirstValue(ClaimTypes.Name) ?? string.Empty;
        var authMethod = user.FindFirstValue("auth_method") ?? string.Empty;
        var roles = user.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
        var permissions = user.FindAll("Permission").Select(c => c.Value).ToList();

        return Task.FromResult(Results.Ok(new
        {
            success = true,
            data = new { userId, username, authMethod, roles, permissions }
        }));
    }

    public static Task<IResult> Logout(ClaimsPrincipal user)
    {
        // JWT 是无状态的，登出主要是前端清除本地 Token
        return Task.FromResult(Results.Ok(new { success = true, message = "已登出" }));
    }
}

/// <summary>
/// 登录请求。
/// </summary>
public record LoginRequest(string Username, string Password);

/// <summary>
/// Token 刷新请求。
/// </summary>
public record RefreshRequest(string RefreshToken);
