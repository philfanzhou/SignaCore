using Grpc.Net.Client;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using QuantumZhou.Identity.Contract.Protos;

namespace QuantumZhou.Identity.Client;

/// <summary>
/// IServiceCollection 扩展方法，注册 Identity Client SDK 所有服务。
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// 注册 Identity Client SDK：gRPC 客户端 + JWT Bearer 认证 + 授权。
    /// </summary>
    public static IServiceCollection AddIdentityClient(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var options = new IdentityClientOptions();
        configuration.GetSection(IdentityClientOptions.SectionName).Bind(options);

        // 允许从 Jwt 配置节覆盖
        var jwtIssuer = configuration["Jwt:Issuer"] ?? options.JwtIssuer;
        var jwtAudience = configuration["Jwt:Audience"] ?? options.JwtAudience;
        var jwksEndpoint = configuration["Jwt:JwksEndpoint"] ?? options.JwksEndpoint;

        // 注册配置选项
        services.AddSingleton(options);

        // 注册 Identity gRPC 客户端
        services.AddSingleton(sp =>
        {
            var channel = GrpcChannel.ForAddress(options.GrpcEndpoint);
            return new AuthGrpcService.AuthGrpcServiceClient(channel);
        });

        // 注册 JWKS 配置管理器
        services.AddSingleton<IConfigurationManager<OpenIdConnectConfiguration>>(sp =>
        {
            var httpClient = new HttpClient();
            var retriever = new OpenIdConnectConfigurationRetriever();
            return new ConfigurationManager<OpenIdConnectConfiguration>(
                jwksEndpoint,
                retriever,
                new HttpDocumentRetriever(httpClient) { RequireHttps = options.RequireHttpsForJwks });
        });

        // 注册 JWT Bearer 认证
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(jwtOptions =>
            {
                jwtOptions.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtIssuer,
                    ValidAudience = jwtAudience,
                    ClockSkew = TimeSpan.FromSeconds(30)
                };

                jwtOptions.Events = new JwtBearerEvents
                {
                    OnMessageReceived = async context =>
                    {
                        var logger = context.HttpContext.RequestServices
                            .GetRequiredService<ILoggerFactory>()
                            .CreateLogger("Identity.Client.Jwks");

                        try
                        {
                            var configManager = context.HttpContext.RequestServices
                                .GetRequiredService<IConfigurationManager<OpenIdConnectConfiguration>>();
                            var config = await configManager.GetConfigurationAsync(context.HttpContext.RequestAborted);
                            context.Options.TokenValidationParameters.IssuerSigningKeys = config.SigningKeys;
                            logger.LogDebug("JWKS loaded: {KeyCount} signing key(s)", config.SigningKeys.Count);
                        }
                        catch (Exception ex)
                        {
                            logger.LogError(ex, "JWKS fetch failed: {Error}", ex.Message);
                            throw;
                        }
                    }
                };
            });

        services.AddAuthorization();

        return services;
    }
}
