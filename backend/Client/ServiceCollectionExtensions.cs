using System.Security.Cryptography;
using System.Text.Json;
using Grpc.Net.Client;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
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

        // 注册手动 JWKS 获取器（不依赖 ConfigurationManager）
        services.AddSingleton<JwksFetcher>(sp =>
        {
            var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger<JwksFetcher>();
            return new JwksFetcher(jwksEndpoint, logger);
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
                        var fetcher = context.HttpContext.RequestServices
                            .GetRequiredService<JwksFetcher>();
                        var keys = await fetcher.GetSigningKeysAsync();
                        context.Options.TokenValidationParameters.IssuerSigningKeys = keys;
                    }
                };
            });

        services.AddAuthorization();

        return services;
    }
}

/// <summary>
/// 手动获取并缓存 JWKS 签名密钥。绕过 ConfigurationManager 的潜在问题。
/// </summary>
public class JwksFetcher
{
    private readonly string _jwksEndpoint;
    private readonly ILogger<JwksFetcher> _logger;
    private readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromSeconds(10) };

    private List<SecurityKey>? _cachedKeys;
    private DateTimeOffset _cacheExpiry = DateTimeOffset.MinValue;
    private readonly object _lock = new();
    private readonly TimeSpan _cacheTtl = TimeSpan.FromMinutes(30);

    public JwksFetcher(string jwksEndpoint, ILogger<JwksFetcher> logger)
    {
        _jwksEndpoint = jwksEndpoint;
        _logger = logger;
    }

    public async Task<IList<SecurityKey>> GetSigningKeysAsync()
    {
        // 缓存命中
        if (_cachedKeys != null && DateTimeOffset.UtcNow < _cacheExpiry)
            return _cachedKeys;

        lock (_lock)
        {
            if (_cachedKeys != null && DateTimeOffset.UtcNow < _cacheExpiry)
                return _cachedKeys;
        }

        try
        {
            _logger.LogInformation("正在从 {Endpoint} 获取 JWKS...", _jwksEndpoint);
            var response = await _httpClient.GetAsync(_jwksEndpoint);
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync();

            var doc = JsonDocument.Parse(json);
            var keys = new List<SecurityKey>();

            if (doc.RootElement.TryGetProperty("keys", out var jwksKeys))
            {
                foreach (var jwk in jwksKeys.EnumerateArray())
                {
                    try
                    {
                        var rsa = RSA.Create();
                        var n = Base64UrlDecode(jwk.GetProperty("n").GetString()!);
                        var e = Base64UrlDecode(jwk.GetProperty("e").GetString()!);
                        rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = e });

                        var kid = jwk.TryGetProperty("kid", out var k) ? k.GetString() : null;
                        var key = new RsaSecurityKey(rsa) { KeyId = kid };
                        keys.Add(key);

                        _logger.LogInformation("已加载 RSA 密钥: kid={Kid}", kid);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "解析 JWKS 密钥失败，跳过");
                    }
                }
            }

            _logger.LogInformation("JWKS 获取成功: 共 {Count} 个签名密钥", keys.Count);

            lock (_lock)
            {
                _cachedKeys = keys;
                _cacheExpiry = DateTimeOffset.UtcNow.Add(_cacheTtl);
            }

            return keys;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "JWKS 获取失败: {Error}", ex.Message);

            // 返回空列表，让 JWT 验证自然失败
            return Array.Empty<SecurityKey>();
        }
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var output = input.Replace('-', '+').Replace('_', '/');
        switch (output.Length % 4)
        {
            case 2: output += "=="; break;
            case 3: output += "="; break;
        }
        return Convert.FromBase64String(output);
    }
}
