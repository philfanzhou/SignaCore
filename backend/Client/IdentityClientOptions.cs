namespace QuantumZhou.Identity.Client;

/// <summary>
/// Identity Client SDK 配置项。
/// </summary>
public class IdentityClientOptions
{
    public const string SectionName = "Identity";

    /// <summary>
    /// Identity gRPC 服务地址。
    /// </summary>
    public string GrpcEndpoint { get; set; } = "http://localhost:5001";

    /// <summary>
    /// 在 Identity 注册的 AppId。
    /// </summary>
    public string AppId { get; set; } = string.Empty;

    /// <summary>
    /// AppSecret，优先从环境变量 IDENTITY_APP_SECRET 读取。
    /// </summary>
    public string AppSecret { get; set; } = string.Empty;

    /// <summary>
    /// JWT 签发者。
    /// </summary>
    public string JwtIssuer { get; set; } = "QuantumZhou.Identity";

    /// <summary>
    /// JWT 受众。
    /// </summary>
    public string JwtAudience { get; set; } = "QuantumZhou.microservices";

    /// <summary>
    /// JWKS 公钥端点。
    /// </summary>
    public string JwksEndpoint { get; set; } = "http://localhost:5002/.well-known/jwks";

    /// <summary>
    /// 认证端点路径前缀。
    /// </summary>
    public string AuthEndpointPrefix { get; set; } = "/admin/auth";

    /// <summary>
    /// 获取 AppSecret，优先从环境变量读取。
    /// </summary>
    public string GetEffectiveAppSecret() =>
        Environment.GetEnvironmentVariable("IDENTITY_APP_SECRET") ?? AppSecret;
}
