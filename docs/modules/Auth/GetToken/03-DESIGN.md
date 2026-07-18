# 统一 Token 获取 — 设计说明 (DESIGN)

## 本功能在项目中的目录与文件结构

```
backend/
├── Host/Controllers/AuthController.cs  # HTTP REST 控制器（GetToken 入口）
├── Host/AdminBootstrapOptions.cs        # bootstrap admin 配置（Username/Password）
├── Domain/
│   ├── Validators/
│   │   ├── IIdentityValidator.cs       # 验证器接口
│   │   ├── ValidatorFactory.cs         # 验证器工厂
│   │   ├── PasswordValidator.cs        # 密码登录验证
│   │   ├── SmsValidator.cs             # 短信登录验证
│   │   ├── WechatValidator.cs          # 微信登录验证
│   │   └── RefreshTokenValidator.cs    # 刷新令牌验证
│   ├── ClaimsResolver.cs               # Claims 构建
│   ├── CallbackService.cs              # 回调权限注入
│   ├── Services/
│   │   ├── TokenService.cs             # JWT 签发
│   │   ├── GatewayValidationService.cs # 网关验证
│   │   ├── CallbackUrlValidator.cs     # 回调 URL 验证
│   │   ├── Sms/DbOtpService.cs         # OTP 验证
│   │   └── WeChat/WechatApiClient.cs   # 微信 API 客户端
│   ├── KeyManager.cs                   # RSA 密钥管理
│   └── AuthMetrics.cs                  # 指标收集
└── Database/
    ├── Entity/AccountEntity.cs          # 账户实体
    ├── Entity/PasswordCredentialEntity.cs
    ├── Entity/UserLoginEntity.cs
    ├── Entity/RefreshTokenEntity.cs
    ├── Entity/AppRegistrationEntity.cs
    ├── Entity/LoginAttemptEntity.cs
    └── Repositories/IRepositories.cs    # 仓储接口
```

## 关键接口签名和数据结构定义

```csharp
// HTTP 端点（AuthController）
[Route("api/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    [HttpPost("token")]              // GetToken（统一 Token 获取）
    [HttpPost("sms-code")]           // RequestSmsCode（请求短信验证码）
    [HttpPost("revoke")]             // RevokeRefreshToken（吊销刷新令牌）
    [HttpPost("callback/register")]  // RegisterCallback（注册回调）
}

// 验证器接口
public interface IIdentityValidator {
    string GrantType { get; }
    Task<ValidationResult> ValidateAsync(ValidationRequest request);
}

// 验证结果
public class ValidationResult {
    public bool IsSuccess { get; set; }
    public string? ErrorMessage { get; set; }
    public AccountEntity? Account { get; set; }
    public string? AuthMethod { get; set; }
    public string? DisplayName { get; set; }
}

// 网关验证结果
public class GatewayAuthResult {
    public bool IsSuccess { get; set; }
    public string? ErrorMessage { get; set; }
    public AppRegistrationEntity? App { get; set; }
}

// 回调服务接口
public interface ICallbackService {
    Task<List<Claim>> FetchExternalClaimsAsync(string callbackUrl, string userId);
}
```

## 依赖的数据库表/字段/索引

- [accounts](../../database/tables/accounts.md) — 账户查询和登录信息更新
- [password_credentials](../../database/tables/password_credentials.md) — 密码凭证验证
- [user_logins](../../database/tables/user_logins.md) — 外部登录绑定查询
- [refresh_tokens](../../database/tables/refresh_tokens.md) — 刷新令牌生成和验证
- [app_registrations](../../database/tables/app_registrations.md) — 网关验证和回调配置
- [login_attempts](../../database/tables/login_attempts.md) — 登录失败计数和锁定
- [login_histories](../../database/tables/login_histories.md) — 登录审计记录

## 数据流/调用链

```
GetToken Request
    │
    ▼
ValidateGatewayAsync ──▶ GatewayValidationService.ValidateAsync
    │                         │
    │                         └──▶ AppRegistrationRepository.GetByAppIdAsync
    │                         └──▶ BCrypt.Verify(AppSecret)
    │                         └──▶ 返回 GatewayAuthResult（含 App 实体，无需二次查询）
    │
    ▼
ValidatorFactory.GetValidator(grantType)
    │
    ▼
IIdentityValidator.ValidateAsync
    │  ├── PasswordValidator ──▶ PasswordCredentialRepo + AccountRepo + LoginAttemptRepo
    │  ├── SmsValidator ──▶ OtpService.VerifyAsync + AccountRepo + UserLoginRepo
    │  ├── WechatValidator ──▶ WechatApiClient.CodeToSessionAsync + AccountRepo
    │  └── RefreshTokenValidator ──▶ RefreshTokenRepo + AccountRepo
    │
    ▼
ClaimsResolver.ResolveBasicClaims
    │
    ▼
CallbackService.FetchExternalClaimsAsync (if CallbackUrl exists)
    │   └── CallbackUrlValidator.ValidateAsync（异步 DNS 解析检查私有地址）
    │   └── Claim 数量限制：每种类型最多 50 个，值长度不超过 256 字符
    │   └── CustomClaims 仅允许白名单类型：department, class_name, grade, subject, school, organization, title
    │
    ▼
Bootstrap Admin Short-Circuit (after callback, before signing)
    │   └── 若 AdminBootstrap:Username 配置非空 且 request.Username 与之相等（OrdinalIgnoreCase）
    │   └── 且 claims 中尚不存在 role=admin
    │   └── 则注入 new Claim(ClaimTypes.Role, "admin")
    │   └── 该逻辑绕过 callback，保证 bootstrap admin 从任意 portal 登录都能获得 admin 角色
    │   └── SMS/微信登录无 Username，不触发此逻辑
    │
    ▼
JwtTokenService.GenerateJwtToken (RSA signing)
    │
    ▼
HandleRefreshTokenAsync (generate/revoke)
    │
    ▼
AuditService.RecordLoginAsync
    │
    ▼
UpdateAccountLoginInfoAsync
    │
    ▼
TokenResponse
```

## 关键设计决策和取舍理由

1. **策略模式验证器**：通过 `IIdentityValidator` + `ValidatorFactory` 实现开闭原则，新增登录方式只需实现接口并注册 DI
2. **回调降级不阻塞**：回调失败返回空 Claims，确保登录流程不中断 [推断]
3. **刷新令牌一次性使用**：使用后立即撤销并生成新令牌，降低令牌泄露风险
4. **短信登录自动注册**：降低注册门槛，首次短信登录自动创建账户
5. **微信登录不自动注册**：微信 OpenId 需预先绑定到已有账户，防止未授权访问
6. **GatewayAuthResult 携带 App 实体**：`GatewayValidationService.ValidateAsync` 验证成功后返回 `AppRegistrationEntity`，避免 `AuthController` 二次查询
7. **回调 Claim 注入防护**：`CallbackService` 对外部回调返回的 Claim 施加数量限制（每种类型最多 50 个）和值长度限制（256 字符），CustomClaims 仅允许白名单类型
8. **SMS 发送器环境隔离**：开发环境使用 `LoggingSmsSender`（掩码记录），生产环境使用 `ThrowingSmsSender`（抛出异常），防止生产环境验证码泄露
9. **CORS 生产环境保护**：生产环境未配置 `AdminWeb:AllowedOrigins` 时不启用跨域凭据，开发环境默认允许 localhost
10. **Bootstrap Admin 注入时机在 callback 之后**：callback 可能返回额外角色（如 teacher），这些角色应保留；bootstrap admin 注入仅补充 role=admin，不覆盖已有角色，且通过 `!claims.Any(...)` 去重
11. **仅 password grant 触发**：`request.Username` 仅在密码登录时有值；SMS/WeChat 的 portal 用户不需要 bootstrap admin 机制
